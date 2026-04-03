// Package collector – SyscallCollector loads the syscall_tracer eBPF program
// and streams raw syscall events to Go userspace via a ring buffer.
//
// Map sharing
// ───────────
// The BPF program defines its own tracked_pids map, but we never actually
// load it.  Instead, the caller passes the *ebpf.Map from the already-loaded
// ProcessTracer collection, and we inject it through
// ebpf.CollectionOptions.MapReplacements before loading.  The kernel sees a
// single shared hash map across both BPF programs.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 SyscallTracer ../../bpf/syscall_tracer.bpf.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// SyscallEvent mirrors the C struct syscall_event from bpf/syscall_tracer.bpf.c.
//
// C layout (sizeof == 16 bytes, naturally aligned):
//
//	__u32 pid           → Pid         uint32   offset  0
//	__u32 syscall_id    → SyscallID   uint32   offset  4
//	__u64 timestamp_ns  → TimestampNs uint64   offset  8
type SyscallEvent struct {
	Pid         uint32
	SyscallID   uint32
	TimestampNs uint64
}

// SyscallCollector attaches to raw_syscalls/sys_enter and streams decoded
// SyscallEvent values to the Events channel.
type SyscallCollector struct {
	objs   SyscallTracerObjects
	link   link.Link
	reader *ringbuf.Reader

	// Events receives one SyscallEvent per syscall made by a tracked PID.
	// The channel is buffered (4096).  Events are dropped (not blocked) when
	// the consumer is slower than the producer.
	Events chan SyscallEvent
}

// NewSyscallCollector loads the BPF objects (sharing tracked_pids with the
// ProcessTracer), attaches the tracepoint, and opens the ring-buffer reader.
//
// trackedPids must be the *ebpf.Map obtained from ProcessTracerObjects.TrackedPids
// after loading the process tracer.  This map is injected via MapReplacements so
// that both BPF programs share the same kernel map.
func NewSyscallCollector(trackedPids *ebpf.Map) (*SyscallCollector, error) {
	// Load pre-compiled BPF programs and maps, replacing tracked_pids with
	// the already-loaded map from the process tracer.
	var objs SyscallTracerObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tracked_pids": trackedPids,
		},
	}
	if err := LoadSyscallTracerObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load SyscallTracer objects: %w", err)
	}

	// Attach to tracepoint/raw_syscalls/sys_enter.
	tp, err := link.Tracepoint(
		"raw_syscalls", "sys_enter",
		objs.TracepointRawSyscallsSysEnter,
		nil,
	)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint raw_syscalls/sys_enter: %w", err)
	}

	// Open a ring-buffer reader on the syscall_events map.
	rd, err := ringbuf.NewReader(objs.SyscallEvents)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &SyscallCollector{
		objs:   objs,
		link:   tp,
		reader: rd,
		Events: make(chan SyscallEvent, 4096),
	}, nil
}

// Run reads events from the ring buffer and forwards them to c.Events until
// ctx is cancelled or Close is called.  Run it in its own goroutine:
//
//	go sc.Run(ctx)
func (c *SyscallCollector) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = c.reader.Close()
	}()

	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var evt SyscallEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}

		select {
		case c.Events <- evt:
		default:
			// Consumer is lagging; drop rather than block.
		}
	}
}

// TrackedPidsMap returns the underlying *ebpf.Map for tracked_pids.
// This is useful if other collectors also need to share the map.
func (c *SyscallCollector) TrackedPidsMap() *ebpf.Map {
	return c.objs.TrackedPids
}

// Close detaches the tracepoint, closes the ring-buffer reader, and releases
// all BPF resources.  Safe to call while Run is still active.
func (c *SyscallCollector) Close() error {
	var errs []error

	if err := c.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		errs = append(errs, fmt.Errorf("close ring buffer reader: %w", err))
	}
	if err := c.link.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tracepoint link: %w", err))
	}
	c.objs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("SyscallCollector.Close: %v", errs)
	}
	return nil
}
