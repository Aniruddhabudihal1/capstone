// Package collector loads the process_tracer eBPF program and streams
// execve events to Go userspace via a ring buffer.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ProcessTracer ../../bpf/process_tracer.bpf.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ProcessEvent mirrors the C struct process_event from bpf/process_tracer.bpf.c.
//
// C layout (sizeof == 296 bytes):
//
//	__u32 pid             →  Pid          uint32   offset   0
//	__u32 ppid            →  Ppid         uint32   offset   4
//	char  comm[16]        →  Comm         [16]byte offset   8
//	char  args[256]       →  Args         [256]byte offset 24
//	__u64 timestamp_ns    →  TimestampNs  uint64   offset 280
//	__u32 is_npm_related  →  IsNpmRelated uint32   offset 288
//	(4-byte trailing pad) →  _            [4]byte  offset 292
type ProcessEvent struct {
	Pid          uint32
	Ppid         uint32
	Comm         [16]byte
	Args         [256]byte
	TimestampNs  uint64
	IsNpmRelated uint32
	_            [4]byte // trailing padding: C compiler pads to multiple of 8
}

// ProcessCollector attaches to the sys_enter_execve tracepoint and streams
// decoded ProcessEvent values to the Events channel.
type ProcessCollector struct {
	objs     ProcessTracerObjects
	link     link.Link
	forkLink link.Link
	exitLink link.Link
	reader   *ringbuf.Reader

	// Events receives one ProcessEvent per execve syscall.
	// The channel is buffered (1024). Events are dropped (not blocked) when
	// the consumer is slower than the producer.
	Events chan ProcessEvent
}

// NewProcessCollector loads the BPF objects, attaches the tracepoint, and
// opens the ring-buffer reader. The caller must call Close() when done.
func NewProcessCollector() (*ProcessCollector, error) {
	// Allow the current process to lock memory for BPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// Load pre-compiled BPF programs and maps into the kernel.
	var objs ProcessTracerObjects
	if err := LoadProcessTracerObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load ProcessTracer objects: %w", err)
	}

	// Attach to tracepoint/syscalls/sys_enter_execve.
	tp, err := link.Tracepoint(
		"syscalls", "sys_enter_execve",
		objs.TracepointSyscallsSysEnterExecve,
		nil,
	)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint sys_enter_execve: %w", err)
	}

	// Attach to tracepoint/sched/sched_process_fork.
	forkTP, err := link.Tracepoint(
		"sched", "sched_process_fork",
		objs.TracepointSchedSchedProcessFork,
		nil,
	)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint sched_process_fork: %w", err)
	}

	// Attach to tracepoint/sched/sched_process_exit.
	exitTP, err := link.Tracepoint(
		"sched", "sched_process_exit",
		objs.TracepointSchedSchedProcessExit,
		nil,
	)
	if err != nil {
		forkTP.Close()
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint sched_process_exit: %w", err)
	}

	// Open a ring-buffer reader on the process_events map.
	rd, err := ringbuf.NewReader(objs.ProcessEvents)
	if err != nil {
		exitTP.Close()
		forkTP.Close()
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &ProcessCollector{
		objs:     objs,
		link:     tp,
		forkLink: forkTP,
		exitLink: exitTP,
		reader:   rd,
		Events:   make(chan ProcessEvent, 1024),
	}, nil
}

// Run reads events from the ring buffer and forwards them to c.Events until
// ctx is cancelled or Close is called. It should be run in its own goroutine.
//
//	go collector.Run(ctx)
func (c *ProcessCollector) Run(ctx context.Context) {
	// Close the reader when the context expires so that the blocking Read()
	// call below returns immediately with ringbuf.ErrClosed.
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
			// Transient error (e.g. lost samples) — keep reading.
			continue
		}

		var evt ProcessEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			// RawSample size mismatch or corrupt data — skip this record.
			continue
		}

		select {
		case c.Events <- evt:
		default:
			// Consumer is lagging; drop the event rather than blocking the reader.
		}
	}
}

// Close detaches the tracepoint, closes the ring-buffer reader, and releases
// all BPF resources. It is safe to call Close while Run is still active.
func (c *ProcessCollector) Close() error {
	var errs []error

	if err := c.reader.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close ring buffer reader: %w", err))
	}
	if err := c.link.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tracepoint link: %w", err))
	}
	if err := c.forkLink.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close fork tracepoint link: %w", err))
	}
	if err := c.exitLink.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close exit tracepoint link: %w", err))
	}
	c.objs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("ProcessCollector.Close: %v", errs)
	}
	return nil
}

// TrackedPidsMap returns the loaded *ebpf.Map for tracked_pids so that other
// BPF collections (e.g. SyscallTracer) can share it via MapReplacements.
func (c *ProcessCollector) TrackedPidsMap() *ebpf.Map {
	return c.objs.TrackedPids
}
