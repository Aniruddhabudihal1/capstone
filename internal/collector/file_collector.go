// Package collector – FileCollector loads the file_monitor eBPF program
// and streams file open events to Go userspace via a ring buffer.
//
// Map sharing
// ───────────
// The BPF program defines its own tracked_pids map, but we never actually
// load it.  Instead, the caller passes the *ebpf.Map from the already-loaded
// ProcessTracer collection, and we inject it through
// ebpf.CollectionOptions.MapReplacements before loading.  The kernel sees a
// single shared hash map across both BPF programs.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 FileMonitor ../../bpf/file_monitor.bpf.c

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

// DirectoryCategory is the u8 classification of file paths (see file_monitor.bpf.c).
type DirectoryCategory uint8

const (
	DirOther   DirectoryCategory = 0
	DirRoot    DirectoryCategory = 1
	DirTemp    DirectoryCategory = 2
	DirHome    DirectoryCategory = 3
	DirUserLib DirectoryCategory = 4
	DirSys     DirectoryCategory = 5
	DirEtc     DirectoryCategory = 6
)

// DirCategoryName maps category values to human-readable strings.
var DirCategoryName = map[DirectoryCategory]string{
	DirOther:   "OTHER",
	DirRoot:    "ROOT",
	DirTemp:    "TEMP",
	DirHome:    "HOME",
	DirUserLib: "USER_LIB",
	DirSys:     "SYS",
	DirEtc:     "ETC",
}

// FileEvent mirrors the C struct file_event from bpf/file_monitor.bpf.c.
//
// C layout (sizeof == 280 bytes):
//
//	__u32 pid                → Pid          uint32              offset   0
//	char filename[256]       → Filename     [256]byte           offset   4
//	__u8 dir_category        → DirCategory  uint8               offset 260
//	__u8 open_success        → OpenSuccess  uint8               offset 261
//	__u8 pad[2]              → Pad          [2]uint8            offset 262
//	__u32 flags              → Flags        uint32              offset 264
//	__u64 timestamp_ns       → TimestampNs  uint64              offset 272
type FileEvent struct {
	Pid         uint32
	Filename    [256]byte
	DirCategory uint8
	OpenSuccess uint8
	Pad         [2]uint8
	Flags       uint32
	TimestampNs uint64
}

// FileCollector attaches to tracepoint/syscalls/sys_enter_openat and
// tracepoint/syscalls/sys_exit_openat and streams decoded FileEvent values
// to the Events channel.  Events are emitted at exit time so open_success
// reflects the actual kernel return value.
type FileCollector struct {
	objs      FileMonitorObjects
	linkEnter link.Link
	linkExit  link.Link
	reader    *ringbuf.Reader

	// Events receives one FileEvent per openat() call made by a tracked PID.
	// The channel is buffered (4096).  Events are dropped (not blocked) when
	// the consumer is slower than the producer.
	Events chan FileEvent
}

// NewFileCollector loads the BPF objects (sharing tracked_pids with the
// ProcessTracer), attaches the tracepoint, and opens the ring-buffer reader.
//
// trackedPids must be the *ebpf.Map obtained from ProcessTracerObjects.TrackedPids
// after loading the process tracer.  This map is injected via MapReplacements so
// that both BPF programs share the same kernel map.
func NewFileCollector(trackedPids *ebpf.Map) (*FileCollector, error) {
	// Load pre-compiled BPF programs and maps, replacing tracked_pids with
	// the already-loaded map from the process tracer.
	var objs FileMonitorObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tracked_pids": trackedPids,
		},
	}
	if err := LoadFileMonitorObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load FileMonitor objects: %w", err)
	}

	// Attach to tracepoint/syscalls/sys_enter_openat.
	tpEnter, err := link.Tracepoint(
		"syscalls", "sys_enter_openat",
		objs.TracepointSyscallsSysEnterOpenat,
		nil,
	)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_enter_openat: %w", err)
	}

	// Attach to tracepoint/syscalls/sys_exit_openat.
	tpExit, err := link.Tracepoint(
		"syscalls", "sys_exit_openat",
		objs.TracepointSyscallsSysExitOpenat,
		nil,
	)
	if err != nil {
		tpEnter.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint syscalls/sys_exit_openat: %w", err)
	}

	// Open a ring-buffer reader on the file_events map.
	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		tpExit.Close()
		tpEnter.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &FileCollector{
		objs:      objs,
		linkEnter: tpEnter,
		linkExit:  tpExit,
		reader:    rd,
		Events:    make(chan FileEvent, 4096),
	}, nil
}

// Run reads events from the ring buffer and forwards them to c.Events until
// ctx is cancelled or Close is called.  Run it in its own goroutine:
//
//	go fc.Run(ctx)
func (c *FileCollector) Run(ctx context.Context) {
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

		var evt FileEvent
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
func (c *FileCollector) TrackedPidsMap() *ebpf.Map {
	return c.objs.TrackedPids
}

// Close detaches both tracepoints, closes the ring-buffer reader, and
// releases all BPF resources.  Safe to call while Run is still active.
func (c *FileCollector) Close() error {
	var errs []error

	if err := c.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		errs = append(errs, fmt.Errorf("close ring buffer reader: %w", err))
	}
	if err := c.linkExit.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tracepoint link (exit): %w", err))
	}
	if err := c.linkEnter.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tracepoint link (enter): %w", err))
	}
	c.objs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("FileCollector.Close: %v", errs)
	}
	return nil
}
