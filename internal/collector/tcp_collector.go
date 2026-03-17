// Package collector – TcpCollector loads the tcp_monitor eBPF program
// and streams TCP state transition events to Go userspace via a ring buffer.
//
// Map sharing
// ───────────
// The BPF program defines its own tracked_pids map, but we never actually
// load it.  Instead, the caller passes the *ebpf.Map from the already-loaded
// ProcessTracer collection, and we inject it through
// ebpf.CollectionOptions.MapReplacements before loading.  The kernel sees a
// single shared hash map across all BPF programs.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 TcpMonitor ../../bpf/tcp_monitor.bpf.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// TCPEvent mirrors the C struct tcp_event from bpf/tcp_monitor.bpf.c.
//
// C layout (sizeof == 32 bytes):
//
//	__u32 pid             → Pid         uint32   offset  0
//	__u32 saddr           → Saddr       uint32   offset  4  (network byte order)
//	__u32 daddr           → Daddr       uint32   offset  8  (network byte order)
//	__u16 sport           → Sport       uint16   offset 12  (host byte order)
//	__u16 dport           → Dport       uint16   offset 14  (host byte order)
//	__u8  old_state       → OldState    uint8    offset 16
//	__u8  new_state       → NewState    uint8    offset 17
//	__u8  _pad[6]         → _           [6]byte  offset 18  (explicit padding)
//	__u64 timestamp_ns    → TimestampNs uint64   offset 24
type TCPEvent struct {
	Pid         uint32
	Saddr       uint32  // IPv4 source address in network byte order
	Daddr       uint32  // IPv4 dest address in network byte order
	Sport       uint16  // source port in host byte order
	Dport       uint16  // dest port in host byte order
	OldState    uint8   // previous TCP state (TCP_* constants)
	NewState    uint8   // new TCP state (TCP_* constants)
	_           [6]byte // padding
	TimestampNs uint64
}

// TcpEvent is kept as a compatibility alias for existing callers.
// New code should use TCPEvent.
type TcpEvent = TCPEvent

// TcpCollector attaches to tracepoint/sock/inet_sock_set_state and streams
// decoded TCPEvent values to the Events channel.
type TcpCollector struct {
	objs   TcpMonitorObjects
	link   link.Link
	reader *ringbuf.Reader

	// Events receives one TCPEvent per TCP state transition made by a tracked PID.
	// The channel is buffered (4096).  Events are dropped (not blocked) when
	// the consumer is slower than the producer.
	Events chan TCPEvent
}

// NewTcpCollector loads the BPF objects (sharing tracked_pids with the
// ProcessTracer), attaches the tracepoint, and opens the ring-buffer reader.
//
// trackedPids must be the *ebpf.Map obtained from ProcessTracerObjects.TrackedPids
// after loading the process tracer.  This map is injected via MapReplacements so
// that both BPF programs share the same kernel map.
func NewTcpCollector(trackedPids *ebpf.Map) (*TcpCollector, error) {
	// Load pre-compiled BPF programs and maps, replacing tracked_pids with
	// the already-loaded map from the process tracer.
	var objs TcpMonitorObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tracked_pids": trackedPids,
		},
	}
	if err := LoadTcpMonitorObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load TcpMonitor objects: %w", err)
	}

	// Attach to tracepoint/sock/inet_sock_set_state.
	tp, err := link.Tracepoint(
		"sock", "inet_sock_set_state",
		objs.TracepointSockInetSockSetState,
		nil,
	)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint sock/inet_sock_set_state: %w", err)
	}

	// Open a ring-buffer reader on the tcp_events map.
	rd, err := ringbuf.NewReader(objs.TcpEvents)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}

	return &TcpCollector{
		objs:   objs,
		link:   tp,
		reader: rd,
		Events: make(chan TCPEvent, 4096),
	}, nil
}

// Run reads events from the ring buffer and forwards them to c.Events until
// ctx is cancelled or Close is called.  Run it in its own goroutine:
//
//	go tc.Run(ctx)
func (c *TcpCollector) Run(ctx context.Context) {
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

		var evt TCPEvent
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
func (c *TcpCollector) TrackedPidsMap() *ebpf.Map {
	return c.objs.TrackedPids
}

// TcpEventsMap returns the underlying *ebpf.Map for tcp_events (for debugging).
func (c *TcpCollector) TcpEventsMap() *ebpf.Map {
	return c.objs.TcpEvents
}

// SockToPidMap returns the underlying *ebpf.Map for sock_to_pid (for debugging).
func (c *TcpCollector) SockToPidMap() *ebpf.Map {
	return c.objs.SockToPid
}

// Close detaches the tracepoint, closes the ring-buffer reader, and releases
// all BPF resources.  Safe to call while Run is still active.
func (c *TcpCollector) Close() error {
	var errs []error

	if err := c.reader.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close ring buffer reader: %w", err))
	}
	if err := c.link.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tracepoint link: %w", err))
	}
	c.objs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("TcpCollector.Close: %v", errs)
	}
	return nil
}
