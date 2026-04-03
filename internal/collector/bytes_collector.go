// Package collector – BytesCollector loads the tcp_monitor eBPF program
// and streams real TCP byte-transfer events (from kprobe/tcp_sendmsg and
// kretprobe/tcp_recvmsg) to Go userspace via a ring buffer.
//
// Map sharing
// ───────────
// BytesCollector shares the tracked_pids map with ProcessTracer (and
// TcpCollector) via MapReplacements.  The kernel sees a single hash map.
//
// Relation to TcpCollector
// ────────────────────────
// Both collectors load the same compiled TcpMonitor BPF object
// (generated from bpf/tcp_monitor.bpf.c by the bpf2go directive in
// tcp_collector.go).  BytesCollector opens the bytes_events ring buffer
// and attaches only the two kprobe/kretprobe programs; TcpCollector
// opens tcp_events and attaches the tracepoint.  They are independent
// instances with separate ring-buffer readers.
package collector

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

// BytesEvent mirrors the C struct bytes_event from bpf/tcp_monitor.bpf.c.
//
// C layout (sizeof == 12 bytes):
//
//	__u32 pid        → Pid       uint32   offset  0
//	__u32 bytes      → Bytes     uint32   offset  4
//	__u8  direction  → Direction uint8    offset  8   (0=recv, 1=send)
//	__u8  pad[3]     → _         [3]byte  offset  9   (explicit padding)
type BytesEvent struct {
	Pid       uint32
	Bytes     uint32
	Direction uint8 // 0 = recv (tcp_recvmsg), 1 = send (tcp_sendmsg)
	_         [3]byte
}

// BytesCollector attaches kprobe/tcp_sendmsg and kretprobe/tcp_recvmsg,
// and streams decoded BytesEvent values to the Events channel.
type BytesCollector struct {
	objs       TcpMonitorObjects
	sendLink   link.Link // kprobe/tcp_sendmsg
	recvLink   link.Link // kretprobe/tcp_recvmsg
	reader     *ringbuf.Reader

	// Events receives one BytesEvent per tcp_sendmsg call or per successful
	// tcp_recvmsg return for a tracked PID.  The channel is buffered (4096).
	// Events are dropped (not blocked) when the consumer is slower than the
	// producer.
	Events chan BytesEvent
}

// NewBytesCollector loads the BPF objects (sharing tracked_pids with the
// ProcessTracer), attaches the kprobe and kretprobe, and opens the
// bytes_events ring-buffer reader.
//
// trackedPids must be the *ebpf.Map obtained from ProcessTracerObjects.TrackedPids.
func NewBytesCollector(trackedPids *ebpf.Map) (*BytesCollector, error) {
	var objs TcpMonitorObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tracked_pids": trackedPids,
		},
	}
	if err := LoadTcpMonitorObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load TcpMonitor objects (bytes): %w", err)
	}

	// Attach kprobe on tcp_sendmsg (captures outbound byte count from arg3).
	sendLink, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kprobe/tcp_sendmsg: %w", err)
	}

	// Attach kretprobe on tcp_recvmsg (captures actual bytes received from retval).
	recvLink, err := link.Kretprobe("tcp_recvmsg", objs.KretprobeTcpRecvmsg, nil)
	if err != nil {
		sendLink.Close()
		objs.Close()
		return nil, fmt.Errorf("attach kretprobe/tcp_recvmsg: %w", err)
	}

	// Open a ring-buffer reader on the bytes_events map.
	rd, err := ringbuf.NewReader(objs.BytesEvents)
	if err != nil {
		recvLink.Close()
		sendLink.Close()
		objs.Close()
		return nil, fmt.Errorf("open bytes_events ring buffer reader: %w", err)
	}

	return &BytesCollector{
		objs:     objs,
		sendLink: sendLink,
		recvLink: recvLink,
		reader:   rd,
		Events:   make(chan BytesEvent, 4096),
	}, nil
}

// Run reads events from the bytes_events ring buffer and forwards them to
// c.Events until ctx is cancelled or Close is called.  Run it in its own
// goroutine:
//
//	go bc.Run(ctx)
func (c *BytesCollector) Run(ctx context.Context) {
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

		var evt BytesEvent
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

// Close detaches both probes, closes the ring-buffer reader, and releases
// all BPF resources.  Safe to call while Run is still active.
func (c *BytesCollector) Close() error {
	var errs []error

	if err := c.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		errs = append(errs, fmt.Errorf("close bytes ring buffer reader: %w", err))
	}
	if err := c.recvLink.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close kretprobe/tcp_recvmsg link: %w", err))
	}
	if err := c.sendLink.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close kprobe/tcp_sendmsg link: %w", err))
	}
	c.objs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("BytesCollector.Close: %v", errs)
	}
	return nil
}
