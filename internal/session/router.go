package session

import (
	"context"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

// Router multiplexes collector event streams into one detector.
type Router struct {
	detector *Detector
	procCh   <-chan collector.ProcessEvent
	sysCh    <-chan collector.SyscallEvent
	fileCh   <-chan collector.FileEvent
	tcpCh    <-chan collector.TCPEvent
	bytesCh  <-chan collector.BytesEvent
}

// NewRouter builds a detector router over the collector event channels.
// bytesCh may be nil if the BytesCollector is not available.
func NewRouter(
	detector *Detector,
	procCh <-chan collector.ProcessEvent,
	sysCh <-chan collector.SyscallEvent,
	fileCh <-chan collector.FileEvent,
	tcpCh <-chan collector.TCPEvent,
	bytesCh <-chan collector.BytesEvent,
) *Router {
	return &Router{
		detector: detector,
		procCh:   procCh,
		sysCh:    sysCh,
		fileCh:   fileCh,
		tcpCh:    tcpCh,
		bytesCh:  bytesCh,
	}
}

// Run drains collector event channels until the context is canceled.
func (r *Router) Run(ctx context.Context) {
	if r == nil || r.detector == nil {
		return
	}

	procCh := r.procCh
	sysCh := r.sysCh
	fileCh := r.fileCh
	tcpCh := r.tcpCh
	bytesCh := r.bytesCh

	for procCh != nil || sysCh != nil || fileCh != nil || tcpCh != nil || bytesCh != nil {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-procCh:
			if !ok {
				procCh = nil
				continue
			}
			r.detector.HandleProcess(event)
		default:
			select {
			case <-ctx.Done():
				return
			case event, ok := <-procCh:
				if !ok {
					procCh = nil
					continue
				}
				r.detector.HandleProcess(event)
			case event, ok := <-sysCh:
				if !ok {
					sysCh = nil
					continue
				}
				r.detector.RouteToSession(event.Pid, func(session *Session) {
					session.AddSyscall(event)
				})
			case event, ok := <-fileCh:
				if !ok {
					fileCh = nil
					continue
				}
				r.detector.RouteToSession(event.Pid, func(session *Session) {
					session.AddFile(event)
				})
			case event, ok := <-tcpCh:
				if !ok {
					tcpCh = nil
					continue
				}
				r.detector.RouteToSession(event.Pid, func(session *Session) {
					session.AddTCP(event)
				})
			case event, ok := <-bytesCh:
				if !ok {
					bytesCh = nil
					continue
				}
				r.detector.RouteToSession(event.Pid, func(session *Session) {
					session.AddBytes(event)
				})
			}
		}
	}
}
