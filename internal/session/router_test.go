package session

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

func TestRouter_Multiplexing(t *testing.T) {
	detector := NewDetector(0)
	session := NewSession(42, "existing")
	detector.registerSession(session)

	childPID := uint32(84)
	detector.associatePID(session, childPID)

	procCh := make(chan collector.ProcessEvent)
	sysCh := make(chan collector.SyscallEvent)
	fileCh := make(chan collector.FileEvent)
	tcpCh := make(chan collector.TCPEvent)

	router := NewRouter(detector, procCh, sysCh, fileCh, tcpCh, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := startRouter(router, ctx)
	defer func() {
		cancel()
		waitForRouterExit(t, done)
	}()

	var senders sync.WaitGroup
	senders.Add(4)

	go func() {
		defer senders.Done()
		procCh <- collector.ProcessEvent{
			Pid:       100,
			Comm:      fixedComm("bash"),
			Args:      fixedSlotArgs("npm", "install", "left-pad"),
			EventType: processEventExec,
		}
	}()
	go func() {
		defer senders.Done()
		sysCh <- collector.SyscallEvent{
			Pid:       childPID,
			SyscallID: 257,
		}
	}()
	go func() {
		defer senders.Done()
		fileCh <- collector.FileEvent{
			Pid:         childPID,
			DirCategory: uint8(collector.DirHome),
			Flags:       uint32(syscall.O_RDONLY),
		}
	}()
	go func() {
		defer senders.Done()
		tcpCh <- collector.TCPEvent{
			Pid:      childPID,
			Saddr:    1,
			Daddr:    2,
			Sport:    3000,
			Dport:    443,
			OldState: 1,
			NewState: 2,
		}
	}()

	waitForWaitGroup(t, &senders, "router senders did not complete")
	waitForCondition(t, func() bool {
		syscallCount, homeCount, fileProcesses, tcpTransitions, livePID := snapshotSession(session, childPID)
		return detectorSession(detector, 100) != nil &&
			syscallCount == 1 &&
			homeCount == 1 &&
			fileProcesses == 1 &&
			tcpTransitions == 1 &&
			livePID
	}, "router did not process multiplexed events")

	created := detectorSession(detector, 100)
	if created == nil {
		t.Fatal("process event did not create a session")
	}
	if created.PackageName != "left-pad" {
		t.Fatalf("created.PackageName = %q, want %q", created.PackageName, "left-pad")
	}

	syscallCount, homeCount, fileProcesses, tcpTransitions, livePID := snapshotSession(session, childPID)
	if syscallCount != 1 {
		t.Fatalf("syscall count = %d, want 1", syscallCount)
	}
	if homeCount != 1 {
		t.Fatalf("home directory count = %d, want 1", homeCount)
	}
	if fileProcesses != 1 {
		t.Fatalf("file access processes = %d, want 1", fileProcesses)
	}
	if tcpTransitions != 1 {
		t.Fatalf("tcp transitions = %d, want 1", tcpTransitions)
	}
	if !livePID {
		t.Fatal("RouteToSession did not mark the child pid as live")
	}
}

func TestRouter_ContextCancellation(t *testing.T) {
	detector := NewDetector(0)
	router := NewRouter(
		detector,
		make(chan collector.ProcessEvent),
		make(chan collector.SyscallEvent),
		make(chan collector.FileEvent),
		make(chan collector.TCPEvent),
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := startRouter(router, ctx)

	cancel()
	waitForRouterExit(t, done)
}

func TestRouter_UnknownPID(t *testing.T) {
	detector := NewDetector(0)
	session := NewSession(42, "existing")
	detector.registerSession(session)

	procCh := make(chan collector.ProcessEvent)
	sysCh := make(chan collector.SyscallEvent)
	fileCh := make(chan collector.FileEvent)
	tcpCh := make(chan collector.TCPEvent)

	router := NewRouter(detector, procCh, sysCh, fileCh, tcpCh, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := startRouter(router, ctx)
	defer func() {
		cancel()
		waitForRouterExit(t, done)
	}()

	var senders sync.WaitGroup
	senders.Add(3)

	go func() {
		defer senders.Done()
		sysCh <- collector.SyscallEvent{Pid: 999, SyscallID: 257}
	}()
	go func() {
		defer senders.Done()
		fileCh <- collector.FileEvent{
			Pid:         999,
			DirCategory: uint8(collector.DirHome),
			Flags:       uint32(syscall.O_RDONLY),
		}
	}()
	go func() {
		defer senders.Done()
		tcpCh <- collector.TCPEvent{
			Pid:      999,
			Saddr:    1,
			Daddr:    2,
			Sport:    3000,
			Dport:    443,
			OldState: 1,
			NewState: 2,
		}
	}()

	waitForWaitGroup(t, &senders, "unknown pid senders did not complete")

	syscallCount, homeCount, fileProcesses, tcpTransitions, livePID := snapshotSession(session, session.NpmPID)
	if syscallCount != 0 {
		t.Fatalf("syscall count = %d, want 0", syscallCount)
	}
	if homeCount != 0 {
		t.Fatalf("home directory count = %d, want 0", homeCount)
	}
	if fileProcesses != 0 {
		t.Fatalf("file access processes = %d, want 0", fileProcesses)
	}
	if tcpTransitions != 0 {
		t.Fatalf("tcp transitions = %d, want 0", tcpTransitions)
	}
	if !livePID {
		t.Fatal("root pid should remain live")
	}

	detector.mu.RLock()
	_, exists := detector.pidToSession[999]
	detector.mu.RUnlock()
	if exists {
		t.Fatal("unknown pid was unexpectedly attached to a session")
	}
}

func TestRouter_RaceConditions(t *testing.T) {
	detector := NewDetector(0)
	session := NewSession(500, "pkg")
	detector.registerSession(session)

	childPID := uint32(501)
	detector.associatePID(session, childPID)

	procCh := make(chan collector.ProcessEvent)
	sysCh := make(chan collector.SyscallEvent)
	fileCh := make(chan collector.FileEvent)
	tcpCh := make(chan collector.TCPEvent)

	router := NewRouter(detector, procCh, sysCh, fileCh, tcpCh, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := startRouter(router, ctx)
	defer func() {
		cancel()
		waitForRouterExit(t, done)
	}()

	const workers = 50

	var senders sync.WaitGroup
	senders.Add(workers)

	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer senders.Done()

			sysCh <- collector.SyscallEvent{
				Pid:       childPID,
				SyscallID: 257,
			}
			fileCh <- collector.FileEvent{
				Pid:         childPID,
				DirCategory: uint8(collector.DirHome),
				Flags:       uint32(syscall.O_RDONLY),
			}
			tcpCh <- collector.TCPEvent{
				Pid:      childPID,
				Saddr:    uint32(i + 1),
				Daddr:    uint32(i + 10_001),
				Sport:    uint16(3000 + i),
				Dport:    uint16(4000 + i),
				OldState: 1,
				NewState: 2,
			}
		}()
	}

	waitForWaitGroup(t, &senders, "race-condition senders did not complete")
	waitForCondition(t, func() bool {
		syscallCount, homeCount, _, tcpTransitions, livePID := snapshotSession(session, childPID)
		return syscallCount == workers &&
			homeCount == workers &&
			tcpTransitions == workers &&
			livePID
	}, "router did not process all concurrent events")

	syscallCount, homeCount, _, tcpTransitions, livePID := snapshotSession(session, childPID)
	if syscallCount != workers {
		t.Fatalf("syscall count = %d, want %d", syscallCount, workers)
	}
	if homeCount != workers {
		t.Fatalf("home directory count = %d, want %d", homeCount, workers)
	}
	if tcpTransitions != workers {
		t.Fatalf("tcp transitions = %d, want %d", tcpTransitions, workers)
	}
	if !livePID {
		t.Fatal("RouteToSession did not mark the child pid as live")
	}
}

func startRouter(router *Router, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.Run(ctx)
	}()
	return done
}

func waitForRouterExit(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router.Run() did not exit in time")
	}
}

func waitForWaitGroup(t *testing.T, wg *sync.WaitGroup, message string) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func waitForCondition(t *testing.T, condition func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal(message)
}

func detectorSession(detector *Detector, pid uint32) *Session {
	detector.mu.RLock()
	defer detector.mu.RUnlock()

	return detector.activeSessions[pid]
}

func snapshotSession(session *Session, pid uint32) (int, int, int, int, bool) {
	session.mu.Lock()
	defer session.mu.Unlock()

	fileProcesses := 0
	if session.FiletopAgg != nil {
		fileProcesses = session.FiletopAgg.Snapshot().FileAccessProcesses
	}

	tcpTransitions := 0
	if session.TCPAgg != nil {
		tcpTransitions = session.TCPAgg.Counts().StateTransitions
	}

	homeCount := 0
	if session.DirCounts != nil {
		homeCount = session.DirCounts.Home
	}

	syscallCount := session.SyscallCounts[features.CategoryFile]
	return syscallCount, homeCount, fileProcesses, tcpTransitions, session.LivePIDs[pid]
}
