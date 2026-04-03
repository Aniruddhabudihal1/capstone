package session

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

func TestDetector_NpmInstallLifecycle(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Run(ctx)
	}()

	submitCtx := context.Background()
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		Args:      fixedArgs("node worker.js"),
		EventType: processEventExec,
	})
	detector.SubmitSyscall(submitCtx, collector.SyscallEvent{
		Pid:       101,
		SyscallID: 257,
	})
	detector.SubmitFile(submitCtx, collector.FileEvent{
		Pid:         101,
		DirCategory: uint8(collector.DirHome),
		Flags:       uint32(syscall.O_RDONLY),
	})
	detector.SubmitTCP(submitCtx, collector.TCPEvent{
		Pid:      101,
		Saddr:    1,
		Daddr:    2,
		Sport:    3000,
		Dport:    443,
		OldState: 1,
		NewState: 2,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	})

	select {
	case session := <-detector.Completed():
		t.Fatalf("Completed() returned early session: %+v", session)
	case <-time.After(100 * time.Millisecond):
	}

	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       101,
		Comm:      fixedComm("node"),
		EventType: processEventExit,
	})

	var session *Session
	select {
	case session = <-detector.Completed():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed session")
	}

	if session == nil {
		t.Fatal("Completed() returned nil session")
	}
	if !strings.HasPrefix(session.ID, "npm-") {
		t.Fatalf("session.ID = %q, want prefix %q", session.ID, "npm-")
	}
	if session.NpmPID != 100 {
		t.Fatalf("session.NpmPID = %d, want 100", session.NpmPID)
	}
	if session.PackageName != "lodash" {
		t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
	}
	if session.Cwd != "/tmp/project-lodash" {
		t.Fatalf("session.Cwd = %q, want %q", session.Cwd, "/tmp/project-lodash")
	}
	if !session.ChildPIDs[101] {
		t.Fatal("ChildPIDs missing child pid 101")
	}
	if session.State != SessionComplete {
		t.Fatalf("session.State = %q, want %q", session.State, SessionComplete)
	}
	if got := session.SyscallCounts[features.CategoryFile]; got != 1 {
		t.Fatalf("session.SyscallCounts[CategoryFile] = %d, want 1", got)
	}
	if session.DirCounts.Home != 1 {
		t.Fatalf("session.DirCounts.Home = %d, want 1", session.DirCounts.Home)
	}
	if session.FiletopAgg.Snapshot().FileAccessProcesses != 1 {
		t.Fatalf("FileAccessProcesses = %d, want 1", session.FiletopAgg.Snapshot().FileAccessProcesses)
	}
	if session.TCPAgg.Counts().StateTransitions != 1 {
		t.Fatalf("StateTransitions = %d, want 1", session.TCPAgg.Counts().StateTransitions)
	}

	detector.mu.RLock()
	_, exists := detector.activeSessions[100]
	detector.mu.RUnlock()
	if exists {
		t.Fatal("activeSessions still contains pid 100 after completion")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestDetector_ConcurrentSessionCwds(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		switch pid {
		case 100:
			return "/tmp/project-lodash", nil
		case 200:
			return "/tmp/project-axios", nil
		default:
			return "", errors.New("unexpected pid")
		}
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		switch pid {
		case 100:
			return "bash", nil
		case 200:
			return "bash", nil
		default:
			return "", errors.New("unexpected pid")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Run(ctx)
	}()

	submitCtx := context.Background()
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       200,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "i", "axios"),
		EventType: processEventExec,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       200,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	})

	got := map[string]string{}
	for len(got) < 2 {
		select {
		case session := <-detector.Completed():
			got[session.PackageName] = session.Cwd
		case <-time.After(250 * time.Millisecond):
			t.Fatal("timed out waiting for completed sessions")
		}
	}

	if got["lodash"] != "/tmp/project-lodash" {
		t.Fatalf("lodash session cwd = %q, want %q", got["lodash"], "/tmp/project-lodash")
	}
	if got["axios"] != "/tmp/project-axios" {
		t.Fatalf("axios session cwd = %q, want %q", got["axios"], "/tmp/project-axios")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestDetector_ContextCancellationClosesCompleted(t *testing.T) {
	detector := NewDetector(0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Run(ctx)
	}()

	cancel()
	waitForDetectorExit(t, done)

	select {
	case _, ok := <-detector.Completed():
		if ok {
			t.Fatal("Completed() channel is still open after detector shutdown")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for Completed() to close")
	}
}

func TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit(t *testing.T) {
	type trackedRoot struct {
		pid  uint32
		ppid uint32
	}

	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	trackedRoots := make(chan trackedRoot, 1)
	detector.SetRootTracker(func(pid, ppid uint32) error {
		trackedRoots <- trackedRoot{pid: pid, ppid: ppid}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Run(ctx)
	}()

	submitCtx := context.Background()
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Ppid:      42,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	})

	select {
	case tracked := <-trackedRoots:
		if tracked.pid != 100 || tracked.ppid != 42 {
			t.Fatalf("tracked root = %+v, want pid=100 ppid=42", tracked)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for root tracker callback")
	}

	select {
	case session := <-detector.Completed():
		if session.PackageName != "lodash" {
			t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
		}
		if session.State != SessionComplete {
			t.Fatalf("session.State = %q, want %q", session.State, SessionComplete)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed root session")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestDetector_ForkOnlyChildrenDoNotBlockCompletion(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Run(ctx)
	}()

	submitCtx := context.Background()
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       102,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	})
	detector.SubmitProcess(submitCtx, collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	})

	select {
	case session := <-detector.Completed():
		if session.PackageName != "lodash" {
			t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed session after root exit")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestParseInstallTarget(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "install lodash", want: "lodash"},
		{command: "npm i axios", want: "axios"},
		{command: "install --save-dev typescript", want: "typescript"},
		{command: "npm install", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := parseInstallTarget(tt.command)
			if got != tt.want {
				t.Fatalf("parseInstallTarget(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestDecodeArgsFixedSlots(t *testing.T) {
	args := fixedSlotArgs("npm", "install", "lodash", "--save-dev", "typescript")

	got := decodeArgs(args)
	want := "npm install lodash --save-dev typescript"
	if got != want {
		t.Fatalf("decodeArgs(fixed slots) = %q, want %q", got, want)
	}
}

func TestIsNpmInstallInvocation_FixedSlotArgs(t *testing.T) {
	event := collector.ProcessEvent{
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("npm", "install", "lodash"),
	}

	command := decodeArgs(event.Args)
	if !isNpmInstallInvocation(event, command) {
		t.Fatalf("isNpmInstallInvocation(%q) = false, want true", command)
	}
}

func TestIsNpmInstallInvocation_MissingBinaryName(t *testing.T) {
	event := collector.ProcessEvent{
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("install", "lodash"),
	}

	command := decodeArgs(event.Args)
	if isNpmInstallInvocation(event, command) {
		t.Fatalf("isNpmInstallInvocation(%q) = true, want false", command)
	}
}

func TestResolveCommand_PrefersEventArgsOverStaleCmdline(t *testing.T) {
	detector := NewDetector(0)
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		return "bash", nil
	}

	event := collector.ProcessEvent{
		Pid:  100,
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("npm", "install", "lodash"),
	}

	got := detector.resolveCommand(event)
	want := "npm install lodash"
	if got != want {
		t.Fatalf("resolveCommand() = %q, want %q", got, want)
	}
}

func fixedArgs(args string) [256]byte {
	var out [256]byte
	copy(out[:], args)
	return out
}

func fixedSlotArgs(parts ...string) [256]byte {
	var out [256]byte

	for i, part := range parts {
		offset := i * 51
		if offset >= len(out) {
			break
		}
		copy(out[offset:offset+51], part)
	}

	return out
}

func waitForDetectorExit(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("detector.Run() did not exit in time")
	}
}

func TestSessionTimeout(t *testing.T) {
const timeout = 100 * time.Millisecond

detector := NewDetector(timeout)

ctx, cancel := context.WithCancel(context.Background())
done := make(chan struct{})
go func() {
defer close(done)
detector.Run(ctx)
}()

// Submit an EXEC for npm install but never send the EXIT.
detector.SubmitProcess(context.Background(), collector.ProcessEvent{
Pid:       500,
Ppid:      1,
Comm:      fixedComm("npm"),
Args:      fixedSlotArgs("npm", "install", "lodash"),
EventType: processEventExec,
})

// Wait up to 300ms — the timer should fire after ~100ms.
var sess *Session
select {
case sess = <-detector.Completed():
case <-time.After(300 * time.Millisecond):
t.Fatal("timed out waiting for session to be completed by the session timer")
}

if sess == nil {
t.Fatal("Completed() returned nil session")
}
if !sess.TimedOut {
t.Fatalf("session.TimedOut = false, want true")
}
if sess.State != SessionComplete {
t.Fatalf("session.State = %q after timeout, want %q", sess.State, SessionComplete)
}

cancel()
waitForDetectorExit(t, done)
}
