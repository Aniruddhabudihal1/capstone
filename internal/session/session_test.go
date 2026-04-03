package session

import (
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

func TestNewSession(t *testing.T) {
	before := time.Now()
	session := NewSession(4242, "left-pad")
	after := time.Now()

	if session == nil {
		t.Fatal("NewSession() returned nil")
	}
	if session.PackageName != "left-pad" {
		t.Fatalf("PackageName = %q, want %q", session.PackageName, "left-pad")
	}
	if session.NpmPID != 4242 {
		t.Fatalf("NpmPID = %d, want %d", session.NpmPID, 4242)
	}
	if session.State != SessionActive {
		t.Fatalf("State = %q, want %q", session.State, SessionActive)
	}
	if session.StartTime.IsZero() {
		t.Fatal("StartTime is zero, want non-zero")
	}
	if session.StartTime.Before(before) || session.StartTime.After(after) {
		t.Fatalf("StartTime = %v, want between %v and %v", session.StartTime, before, after)
	}
	if !session.EndTime.IsZero() {
		t.Fatalf("EndTime = %v, want zero", session.EndTime)
	}
	if session.ProcessTree != "npm(4242)" {
		t.Fatalf("ProcessTree = %q, want %q", session.ProcessTree, "npm(4242)")
	}
	if !strings.HasPrefix(session.ID, "npm-") {
		t.Fatalf("ID = %q, want prefix %q", session.ID, "npm-")
	}
	if _, err := strconv.ParseInt(strings.TrimPrefix(session.ID, "npm-"), 10, 64); err != nil {
		t.Fatalf("ID timestamp suffix is not numeric: %v", err)
	}
	if session.ChildPIDs == nil {
		t.Fatal("ChildPIDs is nil, want initialized map")
	}
	if session.LivePIDs == nil {
		t.Fatal("LivePIDs is nil, want initialized map")
	}
	if !session.LivePIDs[4242] {
		t.Fatal("LivePIDs missing root npm pid")
	}
	if session.SyscallCounts == nil {
		t.Fatal("SyscallCounts is nil, want initialized map")
	}
	if session.FiletopAgg == nil {
		t.Fatal("FiletopAgg is nil, want initialized aggregator")
	}
	if session.DirCounts == nil {
		t.Fatal("DirCounts is nil, want initialized counter")
	}
	if session.TCPAgg == nil {
		t.Fatal("TCPAgg is nil, want initialized aggregator")
	}
	if session.NGramCtr == nil {
		t.Fatal("NGramCtr is nil, want initialized counter")
	}
}

func TestAddProcess(t *testing.T) {
	session := NewSession(9001, "pkg")

	tests := []struct {
		name    string
		event   collector.ProcessEvent
		wantPID uint32
		wantStr string
	}{
		{
			name:    "shell",
			event:   collector.ProcessEvent{Pid: 111, Comm: fixedComm("sh")},
			wantPID: 111,
			wantStr: "->sh(111)",
		},
		{
			name:    "node",
			event:   collector.ProcessEvent{Pid: 222, Comm: fixedComm("node")},
			wantPID: 222,
			wantStr: "->node(222)",
		},
	}

	wantTree := "npm(9001)"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session.AddProcess(tt.event)
			wantTree += tt.wantStr

			if !session.ChildPIDs[tt.wantPID] {
				t.Fatalf("ChildPIDs missing pid %d after AddProcess", tt.wantPID)
			}
			if session.ProcessTree != wantTree {
				t.Fatalf("ProcessTree = %q, want %q", session.ProcessTree, wantTree)
			}
		})
	}
}

func TestAddSyscall(t *testing.T) {
	session := NewSession(101, "pkg")

	session.AddSyscall(collector.SyscallEvent{Pid: 101, SyscallID: 257})

	if got := session.SyscallCounts[features.CategoryFile]; got != 1 {
		t.Fatalf("SyscallCounts[CategoryFile] = %d, want 1", got)
	}

	for _, syscallID := range []uint32{262, 257, 5} {
		session.AddSyscall(collector.SyscallEvent{Pid: 101, SyscallID: syscallID})
	}

	if got := session.NGramCtr.Snapshot().P1; got != 1 {
		t.Fatalf("NGramCtr.Snapshot().P1 = %d, want 1", got)
	}
	if got := session.SyscallCounts[features.CategoryFile]; got != 4 {
		t.Fatalf("SyscallCounts[CategoryFile] = %d, want 4", got)
	}
}

func TestStateTransition(t *testing.T) {
	session := NewSession(202, "pkg")

	session.Complete()

	if session.State != SessionComplete {
		t.Fatalf("State = %q, want %q", session.State, SessionComplete)
	}
	if session.EndTime.IsZero() {
		t.Fatal("EndTime is zero, want non-zero")
	}
	if session.EndTime.Before(session.StartTime) {
		t.Fatalf("EndTime = %v, want at or after StartTime %v", session.EndTime, session.StartTime)
	}
}

func TestAddFileUpdatesDirCounts(t *testing.T) {
	session := NewSession(404, "pkg")

	session.AddFile(collector.FileEvent{
		Pid:         404,
		DirCategory: uint8(collector.DirTemp),
		Flags:       uint32(syscall.O_RDONLY),
	})

	if session.DirCounts.Temp != 1 {
		t.Fatalf("DirCounts.Temp = %d, want 1", session.DirCounts.Temp)
	}

	fileCounts := session.FiletopAgg.Snapshot()
	if fileCounts.FileAccessProcesses != 1 {
		t.Fatalf("FileAccessProcesses = %d, want 1", fileCounts.FileAccessProcesses)
	}
}

func TestConcurrency(t *testing.T) {
	session := NewSession(303, "pkg")

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)

		go func() {
			defer wg.Done()

			pid := uint32(1000 + i)
			syscallIDs := []uint32{257, 262, 5, 41}
			flags := uint32(syscall.O_RDONLY)
			if i%2 == 1 {
				flags = uint32(syscall.O_WRONLY)
			}

			session.AddProcess(collector.ProcessEvent{
				Pid:  pid,
				Comm: fixedComm("node"),
			})
			session.AddSyscall(collector.SyscallEvent{
				Pid:       pid,
				SyscallID: syscallIDs[i%len(syscallIDs)],
			})
			session.AddFile(collector.FileEvent{
				Pid:   pid,
				Flags: flags,
			})
			session.AddTCP(collector.TCPEvent{
				Pid:      pid,
				Saddr:    uint32(i + 1),
				Daddr:    uint32(i + 10_001),
				Sport:    uint16(3000 + i),
				Dport:    uint16(4000 + i),
				OldState: 1,
				NewState: 2,
			})
		}()
	}

	wg.Wait()

	if got := len(session.ChildPIDs); got != 100 {
		t.Fatalf("len(ChildPIDs) = %d, want 100", got)
	}

	totalSyscalls := 0
	for _, count := range session.SyscallCounts {
		totalSyscalls += count
	}
	if totalSyscalls != 100 {
		t.Fatalf("total syscall counts = %d, want 100", totalSyscalls)
	}

	fileCounts := session.FiletopAgg.Snapshot()
	if fileCounts.FileAccessProcesses != 100 {
		t.Fatalf("FileAccessProcesses = %d, want 100", fileCounts.FileAccessProcesses)
	}
	if fileCounts.ReadProcesses == 0 {
		t.Fatal("ReadProcesses = 0, want non-zero")
	}
	if fileCounts.WriteProcesses == 0 {
		t.Fatal("WriteProcesses = 0, want non-zero")
	}
	if got := session.DirCounts.Root + session.DirCounts.Temp + session.DirCounts.Home + session.DirCounts.UserLib + session.DirCounts.Sys + session.DirCounts.Etc + session.DirCounts.Other; got != 100 {
		t.Fatalf("directory event count = %d, want 100", got)
	}

	tcpCounts := session.TCPAgg.Counts()
	if tcpCounts.StateTransitions != 100 {
		t.Fatalf("StateTransitions = %d, want 100", tcpCounts.StateTransitions)
	}
	if tcpCounts.LocalPorts != 100 {
		t.Fatalf("LocalPorts = %d, want 100", tcpCounts.LocalPorts)
	}
	if tcpCounts.RemotePorts != 100 {
		t.Fatalf("RemotePorts = %d, want 100", tcpCounts.RemotePorts)
	}
	if tcpCounts.LocalIPs != 100 {
		t.Fatalf("LocalIPs = %d, want 100", tcpCounts.LocalIPs)
	}
	if tcpCounts.RemoteIPs != 100 {
		t.Fatalf("RemoteIPs = %d, want 100", tcpCounts.RemoteIPs)
	}
}

func fixedComm(comm string) [16]byte {
	var out [16]byte
	copy(out[:], comm)
	return out
}
