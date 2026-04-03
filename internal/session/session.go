package session

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

// SessionState describes the lifecycle phase of one npm install session.
type SessionState string

const (
	SessionWaiting  SessionState = "waiting"
	SessionActive   SessionState = "active"
	SessionComplete SessionState = "complete"
)

// Session tracks one npm install invocation and the features collected for it.
type Session struct {
	mu sync.Mutex

	ID          string
	PackageName string
	Cwd         string
	NpmPID      uint32
	ChildPIDs   map[uint32]bool
	LivePIDs    map[uint32]bool
	State       SessionState
	StartTime   time.Time
	EndTime     time.Time

	FiletopAgg *features.FiletopAggregator
	DirCounts  *features.DirCounts
	TCPAgg     *features.TCPAggregator
	NGramCtr   *features.NGramCounter

	SyscallCounts map[features.SyscallCategory]int
	ProcessTree   string
	TimedOut      bool
}

// NewSession creates an initialized npm install session.
func NewSession(npmPID uint32, packageName string) *Session {
	startTime := time.Now()
	if packageName == "" {
		packageName = "unknown"
	}

	return &Session{
		ID:            fmt.Sprintf("npm-%d", startTime.Unix()),
		PackageName:   packageName,
		NpmPID:        npmPID,
		ChildPIDs:     make(map[uint32]bool),
		LivePIDs:      map[uint32]bool{npmPID: true},
		State:         SessionActive,
		StartTime:     startTime,
		FiletopAgg:    features.NewFiletopAggregator(),
		DirCounts:     &features.DirCounts{},
		TCPAgg:        features.NewTCPAggregator(),
		NGramCtr:      features.NewNGramCounter(),
		SyscallCounts: make(map[features.SyscallCategory]int),
		ProcessTree:   fmt.Sprintf("npm(%d)", npmPID),
	}
}

// AddProcess records a child process as part of the session process tree.
func (s *Session) AddProcess(event collector.ProcessEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ChildPIDs == nil {
		s.ChildPIDs = make(map[uint32]bool)
	}

	s.ChildPIDs[event.Pid] = true
	s.ProcessTree += fmt.Sprintf("->%s(%d)", decodeComm(event.Comm), event.Pid)
}

// AddSyscall records one syscall against the session category and n-gram data.
func (s *Session) AddSyscall(event collector.SyscallEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.SyscallCounts == nil {
		s.SyscallCounts = make(map[features.SyscallCategory]int)
	}
	if s.NGramCtr == nil {
		s.NGramCtr = features.NewNGramCounter()
	}

	category := features.Categorise(event.SyscallID)
	s.SyscallCounts[category]++
	s.NGramCtr.Push(event.SyscallID)
}

// AddFile forwards one file event into the session's file activity summary.
func (s *Session) AddFile(event collector.FileEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FiletopAgg == nil {
		s.FiletopAgg = features.NewFiletopAggregator()
	}
	if s.DirCounts == nil {
		s.DirCounts = &features.DirCounts{}
	}

	s.FiletopAgg.Add(event)
	s.DirCounts.Add(event.DirCategory)
}

// AddTCP forwards one TCP state transition into the session TCP summary.
func (s *Session) AddTCP(event collector.TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TCPAgg == nil {
		s.TCPAgg = features.NewTCPAggregator()
	}

	s.TCPAgg.Add(features.TCPEvent{
		Pid:         event.Pid,
		Saddr:       event.Saddr,
		Daddr:       event.Daddr,
		Sport:       event.Sport,
		Dport:       event.Dport,
		OldState:    event.OldState,
		NewState:    event.NewState,
		TimestampNs: event.TimestampNs,
	})
}

// AddBytes records real TCP byte counts into the session's file-transfer
// summary.  Direction 0 means bytes received (tcp_recvmsg retval);
// direction 1 means bytes sent (tcp_sendmsg size argument).
func (s *Session) AddBytes(event collector.BytesEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FiletopAgg == nil {
		s.FiletopAgg = features.NewFiletopAggregator()
	}

	if event.Direction == 0 {
		s.FiletopAgg.AddReadBytes(event.Pid, int(event.Bytes))
	} else {
		s.FiletopAgg.AddWriteBytes(event.Pid, int(event.Bytes))
	}
}

// Complete marks the session as finished and records its end time.
func (s *Session) Complete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = SessionComplete
	s.EndTime = time.Now()
}

// TrackPID records one process as part of the session's live process set.
func (s *Session) TrackPID(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LivePIDs == nil {
		s.LivePIDs = make(map[uint32]bool)
	}

	s.LivePIDs[pid] = true
}

// HasLivePID reports whether pid is currently counted in the session's live
// process set.
func (s *Session) HasLivePID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.LivePIDs[pid]
}

// ExitPID removes one process from the session's live process set and returns
// the number of tracked processes still running.
func (s *Session) ExitPID(pid uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LivePIDs == nil {
		return 0
	}

	delete(s.LivePIDs, pid)
	return len(s.LivePIDs)
}

// HasChildPID reports whether the session has already recorded pid in its
// process tree.
func (s *Session) HasChildPID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ChildPIDs[pid]
}

func decodeComm(comm [16]byte) string {
	end := bytes.IndexByte(comm[:], 0)
	if end == -1 {
		end = len(comm)
	}

	return string(comm[:end])
}
