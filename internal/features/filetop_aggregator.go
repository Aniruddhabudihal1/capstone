// Package features provides userspace aggregation helpers for eBPF event
// streams.
//
// FiletopCounts reports read and write activity in a compact feature-vector
// form, but the data-transfer fields are only approximations in this design.
// Open flags tell us how a file was opened, not how many bytes were actually
// consumed or produced. Even when we supplement opens with raw syscall-side
// byte accounting, that still reflects attempted I/O observed in userspace or
// entry probes rather than the kernel's final completed result. A more
// accurate implementation would kretprobe vfs_read and record the actual byte
// count returned by the kernel for each completed read operation.
package features

import (
	"sync"
	"syscall"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

// FiletopCounts is the JSON-facing summary of file access activity.
type FiletopCounts struct {
	ReadProcesses       int `json:"read_processes"`
	WriteProcesses      int `json:"write_processes"`
	ReadDataTransferKB  int `json:"read_data_transfer_kb"`
	WriteDataTransferKB int `json:"write_data_transfer_kb"`
	FileAccessProcesses int `json:"file_access_processes"`
}

// FiletopAggregator tracks deduplicated read/write/all-access PIDs and
// approximate byte totals.
type FiletopAggregator struct {
	readPIDs        map[uint32]bool
	writePIDs       map[uint32]bool
	allPIDs         map[uint32]bool
	totalReadBytes  int
	totalWriteBytes int
	mu              sync.Mutex
}

// NewFiletopAggregator creates an initialized FiletopAggregator.
func NewFiletopAggregator() *FiletopAggregator {
	return &FiletopAggregator{
		readPIDs:  make(map[uint32]bool),
		writePIDs: make(map[uint32]bool),
		allPIDs:   make(map[uint32]bool),
	}
}

// Add records one file event into the deduplicated process sets.
func (a *FiletopAggregator) Add(event collector.FileEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.readPIDs == nil {
		a.readPIDs = make(map[uint32]bool)
	}
	if a.writePIDs == nil {
		a.writePIDs = make(map[uint32]bool)
	}
	if a.allPIDs == nil {
		a.allPIDs = make(map[uint32]bool)
	}

	mode := event.Flags & syscall.O_ACCMODE
	if mode == syscall.O_RDONLY {
		a.readPIDs[event.Pid] = true
	}
	if mode == syscall.O_WRONLY || mode == syscall.O_RDWR || (event.Flags&syscall.O_CREAT != 0) {
		a.writePIDs[event.Pid] = true
	}

	a.allPIDs[event.Pid] = true
}

// AddReadBytes accumulates raw read bytes for the current aggregation window.
func (a *FiletopAggregator) AddReadBytes(pid uint32, bytes int) {
	_ = pid

	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalReadBytes += bytes
}

// AddWriteBytes accumulates raw write bytes for the current aggregation window.
func (a *FiletopAggregator) AddWriteBytes(pid uint32, bytes int) {
	_ = pid

	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalWriteBytes += bytes
}

// Snapshot returns the current deduplicated counts and approximate transfer
// totals in kibibytes rounded down.
func (a *FiletopAggregator) Snapshot() FiletopCounts {
	a.mu.Lock()
	defer a.mu.Unlock()

	return FiletopCounts{
		ReadProcesses:       len(a.readPIDs),
		WriteProcesses:      len(a.writePIDs),
		ReadDataTransferKB:  a.totalReadBytes / 1024,
		WriteDataTransferKB: a.totalWriteBytes / 1024,
		FileAccessProcesses: len(a.allPIDs),
	}
}
