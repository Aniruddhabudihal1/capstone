package features

import (
	"syscall"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

func TestFiletopAggregatorDeduplicatesReadProcesses(t *testing.T) {
	agg := NewFiletopAggregator()

	event := collector.FileEvent{
		Pid:   100,
		Flags: uint32(syscall.O_RDONLY),
	}

	for i := 0; i < 5; i++ {
		agg.Add(event)
	}

	got := agg.Snapshot()
	if got.ReadProcesses != 1 {
		t.Fatalf("ReadProcesses = %d, want 1", got.ReadProcesses)
	}
}

func TestFiletopAggregatorParsesWriteFlags(t *testing.T) {
	agg := NewFiletopAggregator()

	events := []collector.FileEvent{
		{Pid: 101, Flags: uint32(syscall.O_WRONLY)},
		{Pid: 102, Flags: uint32(syscall.O_RDWR)},
		{Pid: 103, Flags: uint32(syscall.O_CREAT)},
	}

	for _, event := range events {
		agg.Add(event)
	}

	got := agg.Snapshot()
	if got.WriteProcesses != 3 {
		t.Fatalf("WriteProcesses = %d, want 3", got.WriteProcesses)
	}
}

func TestFiletopAggregatorTracksUniqueFileAccessProcesses(t *testing.T) {
	agg := NewFiletopAggregator()

	events := []collector.FileEvent{
		{Pid: 200, Flags: uint32(syscall.O_RDONLY)},
		{Pid: 201, Flags: uint32(syscall.O_WRONLY)},
		{Pid: 202, Flags: uint32(syscall.O_RDWR)},
	}

	for _, event := range events {
		agg.Add(event)
	}

	got := agg.Snapshot()
	if got.FileAccessProcesses != 3 {
		t.Fatalf("FileAccessProcesses = %d, want 3", got.FileAccessProcesses)
	}
}

func TestFiletopAggregatorDataTransferMath(t *testing.T) {
	agg := NewFiletopAggregator()

	agg.AddReadBytes(300, 2048)
	agg.AddReadBytes(300, 500)
	agg.AddWriteBytes(301, 3072)
	agg.AddWriteBytes(301, 700)

	got := agg.Snapshot()
	if got.ReadDataTransferKB != 2 {
		t.Fatalf("ReadDataTransferKB = %d, want 2", got.ReadDataTransferKB)
	}
	if got.WriteDataTransferKB != 3 {
		t.Fatalf("WriteDataTransferKB = %d, want 3", got.WriteDataTransferKB)
	}
	if got.ReadProcesses != 0 {
		t.Fatalf("ReadProcesses = %d, want 0", got.ReadProcesses)
	}
	if got.WriteProcesses != 0 {
		t.Fatalf("WriteProcesses = %d, want 0", got.WriteProcesses)
	}
	if got.FileAccessProcesses != 0 {
		t.Fatalf("FileAccessProcesses = %d, want 0", got.FileAccessProcesses)
	}
}
