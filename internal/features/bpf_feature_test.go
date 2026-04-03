// Package features – unit tests for BPF-event integration in the features layer.
//
// These are pure Go tests: no BPF programs are loaded.  They verify that the
// DirCounter and FiletopAggregator behave correctly when fed mock FileEvent
// values that simulate what the sys_exit_openat handler emits.
package features

import (
	"syscall"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

// TestOpenSuccessTracking verifies that both failed (open_success=0) and
// successful (open_success=1) file opens are counted in the DirCounter and
// FiletopAggregator.  The current design counts all attempts regardless of
// outcome so that the ML model can observe failed probes of sensitive paths.
func TestOpenSuccessTracking(t *testing.T) {
	t.Run("failed_open_increments_other", func(t *testing.T) {
		dc := DirCounts{}
		agg := NewFiletopAggregator()

		// Simulate an openat() on /.ssh/id_rsa_doesnotexist that returned -ENOENT.
		// The BPF exit handler classifies the path as DIR_OTHER (category 0)
		// because .ssh paths are no longer given a special category.
		evt := collector.FileEvent{
			Pid:         1234,
			OpenSuccess: 0,                        // syscall failed
			DirCategory: uint8(collector.DirOther), // DIR_OTHER = 0
			Flags:       uint32(syscall.O_RDONLY),
		}

		dc.Add(evt.DirCategory)
		agg.Add(evt)

		m := dc.ToMap()
		if m["other_dir_access"] != 1 {
			t.Errorf("after failed open: other_dir_access = %d, want 1", m["other_dir_access"])
		}

		snap := agg.Snapshot()
		if snap.FileAccessProcesses != 1 {
			t.Errorf("after failed open: FileAccessProcesses = %d, want 1", snap.FileAccessProcesses)
		}
	})

	t.Run("successful_open_increments_other", func(t *testing.T) {
		dc := DirCounts{}
		agg := NewFiletopAggregator()

		// Simulate an openat() on some other-category path that succeeded.
		evt := collector.FileEvent{
			Pid:         5678,
			OpenSuccess: 1,                        // syscall succeeded
			DirCategory: uint8(collector.DirOther), // DIR_OTHER = 0
			Flags:       uint32(syscall.O_RDONLY),
		}

		dc.Add(evt.DirCategory)
		agg.Add(evt)

		m := dc.ToMap()
		if m["other_dir_access"] != 1 {
			t.Errorf("after successful open: other_dir_access = %d, want 1", m["other_dir_access"])
		}

		snap := agg.Snapshot()
		if snap.FileAccessProcesses != 1 {
			t.Errorf("after successful open: FileAccessProcesses = %d, want 1", snap.FileAccessProcesses)
		}
	})

	t.Run("both_failed_and_successful_both_count", func(t *testing.T) {
		dc := DirCounts{}
		agg := NewFiletopAggregator()

		events := []collector.FileEvent{
			{
				Pid:         100,
				OpenSuccess: 0, // failed
				DirCategory: uint8(collector.DirOther),
				Flags:       uint32(syscall.O_RDONLY),
			},
			{
				Pid:         101,
				OpenSuccess: 1, // succeeded
				DirCategory: uint8(collector.DirOther),
				Flags:       uint32(syscall.O_RDONLY),
			},
		}

		for _, e := range events {
			dc.Add(e.DirCategory)
			agg.Add(e)
		}

		m := dc.ToMap()
		if m["other_dir_access"] != 2 {
			t.Errorf("two opens (fail+success): other_dir_access = %d, want 2", m["other_dir_access"])
		}

		snap := agg.Snapshot()
		if snap.FileAccessProcesses != 2 {
			t.Errorf("two opens (fail+success): FileAccessProcesses = %d, want 2", snap.FileAccessProcesses)
		}
	})
}
