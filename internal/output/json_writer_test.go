package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
)

func TestJSONWriter_WriteSuccess(t *testing.T) {
	writer := NewJSONWriter(t.TempDir())

	record := SessionRecord{
		SessionID:   "test-123",
		PackageName: "lodash",
		Timestamp:   time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
		Filetop: features.FiletopCounts{
			ReadProcesses:       5,
			WriteProcesses:      2,
			ReadDataTransferKB:  12,
			WriteDataTransferKB: 4,
			FileAccessProcesses: 6,
		},
		Install: features.InstallFeatures{
			TotalDependencies:    17,
			DirectDependencies:   4,
			IndirectDependencies: 13,
		},
		Opensnoop: map[string]int{
			"root_dir_access":       0,
			"temp_dir_access":       1,
			"home_dir_access":       2,
			"user_dir_access":       3,
			"sys_dir_access":        4,
			"etc_dir_access":        5,
			"other_dir_access":      6,
			"ssh_aws_wallet_access": 7,
		},
		TCP: features.TCPCounts{
			StateTransitions: 8,
			LocalIPs:         1,
			RemoteIPs:        2,
			LocalPorts:       3,
			RemotePorts:      4,
		},
		Syscalls: features.SyscallFeatures{
			IoOps:       9,
			FileOps:     8,
			NetworkOps:  7,
			TimeOps:     6,
			SecurityOps: 5,
			ProcessOps:  4,
			UnknownOps:  3,
		},
		Patterns: features.PatternCounts{
			P1:  1,
			P2:  2,
			P3:  3,
			P4:  4,
			P5:  5,
			P6:  6,
			P7:  7,
			P8:  8,
			P9:  9,
			P10: 10,
		},
		ProcessTree: "npm(123)->node(456)",
	}

	path, err := writer.Write(record)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("Write() path = %q, want absolute path", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("json.Unmarshal(...) error = %v", err)
	}

	if got["session_id"] != "test-123" {
		t.Fatalf("session_id = %v, want %q", got["session_id"], "test-123")
	}

	label, ok := got["label"]
	if !ok {
		t.Fatal("label key missing from marshaled JSON")
	}
	if label != nil {
		t.Fatalf("label = %v, want nil", label)
	}
}

func TestBuildRecord_NilSafety(t *testing.T) {
	sess := &session.Session{
		ID:            "nil-safe-session",
		PackageName:   "left-pad",
		StartTime:     time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC),
		FiletopAgg:    nil,
		DirCounts:     nil,
		TCPAgg:        nil,
		NGramCtr:      nil,
		SyscallCounts: nil,
	}

	var (
		record   SessionRecord
		panicked any
	)

	func() {
		defer func() {
			panicked = recover()
		}()
		record = BuildRecord(sess, features.InstallFeatures{})
	}()

	if panicked != nil {
		t.Fatalf("BuildRecord(...) panicked: %v", panicked)
	}

	if record.Filetop != (features.FiletopCounts{}) {
		t.Fatalf("Filetop = %#v, want zero value", record.Filetop)
	}
	if record.TCP != (features.TCPCounts{}) {
		t.Fatalf("TCP = %#v, want zero value", record.TCP)
	}
	if record.Patterns != (features.PatternCounts{}) {
		t.Fatalf("Patterns = %#v, want zero value", record.Patterns)
	}
	if record.Syscalls != (features.SyscallFeatures{}) {
		t.Fatalf("Syscalls = %#v, want zero value", record.Syscalls)
	}

	wantOpensnoop := (&features.DirCounts{}).ToMap()
	if !reflect.DeepEqual(record.Opensnoop, wantOpensnoop) {
		t.Fatalf("Opensnoop = %#v, want %#v", record.Opensnoop, wantOpensnoop)
	}
}

func TestValidate(t *testing.T) {
	populated := SessionRecord{
		Filetop: features.FiletopCounts{
			FileAccessProcesses: 1,
		},
		Install: features.InstallFeatures{
			TotalDependencies: 1,
		},
		Syscalls: features.SyscallFeatures{
			IoOps: 1,
		},
		ProcessTree: "npm(123)",
	}

	if got := Validate(populated); len(got) != 0 {
		t.Fatalf("Validate(populated) returned %d warnings, want 0: %v", len(got), got)
	}

	empty := SessionRecord{}
	got := Validate(empty)

	wantWarnings := []string{
		"warning: syscalls.io_ops is 0 (missing syscall tracer data?)",
		"warning: filetop.file_access_processes is 0 (missing filetop tracer data?)",
		"warning: install.total_dependencies is 0 (missing package-lock/package.json data?)",
		"warning: process_tree is empty (missing process tracer data?)",
	}

	for _, want := range wantWarnings {
		if !slices.Contains(got, want) {
			t.Fatalf("Validate(empty) = %v, want warning %q", got, want)
		}
	}
}
