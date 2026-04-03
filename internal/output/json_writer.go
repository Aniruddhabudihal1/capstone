package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
)

// SessionRecord is the persisted JSON representation of one monitored session.
type SessionRecord struct {
	SessionID   string                   `json:"session_id"`
	PackageName string                   `json:"package_name"`
	Timestamp   time.Time                `json:"timestamp"`
	Label       *int                     `json:"label"`
	Filetop     features.FiletopCounts   `json:"filetop"`
	Install     features.InstallFeatures `json:"install"`
	Opensnoop   map[string]int           `json:"opensnoop"`
	TCP         features.TCPCounts       `json:"tcp"`
	Syscalls    features.SyscallFeatures `json:"syscalls"`
	Patterns    features.PatternCounts   `json:"patterns"`
	ProcessTree string                   `json:"process_tree"`
	TimedOut    bool                     `json:"timed_out"`
}

// ToCSVRow returns a slice of strings representing this record as a CSV row.
//
// Column order (39 total = 3 metadata + 36 QUT-DV25 features):
//
//	package_name, label,
//	read_processes, write_processes, read_data_transfer_kb, write_data_transfer_kb, file_access_processes,
//	total_dependencies, direct_dependencies, indirect_dependencies,
//	root_dir_access, temp_dir_access, home_dir_access, user_dir_access, sys_dir_access, etc_dir_access, other_dir_access,
//	state_transitions, local_ips, remote_ips, local_ports, remote_ports,
//	io_ops, file_ops, network_ops, time_ops, security_ops, process_ops,
//	p1_file_metadata, p2_read_data, p3_write_data, p4_socket_create, p5_process_create,
//	p6_memory_map, p7_fd_manage, p8_ipc, p9_file_lock, p10_error_handle,
//	severity_score
func (s *SessionRecord) ToCSVRow() []string {
	labelStr := "0"
	if s.Label != nil {
		labelStr = strconv.Itoa(*s.Label)
	}

	opensnoop := s.Opensnoop
	if opensnoop == nil {
		opensnoop = (&features.DirCounts{}).ToMap()
	}
	osGet := func(key string) string {
		return strconv.Itoa(opensnoop[key])
	}

	// severity_score: mirrors label for ML team baseline (0 = benign, 1 = malicious)
	severityScore := labelStr

	return []string{
		// metadata
		s.PackageName,
		labelStr,
		// filetop (5)
		strconv.Itoa(s.Filetop.ReadProcesses),
		strconv.Itoa(s.Filetop.WriteProcesses),
		strconv.Itoa(s.Filetop.ReadDataTransferKB),
		strconv.Itoa(s.Filetop.WriteDataTransferKB),
		strconv.Itoa(s.Filetop.FileAccessProcesses),
		// install (3)
		strconv.Itoa(s.Install.TotalDependencies),
		strconv.Itoa(s.Install.DirectDependencies),
		strconv.Itoa(s.Install.IndirectDependencies),
		// opensnoop / dir counts (7)
		osGet("root_dir_access"),
		osGet("temp_dir_access"),
		osGet("home_dir_access"),
		osGet("user_dir_access"),
		osGet("sys_dir_access"),
		osGet("etc_dir_access"),
		osGet("other_dir_access"),
		// tcp (5)
		strconv.Itoa(s.TCP.StateTransitions),
		strconv.Itoa(s.TCP.LocalIPs),
		strconv.Itoa(s.TCP.RemoteIPs),
		strconv.Itoa(s.TCP.LocalPorts),
		strconv.Itoa(s.TCP.RemotePorts),
		// syscalls (6)
		strconv.Itoa(s.Syscalls.IoOps),
		strconv.Itoa(s.Syscalls.FileOps),
		strconv.Itoa(s.Syscalls.NetworkOps),
		strconv.Itoa(s.Syscalls.TimeOps),
		strconv.Itoa(s.Syscalls.SecurityOps),
		strconv.Itoa(s.Syscalls.ProcessOps),
		// patterns (10)
		strconv.Itoa(s.Patterns.P1),
		strconv.Itoa(s.Patterns.P2),
		strconv.Itoa(s.Patterns.P3),
		strconv.Itoa(s.Patterns.P4),
		strconv.Itoa(s.Patterns.P5),
		strconv.Itoa(s.Patterns.P6),
		strconv.Itoa(s.Patterns.P7),
		strconv.Itoa(s.Patterns.P8),
		strconv.Itoa(s.Patterns.P9),
		strconv.Itoa(s.Patterns.P10),
		// severity metadata
		severityScore,
	}
}

// BuildRecord converts a collected session into the JSON output format.
func BuildRecord(sess *session.Session, installFeatures features.InstallFeatures) SessionRecord {
	record := SessionRecord{
		Install:   installFeatures,
		Opensnoop: (&features.DirCounts{}).ToMap(),
	}

	if sess == nil {
		return record
	}

	record.SessionID = sess.ID
	record.PackageName = sess.PackageName
	record.ProcessTree = sess.ProcessTree
	record.Timestamp = sessionTimestamp(sess)
	record.Syscalls = buildSyscallFeatures(sess.SyscallCounts)
	record.TimedOut = sess.TimedOut

	if sess.FiletopAgg != nil {
		record.Filetop = sess.FiletopAgg.Snapshot()
	}
	if sess.DirCounts != nil {
		record.Opensnoop = sess.DirCounts.ToMap()
	}
	if sess.TCPAgg != nil {
		record.TCP = sess.TCPAgg.Counts()
	}
	if sess.NGramCtr != nil {
		record.Patterns = sess.NGramCtr.Snapshot()
	}

	return record
}

// JSONWriter persists session records as indented JSON files.
type JSONWriter struct {
	outputDir string
}

// NewJSONWriter creates a JSON writer rooted at dir.
func NewJSONWriter(dir string) *JSONWriter {
	return &JSONWriter{outputDir: dir}
}

// Write marshals and writes a session record, returning the absolute path.
func (w *JSONWriter) Write(record SessionRecord) (string, error) {
	if err := os.MkdirAll(w.outputDir, 0o755); err != nil {
		return "", err
	}

	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}

	path := filepath.Join(w.outputDir, fmt.Sprintf("%s_%s.json", record.SessionID, record.PackageName))
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	if valErr := MustValidate(absPath); valErr != nil {
		// Re-read warnings individually for per-field logging.
		var top map[string]interface{}
		if jsonErr := json.Unmarshal(payload, &top); jsonErr == nil {
			for _, field := range ValidateRecord(flattenMap(top)) {
				slog.Warn("session record field missing or zero", "field", field, "path", absPath)
			}
		}
	}

	return absPath, nil
}

// Validate returns warnings for critical missing or zeroed fields.
func Validate(record SessionRecord) []string {
	var warnings []string

	if record.Syscalls.IoOps == 0 {
		warnings = append(warnings, "warning: syscalls.io_ops is 0 (missing syscall tracer data?)")
	}
	if record.Filetop.FileAccessProcesses == 0 {
		warnings = append(warnings, "warning: filetop.file_access_processes is 0 (missing filetop tracer data?)")
	}
	if record.Install.TotalDependencies == 0 {
		warnings = append(warnings, "warning: install.total_dependencies is 0 (missing package-lock/package.json data?)")
	}
	if record.ProcessTree == "" {
		warnings = append(warnings, "warning: process_tree is empty (missing process tracer data?)")
	}

	return warnings
}

func sessionTimestamp(sess *session.Session) time.Time {
	if !sess.EndTime.IsZero() {
		return sess.EndTime
	}

	return sess.StartTime
}

func buildSyscallFeatures(counts map[features.SyscallCategory]int) features.SyscallFeatures {
	if counts == nil {
		return features.SyscallFeatures{}
	}

	return features.SyscallFeatures{
		IoOps:       counts[features.CategoryIO],
		FileOps:     counts[features.CategoryFile],
		NetworkOps:  counts[features.CategoryNetwork],
		TimeOps:     counts[features.CategoryTime],
		SecurityOps: counts[features.CategorySecurity],
		ProcessOps:  counts[features.CategoryProcess],
		UnknownOps:  counts[features.CategoryUnknown],
	}
}
