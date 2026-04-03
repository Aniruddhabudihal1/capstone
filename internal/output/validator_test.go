package output

import (
	"testing"
)

// fullRecord returns a flat map containing all 36 required QUT-DV25 fields
// with non-zero values, mimicking the flattened JSON output.
func fullRecord() map[string]interface{} {
	return map[string]interface{}{
		// FILETOP
		"read_processes":         float64(5),
		"write_processes":        float64(2),
		"read_data_transfer_kb":  float64(12),
		"write_data_transfer_kb": float64(4),
		"file_access_processes":  float64(6),
		// INSTALL
		"total_dependencies":    float64(17),
		"direct_dependencies":   float64(4),
		"indirect_dependencies": float64(13),
		// OPENSNOOP
		"root_dir_access":  float64(1),
		"temp_dir_access":  float64(2),
		"home_dir_access":  float64(3),
		"user_dir_access":  float64(4),
		"sys_dir_access":   float64(5),
		"etc_dir_access":   float64(6),
		"other_dir_access": float64(7),
		// TCP
		"state_transitions": float64(8),
		"local_ips":         float64(1),
		"remote_ips":        float64(2),
		"local_ports":       float64(3),
		"remote_ports":      float64(4),
		// SYSCALLS
		"io_ops":       float64(9),
		"file_ops":     float64(8),
		"network_ops":  float64(7),
		"time_ops":     float64(6),
		"security_ops": float64(5),
		"process_ops":  float64(4),
		// PATTERNS
		"p1_file_metadata": float64(1),
		"p2_read_data":     float64(2),
		"p3_write_data":    float64(3),
		"p4_socket_create": float64(4),
		"p5_process_create": float64(5),
		"p6_memory_map":    float64(6),
		"p7_fd_manage":     float64(7),
		"p8_ipc":           float64(8),
		"p9_file_lock":     float64(9),
		"p10_error_handle": float64(10),
	}
}

func TestValidateRecord_AllPresent(t *testing.T) {
	warnings := ValidateRecord(fullRecord())
	if len(warnings) != 0 {
		t.Fatalf("ValidateRecord(full) returned %d warnings, want 0: %v", len(warnings), warnings)
	}
}

func TestValidateRecord_MissingField(t *testing.T) {
	data := fullRecord()
	delete(data, "etc_dir_access")

	warnings := ValidateRecord(data)

	if len(warnings) != 1 {
		t.Fatalf("ValidateRecord(missing etc_dir_access) returned %v, want [\"etc_dir_access\"]", warnings)
	}
	if warnings[0] != "etc_dir_access" {
		t.Fatalf("ValidateRecord(missing etc_dir_access) warning = %q, want %q", warnings[0], "etc_dir_access")
	}
}

func TestValidateRecord_ZeroValue(t *testing.T) {
	data := fullRecord()
	data["root_dir_access"] = float64(0)

	warnings := ValidateRecord(data)

	found := false
	for _, w := range warnings {
		if w == "root_dir_access" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ValidateRecord(zero root_dir_access) = %v, want it to contain \"root_dir_access\"", warnings)
	}
}
