package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// REQUIRED_FIELDS lists all 36 QUT-DV25 feature field names that must be
// present and non-zero in every session record.
var REQUIRED_FIELDS = []string{
	// FILETOP
	"read_processes",
	"write_processes",
	"read_data_transfer_kb",
	"write_data_transfer_kb",
	"file_access_processes",
	// INSTALL
	"total_dependencies",
	"direct_dependencies",
	"indirect_dependencies",
	// OPENSNOOP
	"root_dir_access",
	"temp_dir_access",
	"home_dir_access",
	"user_dir_access",
	"sys_dir_access",
	"etc_dir_access",
	"other_dir_access",
	// TCP
	"state_transitions",
	"local_ips",
	"remote_ips",
	"local_ports",
	"remote_ports",
	// SYSCALLS
	"io_ops",
	"file_ops",
	"network_ops",
	"time_ops",
	"security_ops",
	"process_ops",
	// PATTERNS
	"p1_file_metadata",
	"p2_read_data",
	"p3_write_data",
	"p4_socket_create",
	"p5_process_create",
	"p6_memory_map",
	"p7_fd_manage",
	"p8_ipc",
	"p9_file_lock",
	"p10_error_handle",
}

// ValidateRecord checks that every field in REQUIRED_FIELDS is present and
// non-zero in data.  data is expected to be a flat map (all nested JSON
// objects already merged into a single level by the caller).
//
// A missing key and a numeric zero value are both treated as warnings; the
// function does NOT return an error — it returns a list of warning field names
// so callers can decide how to handle them.
func ValidateRecord(data map[string]interface{}) []string {
	var warnings []string
	for _, field := range REQUIRED_FIELDS {
		val, ok := data[field]
		if !ok {
			warnings = append(warnings, field)
			continue
		}
		// JSON numbers unmarshal as float64.  Treat 0 as unusual.
		if n, isNum := val.(float64); isNum && n == 0 {
			warnings = append(warnings, field)
		}
	}
	return warnings
}

// MustValidate reads the JSON file at path, flattens the nested object into a
// single map, and calls ValidateRecord.  If there are any warnings it returns
// a non-nil error whose message lists all of them.
func MustValidate(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("validator: read %q: %w", path, err)
	}

	var top map[string]interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("validator: unmarshal %q: %w", path, err)
	}

	flat := flattenMap(top)
	warnings := ValidateRecord(flat)
	if len(warnings) == 0 {
		return nil
	}

	return fmt.Errorf("validator: %s: missing or zero fields: %v", path, warnings)
}

// flattenMap merges all nested map[string]interface{} values into a single
// flat map.  Leaf values from inner maps overwrite top-level keys with the
// same name, which is acceptable because the QUT-DV25 field-names are unique
// across all sections.
func flattenMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		switch child := v.(type) {
		case map[string]interface{}:
			for ck, cv := range flattenMap(child) {
				out[ck] = cv
			}
		default:
			out[k] = v
		}
	}
	return out
}
