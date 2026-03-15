// Package features – unit tests for DirCounts.
package features

import (
	"testing"
)

// TestDirCounterToMap simulates a realistic npm install trace:
//   - a handful of /usr/lib reads (node_modules linking)
//   - several /home reads (npm cache)
//   - two .ssh / .aws hits (credential-file reads that must be flagged)
//   - a /tmp write (npm's temp staging area)
//   - a /etc read (e.g. /etc/resolv.conf)
//   - a /sys probe (rare but present)
//   - an unknown category (must land in Other)
//
// Key invariants verified:
//  1. home_dir_access == Home + SshAwsWallet  (folded for QUT-DV25 vector)
//  2. ssh_aws_wallet_access == SshAwsWallet   (kept separate for alerting)
//  3. Every other counter maps 1-to-1 to its field value.
//  4. ToMap() emits exactly the expected set of keys (no extras, no missing).
func TestDirCounterToMap(t *testing.T) {
	dc := DirCounts{}

	// /usr/lib/node_modules/... — user-lib reads during linking
	dc.Add(dirUserLib) // 1
	dc.Add(dirUserLib) // 2
	dc.Add(dirUserLib) // 3
	dc.Add(dirUserLib) // 4
	dc.Add(dirUserLib) // 5

	// /home/user/.npm/cache/... — npm cache hits
	dc.Add(dirHome) // 1
	dc.Add(dirHome) // 2
	dc.Add(dirHome) // 3

	// Sensitive credential reads — must increment both SshAwsWallet and
	// ultimately be reflected in home_dir_access.
	dc.Add(dirSSHAWSWallet) // 1
	dc.Add(dirSSHAWSWallet) // 2

	// /tmp staging
	dc.Add(dirTemp) // 1
	dc.Add(dirTemp) // 2

	// /etc/resolv.conf, /etc/ssl/...
	dc.Add(dirEtc) // 1

	// /sys/fs/cgroup — kernel probe
	dc.Add(dirSys) // 1

	// /root — rare, but BPF emits it
	dc.Add(dirRoot) // 1

	// Unknown future category value and dirOther — both must land in Other.
	dc.Add(dirOther) // 1
	dc.Add(255)      // 2  — unrecognised value → default branch

	want := map[string]int{
		"root_dir_access":       1,
		"temp_dir_access":       2,
		"home_dir_access":       5, // 3 home + 2 ssh_aws_wallet
		"user_dir_access":       5,
		"sys_dir_access":        1,
		"etc_dir_access":        1,
		"other_dir_access":      2,
		"ssh_aws_wallet_access": 2,
	}

	got := dc.ToMap()

	// Verify key count first so subsequent checks are not misleading.
	if len(got) != len(want) {
		t.Errorf("ToMap() returned %d keys, want %d\n  got:  %v\n  want: %v",
			len(got), len(want), got, want)
	}

	for key, wantVal := range want {
		gotVal, ok := got[key]
		if !ok {
			t.Errorf("ToMap() missing key %q", key)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("ToMap()[%q] = %d, want %d", key, gotVal, wantVal)
		}
	}

	// Explicitly confirm the ssh_aws_wallet folding invariant so a future
	// refactor cannot silently break it.
	if got["home_dir_access"] != got["ssh_aws_wallet_access"]+dc.Home {
		t.Errorf(
			"home_dir_access (%d) != Home (%d) + ssh_aws_wallet_access (%d)",
			got["home_dir_access"], dc.Home, got["ssh_aws_wallet_access"],
		)
	}
}

// TestDirCounterToMap_Empty verifies that a zero-value DirCounts produces a
// map where every key is present and every value is 0.
func TestDirCounterToMap_Empty(t *testing.T) {
	dc := DirCounts{}
	got := dc.ToMap()

	expectedKeys := []string{
		"root_dir_access",
		"temp_dir_access",
		"home_dir_access",
		"user_dir_access",
		"sys_dir_access",
		"etc_dir_access",
		"other_dir_access",
		"ssh_aws_wallet_access",
	}

	if len(got) != len(expectedKeys) {
		t.Errorf("empty DirCounts: ToMap() returned %d keys, want %d", len(got), len(expectedKeys))
	}

	for _, key := range expectedKeys {
		if v, ok := got[key]; !ok {
			t.Errorf("empty DirCounts: ToMap() missing key %q", key)
		} else if v != 0 {
			t.Errorf("empty DirCounts: ToMap()[%q] = %d, want 0", key, v)
		}
	}
}

// TestDirCounterAdd_AllCategories walks every defined category constant and
// confirms that a single Add() call increments exactly one field.
func TestDirCounterAdd_AllCategories(t *testing.T) {
	tests := []struct {
		name     string
		category uint8
		wantKey  string
	}{
		{"root", dirRoot, "root_dir_access"},
		{"temp", dirTemp, "temp_dir_access"},
		{"home", dirHome, "home_dir_access"},
		{"userLib", dirUserLib, "user_dir_access"},
		{"sys", dirSys, "sys_dir_access"},
		{"etc", dirEtc, "etc_dir_access"},
		{"other", dirOther, "other_dir_access"},
		// SSH_AWS_WALLET must bump both home_dir_access and ssh_aws_wallet_access.
		{"sshAwsWallet/home", dirSSHAWSWallet, "home_dir_access"},
		{"sshAwsWallet/sensitive", dirSSHAWSWallet, "ssh_aws_wallet_access"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := DirCounts{}
			dc.Add(tt.category)
			m := dc.ToMap()

			if m[tt.wantKey] != 1 {
				t.Errorf("after Add(%d), ToMap()[%q] = %d, want 1",
					tt.category, tt.wantKey, m[tt.wantKey])
			}
		})
	}
}

// TestDirCounterAdd_UnknownCategory ensures that any category value not
// defined in bpf/file_monitor.bpf.c falls through to other_dir_access rather
// than silently discarding the event.
func TestDirCounterAdd_UnknownCategory(t *testing.T) {
	unknownValues := []uint8{8, 50, 127, 200, 255}

	for _, v := range unknownValues {
		dc := DirCounts{}
		dc.Add(v)
		m := dc.ToMap()
		if m["other_dir_access"] != 1 {
			t.Errorf("Add(%d): other_dir_access = %d, want 1", v, m["other_dir_access"])
		}
	}
}
