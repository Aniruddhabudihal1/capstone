// Package features provides higher-level analysis on top of raw eBPF events.
package features

// Directory category constants mirror the C DIR_* defines in
// bpf/file_monitor.bpf.c and the DirectoryCategory iota in
// internal/collector/file_collector.go.
//
// They are duplicated here (unexported) to keep the dependency graph clean:
// the features layer must not import the collector layer.
const (
	dirOther        uint8 = 0
	dirRoot         uint8 = 1
	dirTemp         uint8 = 2
	dirHome         uint8 = 3
	dirUserLib      uint8 = 4
	dirSys          uint8 = 5
	dirEtc          uint8 = 6
	dirSSHAWSWallet uint8 = 7
)

// DirCounts accumulates directory-access counts for a single npm-install
// session.  Each field corresponds to one of the DIR_* categories emitted
// by the file_monitor BPF program.
//
// SshAwsWallet is stored separately from Home so that the alerting layer can
// distinguish a routine home-directory read from a credential-related one,
// while ToMap() still rolls both into "home_dir_access" for the QUT-DV25
// feature vector.
type DirCounts struct {
	Root         int
	Temp         int
	Home         int
	UserLib      int
	Sys          int
	Etc          int
	SshAwsWallet int
	Other        int
}

// Add increments the counter that corresponds to category.
// The value must match one of the DIR_* constants defined in
// bpf/file_monitor.bpf.c; any unrecognised value is counted as Other.
func (dc *DirCounts) Add(category uint8) {
	switch category {
	case dirRoot:
		dc.Root++
	case dirTemp:
		dc.Temp++
	case dirHome:
		dc.Home++
	case dirUserLib:
		dc.UserLib++
	case dirSys:
		dc.Sys++
	case dirEtc:
		dc.Etc++
	case dirSSHAWSWallet:
		dc.SshAwsWallet++
	default: // dirOther (0) and any future/unknown value
		dc.Other++
	}
}

// ToMap returns a map keyed by QUT-DV25 feature names.
//
// SSH/AWS/Wallet paths live inside the home directory tree, so their count is
// folded into "home_dir_access".  They are also emitted as the separate key
// "ssh_aws_wallet_access" so that downstream alerting logic can flag
// credential-file access without reprocessing the raw events.
func (dc *DirCounts) ToMap() map[string]int {
	return map[string]int{
		"root_dir_access":       dc.Root,
		"temp_dir_access":       dc.Temp,
		"home_dir_access":       dc.Home + dc.SshAwsWallet,
		"user_dir_access":       dc.UserLib,
		"sys_dir_access":        dc.Sys,
		"etc_dir_access":        dc.Etc,
		"other_dir_access":      dc.Other,
		"ssh_aws_wallet_access": dc.SshAwsWallet,
	}
}
