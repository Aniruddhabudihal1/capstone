// Package features provides higher-level analysis on top of raw eBPF events.
package features

// SyscallCategory classifies a Linux syscall into a functional group.
type SyscallCategory string

const (
	CategoryIO       SyscallCategory = "IO"
	CategoryFile     SyscallCategory = "FILE"
	CategoryNetwork  SyscallCategory = "NETWORK"
	CategoryTime     SyscallCategory = "TIME"
	CategorySecurity SyscallCategory = "SECURITY"
	CategoryProcess  SyscallCategory = "PROCESS"
	CategoryUnknown  SyscallCategory = "UNKNOWN"
)

// SyscallCategories maps Linux x86-64 syscall numbers to their category.
// Reference: /usr/include/asm/unistd_64.h  (or `ausyscall --dump`).
var SyscallCategories = map[uint32]SyscallCategory{
	// ── IO ────────────────────────────────────────────────────────────────
	0:  CategoryIO, // read
	1:  CategoryIO, // write
	7:  CategoryIO, // poll
	16: CategoryIO, // ioctl
	17: CategoryIO, // pread64
	18: CategoryIO, // pwrite64
	19: CategoryIO, // readv
	20: CategoryIO, // writev
	23: CategoryIO, // select

	// ── FILE ─────────────────────────────────────────────────────────────
	2:   CategoryFile, // open
	3:   CategoryFile, // close
	4:   CategoryFile, // stat
	5:   CategoryFile, // fstat
	6:   CategoryFile, // lstat
	8:   CategoryFile, // lseek
	21:  CategoryFile, // access
	257: CategoryFile, // openat
	262: CategoryFile, // newfstatat

	// ── NETWORK ──────────────────────────────────────────────────────────
	41: CategoryNetwork, // socket
	42: CategoryNetwork, // connect
	43: CategoryNetwork, // accept
	44: CategoryNetwork, // sendto
	45: CategoryNetwork, // recvfrom
	49: CategoryNetwork, // bind
	50: CategoryNetwork, // listen

	// ── TIME ─────────────────────────────────────────────────────────────
	35:  CategoryTime, // nanosleep
	222: CategoryTime, // timer_create
	226: CategoryTime, // timer_delete
	228: CategoryTime, // clock_gettime

	// ── SECURITY ─────────────────────────────────────────────────────────
	102: CategorySecurity, // getuid
	104: CategorySecurity, // getgid
	105: CategorySecurity, // setuid
	106: CategorySecurity, // setgid
	107: CategorySecurity, // geteuid
	108: CategorySecurity, // getegid

	// ── PROCESS ──────────────────────────────────────────────────────────
	56: CategoryProcess, // clone
	57: CategoryProcess, // fork
	58: CategoryProcess, // vfork
	59: CategoryProcess, // execve
	61: CategoryProcess, // wait4
	62: CategoryProcess, // kill
}

// Categorise returns the SyscallCategory for the given x86-64 syscall number.
// If the syscall is not in the known map, CategoryUnknown is returned.
func Categorise(syscallID uint32) SyscallCategory {
	if cat, ok := SyscallCategories[syscallID]; ok {
		return cat
	}
	return CategoryUnknown
}
