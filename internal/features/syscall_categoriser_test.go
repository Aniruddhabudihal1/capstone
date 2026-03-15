package features

import "testing"

func TestCategorise_KnownSyscalls(t *testing.T) {
	tests := []struct {
		name      string
		syscallID uint32
		want      SyscallCategory
	}{
		// FILE
		{name: "openat(257) → FILE", syscallID: 257, want: CategoryFile},
		{name: "open(2) → FILE", syscallID: 2, want: CategoryFile},
		{name: "close(3) → FILE", syscallID: 3, want: CategoryFile},
		{name: "stat(4) → FILE", syscallID: 4, want: CategoryFile},
		{name: "newfstatat(262) → FILE", syscallID: 262, want: CategoryFile},

		// NETWORK
		{name: "socket(41) → NETWORK", syscallID: 41, want: CategoryNetwork},
		{name: "connect(42) → NETWORK", syscallID: 42, want: CategoryNetwork},
		{name: "accept(43) → NETWORK", syscallID: 43, want: CategoryNetwork},
		{name: "bind(49) → NETWORK", syscallID: 49, want: CategoryNetwork},
		{name: "listen(50) → NETWORK", syscallID: 50, want: CategoryNetwork},

		// IO
		{name: "read(0) → IO", syscallID: 0, want: CategoryIO},
		{name: "write(1) → IO", syscallID: 1, want: CategoryIO},
		{name: "ioctl(16) → IO", syscallID: 16, want: CategoryIO},

		// TIME
		{name: "nanosleep(35) → TIME", syscallID: 35, want: CategoryTime},
		{name: "clock_gettime(228) → TIME", syscallID: 228, want: CategoryTime},

		// SECURITY
		{name: "getuid(102) → SECURITY", syscallID: 102, want: CategorySecurity},
		{name: "setuid(105) → SECURITY", syscallID: 105, want: CategorySecurity},

		// PROCESS
		{name: "clone(56) → PROCESS", syscallID: 56, want: CategoryProcess},
		{name: "execve(59) → PROCESS", syscallID: 59, want: CategoryProcess},
		{name: "kill(62) → PROCESS", syscallID: 62, want: CategoryProcess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Categorise(tt.syscallID)
			if got != tt.want {
				t.Errorf("Categorise(%d) = %q, want %q", tt.syscallID, got, tt.want)
			}
		})
	}
}

func TestCategorise_UnknownSyscall(t *testing.T) {
	// 9999 is not mapped to any category.
	got := Categorise(9999)
	if got != CategoryUnknown {
		t.Errorf("Categorise(9999) = %q, want %q", got, CategoryUnknown)
	}
}
