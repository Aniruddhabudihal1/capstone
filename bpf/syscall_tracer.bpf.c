// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: Syscall tracing program
SEC("tp/raw_syscalls/sys_enter")
int syscall_tracer(void *ctx) {
return 0;
}
