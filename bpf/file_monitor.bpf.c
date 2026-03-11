// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: File I/O monitoring program
SEC("tp/syscalls/sys_enter_openat")
int file_open(void *ctx) {
return 0;
}
