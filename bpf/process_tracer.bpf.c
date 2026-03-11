// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: Process tracking program
SEC("tp/sched/sched_process_fork")
int process_fork(void *ctx) {
return 0;
}
