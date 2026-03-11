// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO: TCP connection monitoring program
SEC("tp/tcp/tcp_connect")
int tcp_connect(void *ctx) {
return 0;
}
