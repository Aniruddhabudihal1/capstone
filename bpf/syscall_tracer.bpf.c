// SPDX-License-Identifier: GPL-2.0
// syscall_tracer.bpf.c — capture every syscall made by tracked npm/node PIDs
//
// This program attaches to raw_syscalls/sys_enter (a single tracepoint that
// fires for *every* syscall) and emits a lightweight {pid, syscall_id, ts}
// event for each call made by a PID in the tracked_pids map.
//
// Map sharing with process_tracer.bpf.c:
// ────────────────────────────────────────
// We declare tracked_pids with the SAME definition as in process_tracer.bpf.c.
// At load time the Go userspace code uses ebpf.CollectionOptions.MapReplacements
// to replace this program's tracked_pids with the already-loaded map FD from
// the ProcessTracer collection.  The kernel sees one shared hash map.
//
// Why NOT `extern`?
//   libbpf's skeleton loader supports `extern struct { … } tracked_pids`
//   which causes two ELF objects to be linked against the same map.
//   However, cilium/ebpf's bpf2go generates *separate* CollectionSpecs
//   per .bpf.c file, so there is no ELF-level linking.  The idiomatic
//   approach with bpf2go is:
//     1. Define the map identically in both .bpf.c files.
//     2. Load the first collection (ProcessTracer).
//     3. Before loading the second collection (SyscallTracer), set
//        opts.MapReplacements["tracked_pids"] = processTracerObjs.TrackedPids
//   This makes both programs reference the same kernel map object.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ── Syscall IDs to suppress (reduces noise significantly) ───────── */
#define SYSCALL_NANOSLEEP  35   /* __NR_nanosleep  (x86-64) */
#define SYSCALL_PKEY_ALLOC 330  /* __NR_pkey_alloc (x86-64) */

/* ── event structure shared with userspace ────────────────────────── */
struct syscall_event {
    __u32 pid;
    __u32 syscall_id;
    __u64 timestamp_ns;
};

/* ── ring-buffer map for syscall events ──────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);   /* 1 MB — syscalls are very frequent */
} syscall_events SEC(".maps");

/* ── tracked_pids: identical definition to process_tracer.bpf.c ──── *
 * At load time userspace replaces this with the already-loaded map FD
 * from the ProcessTracer collection (MapReplacements).                */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        /* pid  */
    __type(value, __u32);      /* ppid */
    __uint(max_entries, 4096);
} tracked_pids SEC(".maps");

/* ── helper ──────────────────────────────────────────────────────── */
static __always_inline bool is_tracked(__u32 pid)
{
    return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

/* ── tracepoint: raw_syscalls/sys_enter ──────────────────────────── *
 *
 * Context (from /sys/kernel/tracing/events/raw_syscalls/sys_enter/format):
 *   field: long id;             offset: 8   (syscall number)
 *   field: unsigned long args[6]; offset: 16 (syscall arguments)
 *
 * We use trace_event_raw_sys_enter from vmlinux.h which already has:
 *   long int id;
 *   unsigned long args[6];
 */
SEC("tp/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* ── fast path: bail if this PID is not tracked ──────────── */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);   /* userspace PID */

    if (!is_tracked(tgid))
        return 0;

    /* ── filter out noisy syscalls ───────────────────────────── */
    long syscall_id = ctx->id;

    if (syscall_id == SYSCALL_NANOSLEEP || syscall_id == SYSCALL_PKEY_ALLOC)
        return 0;

    /* ── emit event via ring buffer ──────────────────────────── */
    struct syscall_event *evt;
    evt = bpf_ringbuf_reserve(&syscall_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid          = tgid;
    evt->syscall_id   = (__u32)syscall_id;
    evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
