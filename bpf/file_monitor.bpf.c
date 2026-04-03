// SPDX-License-Identifier: GPL-2.0
// file_monitor.bpf.c — track openat() calls to sensitive directories
//                       by npm/node PIDs in the tracked_pids map.
//
// Tracepoints:
//   syscalls/sys_enter_openat  — capture filename + classify dir → pending_opens
//   syscalls/sys_exit_openat   — read retval, emit file_events ring-buffer event
//
// Maps:
//   file_events    BPF_MAP_TYPE_RINGBUF   — events sent to userspace
//   tracked_pids   BPF_MAP_TYPE_HASH      — shared with process_tracer
//   pending_opens  BPF_MAP_TYPE_HASH      — transient per-syscall state

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ── constants ───────────────────────────────────────────────────── */
#define FILENAME_LEN    256

/* ── dir_category values (u8 enum-style) ─────────────────────────── *
 *  0 = OTHER     nothing special (also used for /.ssh, .aws, etc.)   *
 *  1 = ROOT      /root/                                               *
 *  2 = TEMP      /tmp/  /var/tmp/                                     *
 *  3 = HOME      /home/                                               *
 *  4 = USER_LIB  /usr/lib/  /usr/local/                              *
 *  5 = SYS       /sys/  /proc/  /dev/                                *
 *  6 = ETC       /etc/                                               */
#define DIR_OTHER    0
#define DIR_ROOT     1
#define DIR_TEMP     2
#define DIR_HOME     3
#define DIR_USER_LIB 4
#define DIR_SYS      5
#define DIR_ETC      6

/* ── pending_open: transient state stored between enter and exit ──── */
struct pending_open {
    __u32 pid;
    __u8  dir_category;
    __u8  pad[3];
};

/* ── event structure shared with userspace ────────────────────────── *
 * C layout:
 *   __u32 pid            offset   0
 *   char  filename[256]  offset   4
 *   __u8  dir_category   offset 260
 *   __u8  open_success   offset 261
 *   __u8  pad[2]         offset 262   (explicit, keeps flags at 264)
 *   __u32 flags          offset 264
 *   __u64 timestamp_ns   offset 272
 *   total sizeof          == 280 bytes                               */
struct file_event {
    __u32 pid;
    char  filename[FILENAME_LEN];
    __u8  dir_category;
    __u8  open_success;
    __u8  pad[2];
    __u32 flags;
    __u64 timestamp_ns;
};

/* ── ring-buffer map for file events ─────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   /* 256 KB */
} file_events SEC(".maps");

/* ── tracked_pids: identical definition to process_tracer.bpf.c ──── *
 * At load time userspace replaces this with the already-loaded map FD
 * from the ProcessTracer collection (MapReplacements).                */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        /* pid  */
    __type(value, __u32);      /* ppid */
    __uint(max_entries, 4096);
} tracked_pids SEC(".maps");

/* ── pending_opens: keyed by pid_tgid (u64) ──────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct pending_open);
    __uint(max_entries, 4096);
} pending_opens SEC(".maps");

/* ── helpers ─────────────────────────────────────────────────────── */
static __always_inline bool is_tracked(__u32 pid)
{
    return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

/* ── fast substring search (used for sensitive patterns) ──────────── */
static __always_inline int contains_pattern(const char *buf, int len, const char *pat)
{
    int pat_len = 0;
    for (int i = 0; i < 8; i++) {
        if (pat[i] == '\0') {
            pat_len = i;
            break;
        }
    }

    if (len < pat_len || pat_len == 0)
        return 0;

    int bound = len < 256 ? len - pat_len : 248;
    for (int i = 0; i < bound && i < 256; i++) {
        int match = 1;
        for (int j = 0; j < pat_len && j < 8; j++) {
            if (buf[i + j] != pat[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

/* ── classify_dir ─────────────────────────────────────────────────── *
 * Note: .ssh / .aws / wallet / keystore / .env are intentionally NOT  *
 * given a special category here — they fall through to DIR_OTHER (0)  *
 * to match the QUT-DV25 36-feature schema exactly.                    */
static __always_inline __u8 classify_dir(const char *path, int path_len)
{
    /* Check prefixes using first-byte comparisons */
    if (path_len >= 5) {
        char first5[5];
        bpf_probe_read_kernel(first5, 5, path);

        if (first5[0] == '/' && first5[1] == 'r' && first5[2] == 'o' &&
            first5[3] == 'o' && first5[4] == 't')
            return DIR_ROOT;

        if (first5[0] == '/' && first5[1] == 't' && first5[2] == 'm' &&
            first5[3] == 'p' && first5[4] == '/')
            return DIR_TEMP;

        if (first5[0] == '/' && first5[1] == 'e' && first5[2] == 't' &&
            first5[3] == 'c' && first5[4] == '/')
            return DIR_ETC;

        if (first5[0] == '/' && first5[1] == 's' && first5[2] == 'y' &&
            first5[3] == 's' && first5[4] == '/')
            return DIR_SYS;

        if (first5[0] == '/' && first5[1] == 'd' && first5[2] == 'e' &&
            first5[3] == 'v' && first5[4] == '/')
            return DIR_SYS;

        if (first5[0] == '/' && first5[1] == 'h' && first5[2] == 'o' &&
            first5[3] == 'm' && first5[4] == 'e')
            return DIR_HOME;
    }

    if (path_len >= 9) {
        char first9[9];
        bpf_probe_read_kernel(first9, 9, path);

        if (first9[0] == '/' && first9[1] == 'v' && first9[2] == 'a' &&
            first9[3] == 'r' && first9[4] == '/' && first9[5] == 't' &&
            first9[6] == 'm' && first9[7] == 'p' && first9[8] == '/')
            return DIR_TEMP;

        if (first9[0] == '/' && first9[1] == 'u' && first9[2] == 's' &&
            first9[3] == 'r' && first9[4] == '/' && first9[5] == 'l' &&
            first9[6] == 'i' && first9[7] == 'b' && first9[8] == '/')
            return DIR_USER_LIB;
    }

    if (path_len >= 11) {
        char first11[11];
        bpf_probe_read_kernel(first11, 11, path);

        if (first11[0] == '/' && first11[1] == 'u' && first11[2] == 's' &&
            first11[3] == 'r' && first11[4] == '/' && first11[5] == 'l' &&
            first11[6] == 'o' && first11[7] == 'c' && first11[8] == 'a' &&
            first11[9] == 'l' && first11[10] == '/')
            return DIR_USER_LIB;
    }

    if (path_len >= 6) {
        char first6[6];
        bpf_probe_read_kernel(first6, 6, path);

        if (first6[0] == '/' && first6[1] == 'p' && first6[2] == 'r' &&
            first6[3] == 'o' && first6[4] == 'c' && first6[5] == '/')
            return DIR_SYS;
    }

    return DIR_OTHER;
}

/* ── tracepoint: sys_enter_openat ────────────────────────────────── *
 * Capture filename + classify → store in pending_opens.              *
 * Do NOT emit a ring-buffer event here; we wait for the exit probe   *
 * so we know whether the open succeeded.                             */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    if (!is_tracked(tgid))
        return 0;

    /* Read filename into a temporary stack buffer for classification. */
    char fname[FILENAME_LEN];
    const char *fname_ptr = (const char *)ctx->args[1];
    int len = bpf_probe_read_user_str(fname, sizeof(fname), fname_ptr);
    if (len < 0)
        len = 0;

    struct pending_open po = {};
    po.pid          = tgid;
    po.dir_category = classify_dir(fname, len);

    bpf_map_update_elem(&pending_opens, &pid_tgid, &po, BPF_ANY);
    return 0;
}

/* ── tracepoint: sys_exit_openat ─────────────────────────────────── *
 * Look up pending_opens, emit a ring-buffer event with             *
 *   open_success = (ctx->ret >= 0) ? 1 : 0                         *
 * then delete the transient entry.                                  */
SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct pending_open *po = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
    if (!po)
        return 0;

    /* Reserve ring-buffer slot. */
    struct file_event *evt;
    evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&pending_opens, &pid_tgid);
        return 0;
    }

    evt->pid          = po->pid;
    evt->dir_category = po->dir_category;
    evt->open_success = (ctx->ret >= 0) ? 1 : 0;
    evt->pad[0]       = 0;
    evt->pad[1]       = 0;
    evt->timestamp_ns = bpf_ktime_get_ns();

    /* We don't have the filename here, so zero it out.  The consumer
     * can correlate with pid + timestamp if needed. */
    __builtin_memset(evt->filename, 0, sizeof(evt->filename));
    evt->flags = 0;

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&pending_opens, &pid_tgid);
    return 0;
}

char _license[] SEC("license") = "GPL";
