// SPDX-License-Identifier: GPL-2.0
// file_monitor.bpf.c — track openat() calls to sensitive directories
//                       by npm/node PIDs in the tracked_pids map.
//
// Tracepoint: syscalls/sys_enter_openat
// Events:     file_events ring buffer → struct file_event

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ── constants ───────────────────────────────────────────────────── */
#define FILENAME_LEN    256

/* ── dir_category values (u8 enum-style) ─────────────────────────── *
 *  0 = OTHER           nothing special                                *
 *  1 = ROOT            /root/                                         *
 *  2 = TEMP            /tmp/  /var/tmp/                               *
 *  3 = HOME            /home/                                         *
 *  4 = USER_LIB        /usr/lib/  /usr/local/                         *
 *  5 = SYS             /sys/  /proc/  /dev/                           *
 *  6 = ETC             /etc/                                          *
 *  7 = SSH_AWS_WALLET  contains .ssh .aws wallet keystore .env        */
#define DIR_OTHER          0
#define DIR_ROOT           1
#define DIR_TEMP           2
#define DIR_HOME           3
#define DIR_USER_LIB       4
#define DIR_SYS            5
#define DIR_ETC            6
#define DIR_SSH_AWS_WALLET 7

/* ── event structure shared with userspace ────────────────────────── */
struct file_event {
    __u32 pid;
    char  filename[FILENAME_LEN];
    __u8  dir_category;
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

/* ── classify_dir using bpf_strncmp (kernel >= 5.17) ──────────────── */
static __always_inline __u8 classify_dir(const char *path, int path_len)
{
    /* Check sensitive substrings first (highest priority) */
    if (contains_pattern(path, path_len, ".ssh") ||
        contains_pattern(path, path_len, ".aws") ||
        contains_pattern(path, path_len, "wallet") ||
        contains_pattern(path, path_len, "keystore") ||
        contains_pattern(path, path_len, ".env"))
        return DIR_SSH_AWS_WALLET;

    /* Check prefixes using bpf_strncmp where available */
    /* Simple check: look at first few bytes */
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

/* ── tracepoint: sys_enter_openat ────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* ── fast path: bail if this PID is not tracked ──────────── */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);   /* userspace PID */

    if (!is_tracked(tgid))
        return 0;

    /* ── reserve ring-buffer slot ────────────────────────────── */
    struct file_event *evt;
    evt = bpf_ringbuf_reserve(&file_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid          = tgid;
    evt->timestamp_ns = bpf_ktime_get_ns();

    /* ── read filename from user space ───────────────────────── */
    const char *fname_ptr = (const char *)ctx->args[1];
    int len = bpf_probe_read_user_str(evt->filename, sizeof(evt->filename),
                                      fname_ptr);
    if (len < 0) {
        evt->filename[0] = '\0';
        len = 0;
    }

    /* ── capture open flags ──────────────────────────────────── */
    evt->flags = (__u32)ctx->args[2];

    /* ── classify the directory ──────────────────────────────── */
    evt->dir_category = classify_dir(evt->filename, len);

    /* ── submit to userspace ─────────────────────────────────── */
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
