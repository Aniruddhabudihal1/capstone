// SPDX-License-Identifier: GPL-2.0
// tcp_monitor.bpf.c — trace TCP state transitions for npm/node PIDs
//
// Tracepoint: sock/inet_sock_set_state
// Events:     tcp_events ring buffer → struct tcp_event
//
// WHY tracepoint/sock/inet_sock_set_state instead of kprobing tcp_set_state?
// ──────────────────────────────────────────────────────────────────────────
// 1. STABILITY: kprobes attach to a symbol's raw address.  tcp_set_state is
//    an inline function in many kernel builds, meaning it has no stable symbol.
//    The tracepoint is an ABI-stable hook with a guaranteed stable format that
//    the kernel authors commit never to break.
//
// 2. CONTEXT: The tracepoint fires *after* the state has been committed to the
//    socket, so oldstate and newstate are always consistent.  A kprobe on the
//    function entry would fire before the new state is written.
//
// 3. RICHNESS: The tracepoint context already contains pre-computed fields
//    (family, protocol, sport, dport, saddr, daddr) that the kernel populates
//    for every event.  A kprobe would require CO-RE reads through the entire
//    inet_sock hierarchy to retrieve the same data.
//
// 4. CORRECTNESS: The tracepoint fires for *every* inet socket state change —
//    regardless of kernel version, compiler optimisations, or inlining.
//    Kprobing an inlined helper would silently miss state transitions.
//
// Two-phase PID attribution
// ─────────────────────────
// TCP state transitions do NOT always fire in the context of the application
// that owns the socket:
//
//   • SYN_SENT   — fires in process context when connect(2) is called.
//                  bpf_get_current_pid_tgid() returns the npm/node PID. ✓
//   • ESTABLISHED— fires in softirq context when the SYN-ACK arrives from the
//                  network stack.  bpf_get_current_pid_tgid() returns whichever
//                  unrelated process happens to be scheduled on that CPU. ✗
//   • CLOSE_WAIT — fires in softirq context when the remote FIN arrives. ✗
//   • TIME_WAIT  — fires in softirq context. ✗
//   • CLOSE      — may fire in either context. ±
//
// To bridge these two contexts we maintain a sock_to_pid hash map:
//   Phase 1 (process context): when the current TGID is in tracked_pids, store
//           skaddr → tgid in sock_to_pid.  This captures SYN_SENT (connect).
//   Phase 2 (any context):     look up skaddr in sock_to_pid.  If found, emit
//           the event with the stored PID.  This captures ESTABLISHED and all
//           subsequent transitions on the same socket.
//   Cleanup: delete the sock_to_pid entry when newstate == TCP_CLOSE so that
//           the 4 096-entry map never fills up.
//
// Map sharing
// ───────────
// tracked_pids is replaced at load time with the ProcessTracer's already-loaded
// map FD (MapReplacements in Go), exactly as syscall_tracer.bpf.c and
// file_monitor.bpf.c do.  The kernel sees a single shared hash map.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* ── well-known constants (not always visible without linux/socket.h) ─ */
#define AF_INET     2
#define IPPROTO_TCP 6

/* ── event structure shared with userspace ────────────────────────────
 *
 * Layout is explicit and padded so that Go's binary.Read (LittleEndian)
 * sees the same offsets as the C compiler:
 *
 *   offset  0  __u32 pid             4 B
 *   offset  4  __u32 saddr           4 B  (network byte order)
 *   offset  8  __u32 daddr           4 B  (network byte order)
 *   offset 12  __u16 sport           2 B  (host byte order)
 *   offset 14  __u16 dport           2 B  (host byte order)
 *   offset 16  __u8  old_state       1 B
 *   offset 17  __u8  new_state       1 B
 *   offset 18  __u8  _pad[6]         6 B  (explicit pad → align timestamp)
 *   offset 24  __u64 timestamp_ns    8 B
 *                                  ──────
 *   total                           32 B
 */
struct tcp_event {
	__u32 pid;
	__u32 saddr;       /* source IPv4 in network byte order */
	__u32 daddr;       /* dest   IPv4 in network byte order */
	__u16 sport;       /* source port in host byte order    */
	__u16 dport;       /* dest   port in host byte order    */
	__u8  old_state;
	__u8  new_state;
	__u8  _pad[6];     /* explicit padding — keeps timestamp 8-byte aligned */
	__u64 timestamp_ns;
};

/* ── tcp_events: ring buffer → userspace ──────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);   /* 256 KB */
} tcp_events SEC(".maps");

/* ── tracked_pids: shared with process_tracer via MapReplacements ─── *
 * key:   __u32 tgid (userspace PID)                                    *
 * value: __u32 ppid                                                    */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   __u32);
	__type(value, __u32);
	__uint(max_entries, 4096);
} tracked_pids SEC(".maps");

/* ── sock_to_pid: bridges process context and softirq context ─────── *
 * key:   __u64 skaddr  (kernel sock* cast to u64 — unique per socket)  *
 * value: __u32 pid     (the npm/node TGID that owns the socket)        *
 *                                                                       *
 * Populated during SYN_SENT (connect, process context).                *
 * Consulted during ESTABLISHED / CLOSE_WAIT / etc. (softirq context).  *
 * Entry deleted on TCP_CLOSE to keep the map from filling up.          */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   __u64);
	__type(value, __u32);
	__uint(max_entries, 4096);
} sock_to_pid SEC(".maps");

/* ── helper ──────────────────────────────────────────────────────── */
static __always_inline bool is_tracked(__u32 pid)
{
	return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

/* ══ tracepoint: sock/inet_sock_set_state ════════════════════════════
 *
 * Context struct fields used (from vmlinux.h →
 *   trace_event_raw_inet_sock_set_state):
 *
 *   const void *skaddr   — pointer to struct sock (unique socket ID)
 *   int         oldstate — previous TCP_* state
 *   int         newstate — new      TCP_* state
 *   __u16       sport    — source port, already host byte order
 *   __u16       dport    — dest   port, already host byte order
 *   __u16       family   — AF_INET / AF_INET6
 *   __u16       protocol — IPPROTO_TCP / …
 *   __u8        saddr[4] — source IPv4 (network byte order)
 *   __u8        daddr[4] — dest   IPv4 (network byte order)
 *
 * Note: sport/dport in the tracepoint context are already converted to
 * host byte order by the kernel (it calls ntohs before storing them in
 * the trace record).  The saddr/daddr bytes are in network order.
 *
 * We still use BPF_CORE_READ to satisfy the CO-RE requirement, reading
 * saddr/daddr/sport/dport from the sock struct directly.  skc_num is
 * the source port in host byte order; skc_dport is dest port in network
 * byte order and requires bpf_ntohs().
 */
SEC("tp/sock/inet_sock_set_state")
int tracepoint__sock__inet_sock_set_state(
	struct trace_event_raw_inet_sock_set_state *ctx)
{
	/* ── guard: IPv4 TCP only ─────────────────────────────────── */
	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return 0;

	__u64 skaddr = (__u64)(uintptr_t)ctx->skaddr;
	__u32 pid    = 0;

	/* ── Phase 1: process-context attribution ────────────────────
	 *
	 * When connect(2) fires, inet_sock_set_state transitions the
	 * socket to TCP_SYN_SENT in process context.  At this exact
	 * moment bpf_get_current_pid_tgid() returns the npm/node PID.
	 *
	 * If that PID is tracked, register skaddr → tgid in sock_to_pid
	 * so that every subsequent softirq-context transition on this
	 * socket can be attributed to the same process.
	 */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid     = (__u32)(pid_tgid >> 32);

	if (tgid > 0 && is_tracked(tgid)) {
		/*
		 * BPF_ANY: overwrite any stale entry for a recycled skaddr.
		 * This is safe because the kernel reuses struct sock memory
		 * only after the socket is fully freed (after TCP_CLOSE).
		 */
		bpf_map_update_elem(&sock_to_pid, &skaddr, &tgid, BPF_ANY);
		pid = tgid;
	}

	/* ── Phase 2: sock_to_pid fallback for softirq context ───────
	 *
	 * For ESTABLISHED (SYN-ACK received), CLOSE_WAIT (FIN received),
	 * TIME_WAIT, and similar transitions the CPU is running arbitrary
	 * code — not the npm process.  bpf_get_current_pid_tgid() would
	 * return the wrong PID.  Look up the socket in sock_to_pid
	 * instead.  If we have no entry for this socket it was never
	 * opened by a tracked process — skip it.
	 */
	if (pid == 0) {
		__u32 *stored = bpf_map_lookup_elem(&sock_to_pid, &skaddr);
		if (!stored) {
			/* Not from a tracked process; still clean up on CLOSE. */
			if (ctx->newstate == TCP_CLOSE)
				bpf_map_delete_elem(&sock_to_pid, &skaddr);
			return 0;
		}
		pid = *stored;
	}

	/* ── reserve ring-buffer slot ────────────────────────────────
	 *
	 * bpf_ringbuf_reserve acquires a reference counted slot.  We
	 * must not call any helper that manipulates reference objects
	 * (e.g. map updates) while the slot is outstanding.  Submit or
	 * discard it first, then do the sock_to_pid cleanup.
	 */
	struct tcp_event *evt =
		bpf_ringbuf_reserve(&tcp_events, sizeof(*evt), 0);
	if (!evt) {
		/* ring buffer full — still clean up on CLOSE */
		if (ctx->newstate == TCP_CLOSE)
			bpf_map_delete_elem(&sock_to_pid, &skaddr);
		return 0;
	}

	/* ── fill the event ──────────────────────────────────────────  */
	evt->pid       = pid;
	evt->old_state = (__u8)ctx->oldstate;
	evt->new_state = (__u8)ctx->newstate;
	evt->timestamp_ns = bpf_ktime_get_ns();

	/* ── CO-RE reads from the sock struct ───────────────────────
	 *
	 * ctx->skaddr is the kernel's struct sock pointer for the socket
	 * undergoing the state transition.  We cast it and use
	 * BPF_CORE_READ to let libbpf resolve field offsets at load time
	 * via BTF, making the program portable across kernel versions.
	 *
	 *   skc_rcv_saddr — __be32 source IPv4  (network byte order)
	 *   skc_daddr     — __be32 dest   IPv4  (network byte order)
	 *   skc_num       — __u16  source port  (host byte order)
	 *   skc_dport     — __be16 dest   port  (network byte order → needs ntohs)
	 */
	const struct sock *sk = (const struct sock *)ctx->skaddr;

	evt->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	evt->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	evt->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	evt->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	/* ── submit to userspace — releases the ring-buffer reference ─ */
	bpf_ringbuf_submit(evt, 0);

	/* ── cleanup: evict sock_to_pid entry when socket fully closes ─
	 *
	 * TCP_CLOSE is the terminal state; after this the kernel may free
	 * and recycle the struct sock memory.  Deleting the entry now
	 * prevents stale mappings and keeps the map from filling up.
	 * It is safe to call bpf_map_delete_elem here because the ring-
	 * buffer reference was already released by bpf_ringbuf_submit.
	 */
	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&sock_to_pid, &skaddr);

	return 0;
}

char _license[] SEC("license") = "GPL";