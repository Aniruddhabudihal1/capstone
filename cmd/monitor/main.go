package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

// TCP state constants (match Linux kernel TCP_* values)
var tcpStateNames = map[uint8]string{
	0:  "UNKNOWN",
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

func main() {
	duration := flag.Duration("duration", 90*time.Second, "how long to trace (e.g. 60s, 2m)")
	flag.Parse()

	log.SetFlags(log.Ltime)
	log.Println("npm-ebpf-monitor starting (requires root)")

	// ── 1. Process tracer — owns the tracked_pids map ───────────────
	pc, err := collector.NewProcessCollector()
	if err != nil {
		log.Fatalf("NewProcessCollector: %v", err)
	}
	defer func() {
		if err := pc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close process collector: %v\n", err)
		}
	}()

	// ── 2. Syscall tracer — shares tracked_pids via MapReplacements ─
	sc, err := collector.NewSyscallCollector(pc.TrackedPidsMap())
	if err != nil {
		log.Fatalf("NewSyscallCollector: %v", err)
	}
	defer func() {
		if err := sc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close syscall collector: %v\n", err)
		}
	}()

	// ── 3. File monitor — shares tracked_pids via MapReplacements ────
	fc, err := collector.NewFileCollector(pc.TrackedPidsMap())
	if err != nil {
		log.Fatalf("NewFileCollector: %v", err)
	}
	defer func() {
		if err := fc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close file collector: %v\n", err)
		}
	}()

	// ── 4. TCP monitor — shares tracked_pids via MapReplacements ─────
	tc, err := collector.NewTcpCollector(pc.TrackedPidsMap())
	if err != nil {
		log.Fatalf("NewTcpCollector: %v", err)
	}
	defer func() {
		if err := tc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close tcp collector: %v\n", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	go pc.Run(ctx)
	go sc.Run(ctx)
	go fc.Run(ctx)
	go tc.Run(ctx)

	log.Printf("Tracing execve + syscalls for %s — run `npm install lodash` now...", *duration)
	fmt.Println()
	fmt.Printf("%-8s %-8s %-16s %s\n", "PID", "PPID", "COMM", "ARGS")
	fmt.Println("-------- -------- ---------------- ----------------------------------------")

	var syscallCount atomic.Int64
	var fileEventCount atomic.Int64
	var tcpEventCount atomic.Int64
	var pidMu sync.Mutex
	pidCounts := make(map[uint32]int64) // pid → syscall count
	pidComms := make(map[uint32]string) // pid → comm (from process events)

	// Drain syscall events in a separate goroutine (high volume).
	go func() {
		for {
			select {
			case evt := <-sc.Events:
				syscallCount.Add(1)
				pidMu.Lock()
				pidCounts[evt.Pid]++
				pidMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Drain file events in a separate goroutine.
	go func() {
		for {
			select {
			case evt := <-fc.Events:
				fileEventCount.Add(1)
				filename := string(bytes.TrimRight(evt.Filename[:], "\x00"))
				catName := collector.DirCategoryName[collector.DirectoryCategory(evt.DirCategory)]
				log.Printf("[FILE] PID=%d path=%s category=%s", evt.Pid, filename, catName)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Drain TCP events in a separate goroutine.
	go func() {
		for {
			select {
			case evt := <-tc.Events:
				tcpEventCount.Add(1)
				// Convert IPv4 addresses from network byte order to dotted-quad notation
				saddr := ipv4ToString(evt.Saddr)
				daddr := ipv4ToString(evt.Daddr)
				oldStateName := tcpStateNames[evt.OldState]
				newStateName := tcpStateNames[evt.NewState]
				log.Printf("[TCP] PID=%-6d %s:%-5d → %s:%-5d  %s → %s",
					evt.Pid, saddr, evt.Sport, daddr, evt.Dport,
					oldStateName, newStateName)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Print process events in the main goroutine.
	for {
		select {
		case evt := <-pc.Events:
			comm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
			args := string(bytes.TrimRight(evt.Args[:], "\x00"))
			npmTag := ""
			if evt.IsNpmRelated == 1 {
				npmTag = "  *** npm/node ***"
				pidMu.Lock()
				if _, seen := pidComms[evt.Pid]; !seen {
					pidComms[evt.Pid] = comm
				}
				pidMu.Unlock()
			}
			fmt.Printf("%-8d %-8d %-16s %s%s\n",
				evt.Pid, evt.Ppid, comm, args, npmTag)
		case <-ctx.Done():
			total := syscallCount.Load()
			fileTotal := fileEventCount.Load()
			tcpTotal := tcpEventCount.Load()
			log.Printf("Done — captured %d syscall events, %d file events, and %d TCP events from tracked PIDs.", total, fileTotal, tcpTotal)

			// Print per-PID breakdown sorted by count descending.
			pidMu.Lock()
			type pidRow struct {
				pid   uint32
				comm  string
				count int64
			}
			var rows []pidRow
			for pid, cnt := range pidCounts {
				comm := pidComms[pid]
				if comm == "" {
					comm = "(unknown)"
				}
				rows = append(rows, pidRow{pid, comm, cnt})
			}
			pidMu.Unlock()
			sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })

			if len(rows) > 0 {
				fmt.Println()
				fmt.Printf("%-8s %-16s %s\n", "PID", "COMM", "SYSCALLS")
				fmt.Println("-------- ---------------- ----------")
				for _, r := range rows {
					fmt.Printf("%-8d %-16s %d\n", r.pid, r.comm, r.count)
				}
				fmt.Println()
			}

			// PASS/FAIL verdict
			if total >= 1000 {
				log.Printf("✅ PASS — %d syscall events (≥1000 threshold met)", total)
			} else {
				log.Printf("❌ FAIL — only %d syscall events captured (want ≥1000)", total)
			}
			return
		}
	}
}

// ipv4ToString converts a uint32 IPv4 address in network byte order to dotted-quad notation.
// Network byte order is big-endian, so byte 0 (LSB) is the first octet.
func ipv4ToString(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24))
}
