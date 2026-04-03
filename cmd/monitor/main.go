/*
Goroutine / data-flow layout

	   kernel ring buffers
	      |          |           |          |
	      v          v           v          v
	 Process     Syscall      File       TCP
	Collector   Collector   Collector  Collector
	   Run         Run         Run        Run
	      \          |           |         /
	       \         |           |        /
	        +--------+-----------+-------+
	                         |
	                         v
	                router goroutine select
	                         |
	                         v
	                detector session methods
	                         |
	                         v
	                detector.Completed() chan
	                         |
	                         v
	                  output worker goroutine
	                         |
	                         v
	                  output.JSONWriter.Write
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
	"github.com/cilium/ebpf/rlimit"
)

type closer interface {
	Close() error
}

func main() {
	outputDir := flag.String("output-dir", "./sessions", "directory for JSON session outputs")
	verbose := flag.Bool("verbose", false, "enable verbose monitor logging")
	sessionTimeout := flag.Duration("session-timeout", 120*time.Second, "maximum duration for an npm session before it is forcibly completed (0 = disable)")
	dryRun := flag.Bool("dry-run", false, "load all BPF programs, print attachment status, and exit")
	flag.Parse()

	log.SetFlags(log.LstdFlags)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	if *dryRun {
		runDryRun()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	processCollector, err := collector.NewProcessCollector()
	if err != nil {
		log.Fatalf("load ProcessTracer: %v", err)
	}

	syscallCollector, err := collector.NewSyscallCollector(processCollector.TrackedPidsMap())
	if err != nil {
		closeAndLog("process collector", processCollector)
		log.Fatalf("load SyscallTracer: %v", err)
	}

	fileCollector, err := collector.NewFileCollector(processCollector.TrackedPidsMap())
	if err != nil {
		closeAndLog("syscall collector", syscallCollector)
		closeAndLog("process collector", processCollector)
		log.Fatalf("load FileMonitor: %v", err)
	}

	tcpCollector, err := collector.NewTcpCollector(processCollector.TrackedPidsMap())
	if err != nil {
		closeAndLog("file collector", fileCollector)
		closeAndLog("syscall collector", syscallCollector)
		closeAndLog("process collector", processCollector)
		log.Fatalf("load TCPMonitor: %v", err)
	}

	bytesCollector, err := collector.NewBytesCollector(processCollector.TrackedPidsMap())
	if err != nil {
		closeAndLog("tcp collector", tcpCollector)
		closeAndLog("file collector", fileCollector)
		closeAndLog("syscall collector", syscallCollector)
		closeAndLog("process collector", processCollector)
		log.Fatalf("load BytesCollector: %v", err)
	}

	detector := session.NewDetector(*sessionTimeout)
	writer := output.NewJSONWriter(*outputDir)
	detector.SetRootTracker(func(pid, ppid uint32) error {
		return processCollector.TrackedPidsMap().Put(&pid, &ppid)
	})
	if *verbose {
		detector.SetLogger(log.Printf)
	}

	if *verbose {
		log.Printf("loaded process, syscall, file, and TCP collectors")
	}

	router := session.NewRouter(
		detector,
		processCollector.Events,
		syscallCollector.Events,
		fileCollector.Events,
		tcpCollector.Events,
		bytesCollector.Events,
	)

	var wg sync.WaitGroup

	startTrackedGoroutine(&wg, func() { processCollector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { syscallCollector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { fileCollector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { tcpCollector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { bytesCollector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { detector.Run(ctx) })
	startTrackedGoroutine(&wg, func() { router.Run(ctx) })
	startTrackedGoroutine(&wg, func() {
		runOutputWorker(detector, writer, *verbose)
	})

	fmt.Println("npm-ebpf-monitor active. Watching for npm install...")

	<-signalCh
	fmt.Println("Shutting down cleanly...")

	cancel()
	wg.Wait()

	closeAndLog("bytes collector", bytesCollector)
	closeAndLog("tcp collector", tcpCollector)
	closeAndLog("file collector", fileCollector)
	closeAndLog("syscall collector", syscallCollector)
	closeAndLog("process collector", processCollector)
}

// probeResult holds the load outcome for a single BPF probe group.
type probeResult struct {
	name   string
	attach string
	err    error
}

// runDryRun loads each BPF collector, prints its attachment status, then exits.
func runDryRun() {
	var results []probeResult
	allOK := true

	addResult := func(name, attach string, err error) {
		results = append(results, probeResult{name: name, attach: attach, err: err})
		if err != nil {
			allOK = false
		}
	}

	// ProcessTracer — must be loaded first (owns the tracked_pids map).
	processCollector, err := collector.NewProcessCollector()
	addResult("ProcessTracer",
		"tracepoint/syscalls/sys_enter_execve, sched_process_fork, sched_process_exit",
		err)
	if err != nil {
		// Remaining collectors need the tracked_pids map — skip them.
		printDryRunResults(results)
		printKernelInfo()
		exitDryRun(allOK)
	}
	defer closeAndLog("process collector", processCollector)

	syscallCollector, err := collector.NewSyscallCollector(processCollector.TrackedPidsMap())
	addResult("SyscallTracer", "tracepoint/raw_syscalls/sys_enter", err)
	if err == nil {
		defer closeAndLog("syscall collector", syscallCollector)
	}

	fileCollector, err := collector.NewFileCollector(processCollector.TrackedPidsMap())
	addResult("FileMonitor", "tracepoint/syscalls/sys_enter_openat, sys_exit_openat", err)
	if err == nil {
		defer closeAndLog("file collector", fileCollector)
	}

	tcpCollector, err := collector.NewTcpCollector(processCollector.TrackedPidsMap())
	addResult("TCPMonitor", "tracepoint/sock/inet_sock_set_state", err)
	if err == nil {
		defer closeAndLog("tcp collector", tcpCollector)
	}

	bytesCollector, err := collector.NewBytesCollector(processCollector.TrackedPidsMap())
	addResult("BytesCollector", "kprobe/tcp_sendmsg, kretprobe/tcp_recvmsg", err)
	if err == nil {
		defer closeAndLog("bytes collector", bytesCollector)
	}

	printDryRunResults(results)
	printKernelInfo()
	exitDryRun(allOK)
}

func printDryRunResults(results []probeResult) {
	for _, r := range results {
		mark := "✓"
		if r.err != nil {
			mark = "✗"
		}
		fmt.Printf("  %s %-18s → %s\n", mark, r.name, r.attach)
		if r.err != nil {
			fmt.Printf("      error: %v\n", r.err)
		}
	}
}

func printKernelInfo() {
	kernelVersion := "unknown"
	if data, err := os.ReadFile("/proc/version"); err == nil {
		line := strings.TrimSpace(string(data))
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			kernelVersion = strings.Join(fields[:3], " ")
		}
	}

	btfStatus := "not supported"
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		btfStatus = "supported"
	}
	coreStatus := btfStatus // CO-RE requires BTF

	fmt.Printf("  Kernel: %-30s   BTF: %-14s   CO-RE: %s\n",
		kernelVersion, btfStatus, coreStatus)
}

func exitDryRun(allOK bool) {
	if allOK {
		fmt.Println("  All probes loaded successfully.")
		os.Exit(0)
	}
	fmt.Println("  One or more probes failed to load.")
	os.Exit(1)
}

func startTrackedGoroutine(wg *sync.WaitGroup, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
}

func runOutputWorker(detector *session.Detector, writer *output.JSONWriter, verbose bool) {
	for completed := range detector.Completed() {
		installFeatures, err := loadInstallFeatures(completed)
		if err != nil {
			log.Printf("extract install features for session %s: %v", completed.ID, err)
		} else if verbose && completed.Cwd == "" {
			log.Printf("session %s has no cwd; install metadata unavailable", completed.ID)
		}

		record := output.BuildRecord(completed, installFeatures)
		for _, warning := range output.Validate(record) {
			log.Printf("%s", warning)
		}

		path, err := writer.Write(record)
		if err != nil {
			log.Printf("write session %s: %v", completed.ID, err)
			continue
		}

		if verbose {
			log.Printf("wrote session record: %s", path)
		}
	}
}

func loadInstallFeatures(sess *session.Session) (features.InstallFeatures, error) {
	if sess == nil || sess.Cwd == "" {
		return features.InstallFeatures{}, nil
	}

	return features.ExtractInstallFeatures(filepath.Join(sess.Cwd, "package-lock.json"))
}

func closeAndLog(name string, resource closer) {
	if resource == nil {
		return
	}

	if err := resource.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("close %s: %v", name, err)
	}
}
