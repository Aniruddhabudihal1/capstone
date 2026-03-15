// test_tcp_direct.go — minimal test for TCP collector
// Usage: sudo go run test_tcp_direct.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("TCP Collector Test — checking if tracepoint fires")

	// Check root
	if os.Geteuid() != 0 {
		log.Fatal("ERROR: Must run as root (use sudo)")
	}

	// 1. Start process collector (owns tracked_pids)
	pc, err := collector.NewProcessCollector()
	if err != nil {
		log.Fatalf("NewProcessCollector: %v", err)
	}
	defer pc.Close()

	// 2. Start TCP collector
	tc, err := collector.NewTcpCollector(pc.TrackedPidsMap())
	if err != nil {
		log.Fatalf("NewTcpCollector: %v", err)
	}
	defer tc.Close()
	log.Println("✓ TCP collector loaded successfully")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go pc.Run(ctx)
	go tc.Run(ctx)

	log.Println("BPF programs loaded and attached")
	log.Printf("My PID: %d\n", os.Getpid())

	// Verify the tcp_events map exists
	if tc.TcpEventsMap() == nil {
		log.Fatalf("ERROR: tcp_events map is nil!")
	}
	log.Println("✓ tcp_events ring buffer map verified")

	// Manually add ourselves to tracked_pids so our TCP connections are monitored
	myPid := uint32(os.Getpid())
	if err := pc.TrackedPidsMap().Put(&myPid, &myPid); err != nil {
		log.Fatalf("Failed to add self to tracked_pids: %v", err)
	}
	log.Println("Added self to tracked_pids map")

	// Verify it was added
	value, err := pc.TrackedPidsMap().LookupBytes(&myPid)
	if err != nil {
		log.Fatalf("Failed to verify tracked_pids entry: %v", err)
	}
	if value == nil {
		log.Fatalf("PID not found in tracked_pids after adding!")
	}
	log.Println("✓ Verified PID is in tracked_pids map")

	// Check sock_to_pid map
	if tc.SockToPidMap() == nil {
		log.Fatalf("ERROR: sock_to_pid map is nil!")
	}
	log.Println("✓ sock_to_pid map verified")

	// Start TCP event counter
	tcpCount := 0
	go func() {
		for {
			select {
			case evt := <-tc.Events:
				tcpCount++
				saddr := fmt.Sprintf("%d.%d.%d.%d", byte(evt.Saddr), byte(evt.Saddr>>8), byte(evt.Saddr>>16), byte(evt.Saddr>>24))
				daddr := fmt.Sprintf("%d.%d.%d.%d", byte(evt.Daddr), byte(evt.Daddr>>8), byte(evt.Daddr>>16), byte(evt.Daddr>>24))
				log.Printf("[TCP EVENT #%d] PID=%d %s:%d → %s:%d  state %d → %d",
					tcpCount, evt.Pid, saddr, evt.Sport, daddr, evt.Dport, evt.OldState, evt.NewState)
			case <-ctx.Done():
				log.Printf("Event reader goroutine exiting (captured %d events so far)", tcpCount)
				return
			}
		}
	}()

	// Wait a moment for BPF to stabilize
	log.Println("Waiting 2 seconds for BPF programs to stabilize...")
	time.Sleep(2 * time.Second)

	// Make HTTP request to trigger TCP connection
	log.Println("Making HTTP request to example.com...")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		log.Printf("HTTP request failed: %v", err)
	} else {
		log.Printf("HTTP response: %d", resp.StatusCode)
		resp.Body.Close()
	}

	// Wait for events to arrive
	log.Println("Waiting 5 seconds for TCP events to arrive...")
	time.Sleep(5 * time.Second)
	log.Printf("Event count so far: %d", tcpCount)

	log.Printf("\n=== RESULT ===")
	log.Printf("TCP events captured: %d", tcpCount)
	if tcpCount > 0 {
		log.Printf("✅ PASS — TCP monitoring is working!")
		os.Exit(0)
	} else {
		log.Printf("❌ FAIL — No TCP events captured")
		log.Printf("Possible issues:")
		log.Printf("  1. Tracepoint not firing")
		log.Printf("  2. PID filtering not working")
		log.Printf("  3. Kernel version incompatibility")
		os.Exit(1)
	}
}
