// Package main implements a CSV exporter for npm-ebpf-monitor session records.
//
// Usage:
//
//	go run ./cmd/dataset/exporter --dir ./sessions/dataset/ --out ./sessions/sessions.csv
//
// It reads every JSON file in --dir, unmarshals each into a SessionRecord,
// calls ToCSVRow() for the 39-column feature vector, and writes the result to
// the CSV file specified by --out.  A header row is written first.
//
// Exit codes:
//
//	0  success
//	1  flag / I-O error
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
)

// csvHeader lists the 39 column names in the same order as ToCSVRow().
// Layout: 2 metadata + 36 QUT-DV25 features + 1 trailing metadata.
var csvHeader = []string{
	// metadata
	"package_name",
	"label",
	// filetop (5)
	"read_processes",
	"write_processes",
	"read_data_transfer_kb",
	"write_data_transfer_kb",
	"file_access_processes",
	// install (3)
	"total_dependencies",
	"direct_dependencies",
	"indirect_dependencies",
	// opensnoop / dir counts (7)
	"root_dir_access",
	"temp_dir_access",
	"home_dir_access",
	"user_dir_access",
	"sys_dir_access",
	"etc_dir_access",
	"other_dir_access",
	// tcp (5)
	"state_transitions",
	"local_ips",
	"remote_ips",
	"local_ports",
	"remote_ports",
	// syscalls (6)
	"io_ops",
	"file_ops",
	"network_ops",
	"time_ops",
	"security_ops",
	"process_ops",
	// patterns (10)
	"p1_file_metadata",
	"p2_read_data",
	"p3_write_data",
	"p4_socket_create",
	"p5_process_create",
	"p6_memory_map",
	"p7_fd_manage",
	"p8_ipc",
	"p9_file_lock",
	"p10_error_handle",
	// severity metadata
	"severity_score",
}

func main() {
	dir := flag.String("dir", "", "Path to the sessions directory containing JSON files (required)")
	out := flag.String("out", "sessions.csv", "Output CSV file path")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required")
		flag.Usage()
		os.Exit(1)
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		log.Fatalf("cannot read directory %q: %v", *dir, err)
	}

	// Create (or truncate) the output CSV file.
	outFile, err := os.Create(*out)
	if err != nil {
		log.Fatalf("cannot create output file %q: %v", *out, err)
	}
	defer outFile.Close()

	w := csv.NewWriter(outFile)

	// Write header row.
	if err := w.Write(csvHeader); err != nil {
		log.Fatalf("cannot write CSV header: %v", err)
	}

	var rows int

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(*dir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("SKIP %s: read error: %v", entry.Name(), err)
			continue
		}

		var record output.SessionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			log.Printf("SKIP %s: unmarshal error: %v", entry.Name(), err)
			continue
		}

		if err := w.Write(record.ToCSVRow()); err != nil {
			log.Printf("SKIP %s: csv write error: %v", entry.Name(), err)
			continue
		}

		rows++
	}

	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatalf("csv flush error: %v", err)
	}

	fmt.Printf("Wrote %d rows to %s.\n", rows, *out)
}
