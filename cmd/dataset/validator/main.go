// Package main implements a dataset validator for npm-ebpf-monitor session records.
//
// It reads every JSON file in the --dir directory, parses them using the
// internal/output.SessionRecord struct, and checks three dataset-level rules:
//
//  1. No file may have all 36 QUT-DV25 features at zero.
//  2. At least one malicious file must have other_dir_access > 0
//     (confirming the /.ssh probe is captured).
//  3. The median etc_dir_access for benign files must be lower than the
//     median for malicious files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
)

func main() {
	dir := flag.String("dir", "", "Path to the sessions directory (required)")
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

	type fileResult struct {
		name   string
		record output.SessionRecord
		label  int // 0 = benign, 1 = malicious
	}

	var results []fileResult

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

		var rec output.SessionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			log.Printf("SKIP %s: unmarshal error: %v", entry.Name(), err)
			continue
		}

		// Determine label from the JSON label field or from name/package_name.
		label := derivedLabel(entry.Name(), rec)

		results = append(results, fileResult{name: entry.Name(), record: rec, label: label})
	}

	if len(results) == 0 {
		fmt.Println("No JSON files found — nothing to validate.")
		os.Exit(0)
	}

	// -------------------------------------------------------------------------
	// Rule 1: No file may have all 36 QUT-DV25 features at zero.
	// -------------------------------------------------------------------------
	fmt.Println("\n─── Rule 1: All files have non-zero features ───")
	rule1Pass := true
	for _, r := range results {
		if allFeaturesZero(r.record) {
			fmt.Printf("  FAIL: %s has all QUT-DV25 features at zero\n", r.name)
			rule1Pass = false
		}
	}
	if rule1Pass {
		fmt.Println("  All files have non-zero features ✓")
	}

	// -------------------------------------------------------------------------
	// Rule 2: At least one malicious file must have other_dir_access > 0.
	// -------------------------------------------------------------------------
	fmt.Println("\n─── Rule 2: Malicious files have other_dir_access > 0 ───")
	rule2Pass := false
	for _, r := range results {
		if r.label == 1 && r.record.Opensnoop["other_dir_access"] > 0 {
			rule2Pass = true
			break
		}
	}
	if rule2Pass {
		fmt.Println("  Malicious files have other_dir_access > 0 ✓")
	} else {
		fmt.Println("  FAIL: no malicious file has other_dir_access > 0")
	}

	// -------------------------------------------------------------------------
	// Rule 3: median etc_dir_access for benign < median for malicious.
	// -------------------------------------------------------------------------
	fmt.Println("\n─── Rule 3: Benign median etc_dir_access < malicious median ───")
	var benignEtc, maliciousEtc []int
	for _, r := range results {
		v := r.record.Opensnoop["etc_dir_access"]
		if r.label == 0 {
			benignEtc = append(benignEtc, v)
		} else {
			maliciousEtc = append(maliciousEtc, v)
		}
	}

	rule3Pass := false
	var rule3Detail string
	if len(benignEtc) == 0 || len(maliciousEtc) == 0 {
		rule3Detail = "FAIL: not enough labelled data (need both benign and malicious records)"
	} else {
		bMedian := median(benignEtc)
		mMedian := median(maliciousEtc)
		rule3Detail = fmt.Sprintf("  benign median=%d, malicious median=%d", bMedian, mMedian)
		if bMedian < mMedian {
			rule3Pass = true
		}
	}

	if rule3Pass {
		fmt.Printf("  Benign median etc_dir_access < malicious median etc_dir_access ✓\n")
		fmt.Printf("  %s\n", rule3Detail)
	} else {
		fmt.Printf("  FAIL: %s\n", rule3Detail)
	}

	// -------------------------------------------------------------------------
	// Final verdict.
	// -------------------------------------------------------------------------
	benignCount := 0
	maliciousCount := 0
	for _, r := range results {
		if r.label == 0 {
			benignCount++
		} else {
			maliciousCount++
		}
	}

	fmt.Printf("\nDataset: %d benign, %d malicious (%d total)\n", benignCount, maliciousCount, len(results))

	if rule1Pass && rule2Pass && rule3Pass {
		fmt.Println("\nPASS")
		os.Exit(0)
	} else {
		fmt.Println("\nFAIL")
		os.Exit(1)
	}
}

// derivedLabel returns the label stored in the record if set; otherwise it
// falls back to inspecting the filename and package_name for "suspicious".
func derivedLabel(filename string, rec output.SessionRecord) int {
	if rec.Label != nil {
		return *rec.Label
	}
	if strings.Contains(strings.ToLower(filename), "suspicious") {
		return 1
	}
	if strings.Contains(strings.ToLower(rec.PackageName), "suspicious") {
		return 1
	}
	return 0
}

// allFeaturesZero returns true if every one of the 36 QUT-DV25 numeric
// features is zero for the given record.
func allFeaturesZero(r output.SessionRecord) bool {
	// Filetop (5 fields)
	if r.Filetop.ReadProcesses != 0 ||
		r.Filetop.WriteProcesses != 0 ||
		r.Filetop.ReadDataTransferKB != 0 ||
		r.Filetop.WriteDataTransferKB != 0 ||
		r.Filetop.FileAccessProcesses != 0 {
		return false
	}
	// Install (3 fields)
	if r.Install.TotalDependencies != 0 ||
		r.Install.DirectDependencies != 0 ||
		r.Install.IndirectDependencies != 0 {
		return false
	}
	// Opensnoop (7 fields)
	for _, v := range r.Opensnoop {
		if v != 0 {
			return false
		}
	}
	// TCP (5 fields)
	if r.TCP.StateTransitions != 0 ||
		r.TCP.LocalIPs != 0 ||
		r.TCP.RemoteIPs != 0 ||
		r.TCP.LocalPorts != 0 ||
		r.TCP.RemotePorts != 0 {
		return false
	}
	// Syscalls (6 of the 7 — unknown_ops excluded from QUT-DV25)
	if r.Syscalls.IoOps != 0 ||
		r.Syscalls.FileOps != 0 ||
		r.Syscalls.NetworkOps != 0 ||
		r.Syscalls.TimeOps != 0 ||
		r.Syscalls.SecurityOps != 0 ||
		r.Syscalls.ProcessOps != 0 {
		return false
	}
	// Patterns (10 fields)
	if r.Patterns.P1 != 0 ||
		r.Patterns.P2 != 0 ||
		r.Patterns.P3 != 0 ||
		r.Patterns.P4 != 0 ||
		r.Patterns.P5 != 0 ||
		r.Patterns.P6 != 0 ||
		r.Patterns.P7 != 0 ||
		r.Patterns.P8 != 0 ||
		r.Patterns.P9 != 0 ||
		r.Patterns.P10 != 0 {
		return false
	}
	return true
}

// median returns the median value of a non-empty slice of ints.
// The slice is sorted in-place (copy is fine since we pass by value).
func median(vals []int) int {
	sort.Ints(vals)
	n := len(vals)
	if n%2 == 1 {
		return vals[n/2]
	}
	return (vals[n/2-1] + vals[n/2]) / 2
}
