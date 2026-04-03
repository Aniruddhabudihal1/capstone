// Package main implements a dataset labeler for npm-ebpf-monitor session records.
//
// It reads every JSON file in the --dir directory, determines whether the
// session is malicious (based on filename or package_name containing
// "suspicious"), writes back label=1 or label=0, and prints a summary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

	var benign, malicious int

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

		// Unmarshal into a generic map to preserve all existing keys exactly.
		var record map[string]interface{}
		if err := json.Unmarshal(data, &record); err != nil {
			log.Printf("SKIP %s: unmarshal error: %v", entry.Name(), err)
			continue
		}

		label := labelFor(entry.Name(), record)
		record["label"] = label

		out, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			log.Printf("SKIP %s: marshal error: %v", entry.Name(), err)
			continue
		}

		if err := os.WriteFile(path, out, 0o644); err != nil {
			log.Printf("SKIP %s: write error: %v", entry.Name(), err)
			continue
		}

		if label == 1 {
			malicious++
			fmt.Printf("  [malicious] %s\n", entry.Name())
		} else {
			benign++
			fmt.Printf("  [benign]    %s\n", entry.Name())
		}
	}

	total := benign + malicious
	fmt.Printf("\nDataset: %d benign, %d malicious (%d total)\n", benign, malicious, total)
}

// labelFor returns 1 (malicious) if the filename or package_name field
// contains "suspicious", and 0 (benign) otherwise.
func labelFor(filename string, record map[string]interface{}) int {
	if strings.Contains(strings.ToLower(filename), "suspicious") {
		return 1
	}

	if pkgName, ok := record["package_name"].(string); ok {
		if strings.Contains(strings.ToLower(pkgName), "suspicious") {
			return 1
		}
	}

	return 0
}
