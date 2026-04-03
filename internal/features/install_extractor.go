// Package features provides higher-level analysis on top of raw eBPF events.
package features

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// InstallFeatures captures dependency counts for an npm install.
type InstallFeatures struct {
	TotalDependencies    int `json:"total_dependencies"`
	DirectDependencies   int `json:"direct_dependencies"`
	IndirectDependencies int `json:"indirect_dependencies"`
}

type packageJSON struct {
	Dependencies map[string]string `json:"dependencies"`
}

type packageLockJSON struct {
	Packages     map[string]any `json:"packages"`
	Dependencies map[string]any `json:"dependencies"`
}

var addedPackagesRegex = regexp.MustCompile(`\badded\s+(\d+)\s+packages?\b`)

// ExtractInstallFeatures reads package metadata and derives direct, total, and
// indirect dependency counts. Missing files and read failures degrade
// gracefully to zero counts; malformed JSON is returned as an error.
func ExtractInstallFeatures(packageLockPath string) (InstallFeatures, error) {
	var features InstallFeatures

	dir := filepath.Dir(packageLockPath)
	packageJSONPath := filepath.Join(dir, "package.json")

	packageJSONBytes, err := os.ReadFile(packageJSONPath)
	if err == nil {
		var pkg packageJSON
		if err := json.Unmarshal(packageJSONBytes, &pkg); err != nil {
			return InstallFeatures{}, err
		}
		features.DirectDependencies = len(pkg.Dependencies)
	}

	packageLockBytes, err := os.ReadFile(packageLockPath)
	if err == nil {
		var lock packageLockJSON
		if err := json.Unmarshal(packageLockBytes, &lock); err != nil {
			return InstallFeatures{}, err
		}

		switch {
		case len(lock.Packages) > 0:
			features.TotalDependencies = len(lock.Packages)
			if _, hasRoot := lock.Packages[""]; hasRoot && features.TotalDependencies > 0 {
				features.TotalDependencies--
			}
		case len(lock.Dependencies) > 0:
			features.TotalDependencies = len(lock.Dependencies)
		}
	}

	features.IndirectDependencies = features.TotalDependencies - features.DirectDependencies
	if features.IndirectDependencies < 0 {
		features.IndirectDependencies = 0
	}

	return features, nil
}

// ParseNpmOutput extracts the number of packages added from npm stdout.
func ParseNpmOutput(stdout string) int {
	matches := addedPackagesRegex.FindStringSubmatch(stdout)
	if len(matches) != 2 {
		return 0
	}

	count, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}

	return count
}
