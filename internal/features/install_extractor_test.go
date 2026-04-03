package features

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractInstallFeatures_V3(t *testing.T) {
	tempDir := t.TempDir()

	writeTestFile(t, filepath.Join(tempDir, "package.json"), `{
  "dependencies": {
    "react": "^18.0.0",
    "lodash": "^4.17.21"
  }
}`)

	writeTestFile(t, filepath.Join(tempDir, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/react": {},
    "node_modules/lodash": {},
    "node_modules/scheduler": {},
    "node_modules/js-tokens": {},
    "node_modules/loose-envify": {}
  }
}`)

	got, err := ExtractInstallFeatures(filepath.Join(tempDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("ExtractInstallFeatures() error = %v, want nil", err)
	}

	want := InstallFeatures{
		TotalDependencies:    5,
		DirectDependencies:   2,
		IndirectDependencies: 3,
	}

	if got != want {
		t.Fatalf("ExtractInstallFeatures() = %+v, want %+v", got, want)
	}
}

func TestExtractInstallFeatures_V1(t *testing.T) {
	tempDir := t.TempDir()

	writeTestFile(t, filepath.Join(tempDir, "package.json"), `{
  "dependencies": {
    "chalk": "^5.0.0"
  }
}`)

	writeTestFile(t, filepath.Join(tempDir, "package-lock.json"), `{
  "lockfileVersion": 1,
  "dependencies": {
    "chalk": {},
    "ansi-styles": {},
    "supports-color": {},
    "color-convert": {}
  }
}`)

	got, err := ExtractInstallFeatures(filepath.Join(tempDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("ExtractInstallFeatures() error = %v, want nil", err)
	}

	want := InstallFeatures{
		TotalDependencies:    4,
		DirectDependencies:   1,
		IndirectDependencies: 3,
	}

	if got != want {
		t.Fatalf("ExtractInstallFeatures() = %+v, want %+v", got, want)
	}
}

func TestExtractInstallFeatures_MissingFiles(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "does-not-exist", "package-lock.json")

	got, err := ExtractInstallFeatures(missingPath)
	if err != nil {
		t.Fatalf("ExtractInstallFeatures() error = %v, want nil", err)
	}

	if got != (InstallFeatures{}) {
		t.Fatalf("ExtractInstallFeatures() = %+v, want zero-value InstallFeatures", got)
	}
}

func TestParseNpmOutput(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   int
	}{
		{
			name:   "multiple packages",
			stdout: "added 42 packages, and audited 43 packages in 3s",
			want:   42,
		},
		{
			name:   "single package",
			stdout: "added 1 package in 1s",
			want:   1,
		},
		{
			name:   "no match",
			stdout: "up to date, audited 10 packages",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseNpmOutput(tt.stdout)
			if got != tt.want {
				t.Fatalf("ParseNpmOutput(%q) = %d, want %d", tt.stdout, got, tt.want)
			}
		})
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
