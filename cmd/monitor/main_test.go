package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
)

func TestLoadInstallFeaturesUsesSessionCwd(t *testing.T) {
	dirOne := t.TempDir()
	dirTwo := t.TempDir()

	writeTestFile(t, filepath.Join(dirOne, "package.json"), `{
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`)
	writeTestFile(t, filepath.Join(dirOne, "package-lock.json"), `{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {},
    "once": {}
  }
}`)

	writeTestFile(t, filepath.Join(dirTwo, "package.json"), `{
  "dependencies": {
    "axios": "^1.0.0",
    "follow-redirects": "^1.15.0"
  }
}`)
	writeTestFile(t, filepath.Join(dirTwo, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/axios": {},
    "node_modules/follow-redirects": {},
    "node_modules/form-data": {},
    "node_modules/proxy-from-env": {}
  }
}`)

	gotOne, err := loadInstallFeatures(&session.Session{Cwd: dirOne})
	if err != nil {
		t.Fatalf("loadInstallFeatures(dirOne) error = %v", err)
	}
	gotTwo, err := loadInstallFeatures(&session.Session{Cwd: dirTwo})
	if err != nil {
		t.Fatalf("loadInstallFeatures(dirTwo) error = %v", err)
	}

	wantOne := features.InstallFeatures{
		TotalDependencies:    2,
		DirectDependencies:   1,
		IndirectDependencies: 1,
	}
	wantTwo := features.InstallFeatures{
		TotalDependencies:    4,
		DirectDependencies:   2,
		IndirectDependencies: 2,
	}

	if gotOne != wantOne {
		t.Fatalf("loadInstallFeatures(dirOne) = %+v, want %+v", gotOne, wantOne)
	}
	if gotTwo != wantTwo {
		t.Fatalf("loadInstallFeatures(dirTwo) = %+v, want %+v", gotTwo, wantTwo)
	}
}

func TestLoadInstallFeaturesMissingCwd(t *testing.T) {
	got, err := loadInstallFeatures(&session.Session{})
	if err != nil {
		t.Fatalf("loadInstallFeatures(empty cwd) error = %v, want nil", err)
	}
	if got != (features.InstallFeatures{}) {
		t.Fatalf("loadInstallFeatures(empty cwd) = %+v, want zero value", got)
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
