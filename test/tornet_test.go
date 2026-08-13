package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/neozmmv/blindspot/internal/tornet"
)

func torExeName() string {
	if runtime.GOOS == "windows" {
		return "tor.exe"
	}
	return "tor"
}

// With nothing bundled beside the binary, resolution must fall back to PATH.
// The Tor Project publishes no linux-aarch64 Expert Bundle, so on that target
// the fallback is the only way Tor is available at all.
func TestExePathFallsBackToSystemTor(t *testing.T) {
	onPath, err := exec.LookPath(torExeName())
	if err != nil {
		t.Skipf("no tor on PATH to test the fallback against: %v", err)
	}

	got, libDir, err := tornet.ExePathFrom(t.TempDir()) // empty dir: nothing bundled
	if err != nil {
		t.Fatalf("ExePathFrom: %v", err)
	}
	if got != onPath {
		t.Fatalf("expected fallback to PATH copy %q, got %q", onPath, got)
	}
	// A system tor brings its own libraries; overriding the loader search path
	// for it would be wrong, so libDir must be empty on this branch.
	if libDir != "" {
		t.Fatalf("expected no library dir for a PATH tor, got %q", libDir)
	}
}

// The bundled copy must win over PATH, or a user with an old system tor would
// silently get that instead of the version shipped and tested with.
func TestExePathPrefersBundledOverPath(t *testing.T) {
	base := t.TempDir()
	bundleDir := filepath.Join(base, "tor")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bundled := filepath.Join(bundleDir, torExeName())
	if err := os.WriteFile(bundled, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, libDir, err := tornet.ExePathFrom(base)
	if err != nil {
		t.Fatalf("ExePathFrom: %v", err)
	}
	if got != bundled {
		t.Fatalf("bundled tor should win; got %q, want %q", got, bundled)
	}
	// The Expert Bundle's tor has no RPATH and links libssl/libcrypto/libevent
	// from its own directory, so that directory must go on the loader path.
	if libDir != bundleDir {
		t.Fatalf("expected library dir %q, got %q", bundleDir, libDir)
	}
}

// A directory named like the executable must not be mistaken for it.
func TestExePathIgnoresDirectoryNamedTor(t *testing.T) {
	if _, err := exec.LookPath(torExeName()); err != nil {
		t.Skipf("fallback needs a tor on PATH: %v", err)
	}

	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "tor", torExeName()), 0o755); err != nil {
		t.Fatal(err)
	}

	got, _, err := tornet.ExePathFrom(base)
	if err != nil {
		t.Fatalf("ExePathFrom: %v", err)
	}
	if got == filepath.Join(base, "tor", torExeName()) {
		t.Fatal("resolved a directory as the tor executable")
	}
}
