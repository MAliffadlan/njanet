package main

import (
	"os"
	"path/filepath"
	"testing"
)

func withTestRuntimeDir(t *testing.T) string {
	t.Helper()
	old := runtimeStateDirOverride
	dir := t.TempDir()
	runtimeStateDirOverride = dir
	t.Cleanup(func() { runtimeStateDirOverride = old })
	return dir
}

func TestControllerLockIsExclusive(t *testing.T) {
	withTestRuntimeDir(t)

	unlock, err := acquireControllerLock()
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := acquireControllerLock(); err == nil {
		t.Fatal("second lock unexpectedly succeeded")
	}
	unlock()

	unlock2, err := acquireControllerLock()
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

func TestScheduleLockIsExclusive(t *testing.T) {
	oldPath := dbPath
	t.Cleanup(func() { dbPath = oldPath })
	dbPath = filepath.Join(t.TempDir(), "state", "njanet.db")

	unlock, err := acquireScheduleLock()
	if err != nil {
		t.Fatalf("first schedule lock: %v", err)
	}
	if _, err := acquireScheduleLock(); err == nil {
		t.Fatal("second schedule lock unexpectedly succeeded")
	}
	unlock()

	unlock2, err := acquireScheduleLock()
	if err != nil {
		t.Fatalf("schedule lock after unlock: %v", err)
	}
	unlock2()
}

func TestControllerLockRefusesSymlink(t *testing.T) {
	stateDir := withTestRuntimeDir(t)
	base := filepath.Dir(stateDir)
	victim := filepath.Join(base, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(stateDir, "controller.lock")); err != nil {
		t.Fatal(err)
	}

	unlock, err := acquireControllerLock()
	if err == nil {
		unlock()
		t.Fatal("lock accepted a symlink")
	}
	data, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "keep" {
		t.Fatalf("symlink target was modified: %q", data)
	}
}
