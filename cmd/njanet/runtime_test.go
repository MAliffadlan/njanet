package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestMigrateLegacyRuntimeStateMovesSpoofFiles(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, "legacy")
	runtimeDir := filepath.Join(base, "run")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	spoof := filepath.Join(legacy, "spoof-abc.json")
	if err := os.WriteFile(spoof, []byte(`{"iface":"eth0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "controller.lock"), []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "sched.pid"), []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "njanet.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := migrateLegacyRuntimeState(legacy, runtimeDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "spoof-abc.json")); err != nil {
		t.Fatalf("spoof state not moved: %v", err)
	}
	for _, name := range []string{"spoof-abc.json", "controller.lock", "sched.pid"} {
		if _, err := os.Stat(filepath.Join(legacy, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists in legacy dir: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(legacy, "njanet.db")); err != nil {
		t.Errorf("database was moved/deleted: %v", err)
	}
}

func TestMigrateLegacyRuntimeStateRefusesActiveOldSession(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, "legacy")
	runtimeDir := filepath.Join(base, "run")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(legacy, "controller.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	err = migrateLegacyRuntimeState(legacy, runtimeDir)
	if err == nil || !strings.Contains(err.Error(), "lama") {
		t.Fatalf("migration accepted an active old session: %v", err)
	}
}
