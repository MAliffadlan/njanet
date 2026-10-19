package main

import (
	"path/filepath"
	"testing"
)

func TestControllerLockIsExclusive(t *testing.T) {
	oldPath := dbPath
	t.Cleanup(func() { dbPath = oldPath })
	dbPath = filepath.Join(t.TempDir(), "state", "njanet.db")

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
