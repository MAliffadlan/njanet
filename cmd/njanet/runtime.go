package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// runtimeStateDirOverride is only set by tests. Production root state must
// live in a directory the invoking user cannot create, replace, or symlink.
var runtimeStateDirOverride string

func mustRuntimeStateDir() string {
	dir, err := resolveRuntimeStateDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return dir
}

func resolveRuntimeStateDir() (string, error) {
	if runtimeStateDirOverride != "" {
		if err := os.MkdirAll(runtimeStateDirOverride, 0o700); err != nil {
			return "", fmt.Errorf("create test runtime dir: %w", err)
		}
		return runtimeStateDirOverride, nil
	}
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("root required: jalankan dengan sudo")
	}
	dir := "/run/njanet"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("stat runtime dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("runtime dir %s is not a real directory", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return "", fmt.Errorf("runtime dir %s is not owned by root", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", fmt.Errorf("chmod runtime dir: %w", err)
		}
	}
	return dir, nil
}

func legacyLockBusy(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return true, nil
		}
		return false, err
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
}

// migrateLegacyRuntimeState moves spoof PID files written by older versions
// (next to the database) into the root-owned runtime directory. It refuses to
// proceed while an old controller/scheduler still holds its lock.
func migrateLegacyRuntimeState(legacyDir, runtimeDir string) error {
	if legacyDir == "" || legacyDir == runtimeDir {
		return nil
	}
	for _, name := range []string{"controller.lock", "sched.pid"} {
		busy, err := legacyLockBusy(filepath.Join(legacyDir, name))
		if err != nil {
			return fmt.Errorf("cek state lama %s: %w", name, err)
		}
		if busy {
			return fmt.Errorf("sesi Njanet lama masih berjalan (%s); hentikan dulu", name)
		}
	}
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "spoof-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		src := filepath.Join(legacyDir, name)
		dst := filepath.Join(runtimeDir, name)
		info, err := os.Lstat(src)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			errs = append(errs, err)
			continue
		}
		_ = os.Chmod(dst, 0o600)
		if err := os.Remove(src); err != nil {
			errs = append(errs, err)
		}
	}
	for _, name := range []string{"controller.lock", "sched.pid"} {
		if err := os.Remove(filepath.Join(legacyDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
