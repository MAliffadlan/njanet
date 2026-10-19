package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// acquireControllerLock serializes every command that mutates tc, iptables,
// or ARP-spoof processes. Long-running commands (throttle/hog/scheduler) hold
// it for their whole lifetime so another invocation cannot silently wipe
// their rules.
func acquireControllerLock() (func(), error) {
	dir, err := resolveRuntimeStateDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "controller.lock")
	fd, err := syscall.Open(path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("controller.lock is a symlink; refusing to open it")
		}
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("root required: jalankan dengan sudo")
		}
		return nil, fmt.Errorf("open controller lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat controller lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("controller.lock is not a regular file")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && st.Uid != 0 {
		f.Close()
		return nil, fmt.Errorf("controller.lock is not owned by root")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("proses NjaNet lain sedang aktif (throttle/hog/scheduler). Hentikan dulu")
		}
		return nil, fmt.Errorf("lock controller: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// acquireScheduleLock serializes sched add/remove. It lives in the DB
// directory because these commands intentionally run without sudo, while the
// controller lock lives in root-owned runtime state.
func acquireScheduleLock() (func(), error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(dir, "schedules.lock")
	fd, err := syscall.Open(path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o666)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("schedules.lock is a symlink; refusing to open it")
		}
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("cannot open schedules.lock (root-owned?); jalankan sebagai user pemilik DB")
		}
		return nil, fmt.Errorf("open schedule lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat schedule lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("schedules.lock is not a regular file")
	}
	// The directory is private to the DB owner, so allowing root and that user
	// to open the same lock file is safe.
	_ = f.Chmod(0o666)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("proses lain sedang mengubah jadwal")
		}
		return nil, fmt.Errorf("lock schedule: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
