package db

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type stateOwner struct {
	uid int
	gid int
}

// ownerForPath returns the invoking sudo user only when dir is strictly inside
// that user's home. This prevents a root process from chowning arbitrary paths
// (e.g. "." or "/") just because SUDO_UID happens to be set.
func ownerForPath(dir string) *stateOwner {
	if os.Geteuid() != 0 {
		return nil
	}
	uidRaw := os.Getenv("SUDO_UID")
	if uidRaw == "" {
		return nil
	}
	uid, err := strconv.Atoi(uidRaw)
	if err != nil || uid < 0 {
		return nil
	}
	gid := uid
	if gidRaw := os.Getenv("SUDO_GID"); gidRaw != "" {
		if g, err := strconv.Atoi(gidRaw); err == nil && g >= 0 {
			gid = g
		}
	}
	u, err := user.LookupId(uidRaw)
	if err != nil || u.HomeDir == "" {
		return nil
	}
	home := filepath.Clean(u.HomeDir)
	dir = filepath.Clean(dir)
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	return &stateOwner{uid: uid, gid: gid}
}

func openNoFollow(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func secureFile(f *os.File, owner *stateOwner, mode os.FileMode) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", f.Name())
	}
	if owner != nil {
		if err := f.Chown(owner.uid, owner.gid); err != nil {
			return fmt.Errorf("chown %s: %w", f.Name(), err)
		}
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", f.Name(), err)
	}
	return nil
}

func ensureStateDir(dir string, owner *stateOwner) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	f, err := openNoFollow(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("refusing symlinked state directory %s", dir)
		}
		return fmt.Errorf("open db dir: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat db dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %s is not a directory", dir)
	}
	if owner != nil {
		if err := f.Chown(owner.uid, owner.gid); err != nil {
			return fmt.Errorf("chown state dir %s: %w", dir, err)
		}
		if err := f.Chmod(0o700); err != nil {
			return fmt.Errorf("chmod state dir %s: %w", dir, err)
		}
		return nil
	}
	// Best effort privacy for user-owned dirs; ignore EPERM for shared dirs.
	if info.Mode().Perm()&0o077 != 0 {
		_ = f.Chmod(0o700)
	}
	return nil
}

func prepareDBFile(path string, owner *stateOwner) error {
	f, err := openNoFollow(path, syscall.O_CREAT|syscall.O_RDWR, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("refusing symlinked database %s", path)
		}
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("database %s is not writable (often created by an earlier sudo run); run once with sudo so NjaNet can repair ownership: %w", path, err)
		}
		return fmt.Errorf("open database: %w", err)
	}
	defer f.Close()
	return secureFile(f, owner, 0o600)
}

// secureStateFiles fixes ownership and mode of the database and its SQLite
// sidecars. It runs right after migration (so WAL/SHM created by root are
// repaired before the next non-root command) and again on Close.
func secureStateFiles(path string, owner *stateOwner) error {
	var errs []error
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		f, err := openNoFollow(p, syscall.O_RDONLY, 0)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
				continue
			}
			if errors.Is(err, syscall.ELOOP) {
				errs = append(errs, fmt.Errorf("refusing symlinked state file %s", p))
				continue
			}
			errs = append(errs, fmt.Errorf("open %s: %w", p, err))
			continue
		}
		err = secureFile(f, owner, 0o600)
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (d *Database) Close() error {
	return errors.Join(d.DB.Close(), secureStateFiles(d.path, d.owner))
}
