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

func ensureStateDir(dir string, owner *stateOwner) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat db dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked state directory %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %s is not a directory", dir)
	}
	if owner != nil {
		if err := os.Chown(dir, owner.uid, owner.gid); err != nil {
			return fmt.Errorf("chown state dir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod state dir %s: %w", dir, err)
		}
		return nil
	}
	// Best effort privacy for user-owned dirs; ignore EPERM for shared dirs.
	if info.Mode().Perm()&0077 != 0 {
		_ = os.Chmod(dir, 0700)
	}
	return nil
}

func prepareDBFile(path string, owner *stateOwner) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked database %s", path)
		}
		if info.IsDir() {
			return fmt.Errorf("database path %s is a directory", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat database: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("database %s is not writable (often created by an earlier sudo run); run once with sudo so NjaNet can repair ownership: %w", path, err)
		}
		return fmt.Errorf("open database: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	if owner != nil {
		if err := os.Chown(path, owner.uid, owner.gid); err != nil {
			return fmt.Errorf("chown database %s: %w", path, err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("chmod database %s: %w", path, err)
	}
	return nil
}

// secureStateFiles fixes ownership and mode of the database and its SQLite
// sidecars. It runs right after migration (so WAL/SHM created by root are
// repaired before the next non-root command) and again on Close.
func secureStateFiles(path string, owner *stateOwner) error {
	var errs []error
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("stat %s: %w", p, err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("refusing symlinked state file %s", p))
			continue
		}
		if owner != nil {
			if err := os.Chown(p, owner.uid, owner.gid); err != nil {
				errs = append(errs, fmt.Errorf("chown %s: %w", p, err))
				continue
			}
		}
		if err := os.Chmod(p, 0600); err != nil {
			errs = append(errs, fmt.Errorf("chmod %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func (d *Database) Close() error {
	return errors.Join(d.DB.Close(), secureStateFiles(d.path, d.owner))
}
