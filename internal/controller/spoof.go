package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	purposeManualBlock = "block"
	purposeSchedBlock  = "sched-block"
	purposeThrottle    = "throttle"
	spoofMarker        = "NJANET_SPOOF"
)

type spoofState struct {
	Iface     string    `json:"iface"`
	Target    string    `json:"target"`
	MAC       string    `json:"mac"`
	Kind      string    `json:"kind"`
	PIDs      []int     `json:"pids"`
	Purposes  []string  `json:"purposes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type spoofStateFile struct {
	Path  string
	State *spoofState
}

const spoofPythonSource = `# NJANET_SPOOF
import socket, struct, time
def arp(iface, sm, si, dm, di):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((iface, 0))
    while True:
        eth = struct.pack("!6s6sH",
            bytes.fromhex(dm.replace(":","")),
            bytes.fromhex(sm.replace(":","")), 0x0806)
        a = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
            bytes.fromhex(sm.replace(":","")),
            socket.inet_aton(si),
            bytes.fromhex(dm.replace(":","")),
            socket.inet_aton(di))
        s.send(eth + a)
        time.sleep(1)
`

func (c *Controller) spoofStatePath(target string) string {
	sum := sha256.Sum256([]byte(c.iface + "|" + target))
	return filepath.Join(c.stateDir, "spoof-"+hex.EncodeToString(sum[:8])+".json")
}

func (c *Controller) ensureSpoofStateDir() error {
	if c.stateDir == "" {
		return fmt.Errorf("state directory is not configured")
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	info, err := os.Lstat(c.stateDir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked state directory %s", c.stateDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %s is not a directory", c.stateDir)
	}
	return nil
}

func loadSpoofState(path string) (*spoofState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked spoof state %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st spoofState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse spoof state: %w", err)
	}
	return &st, nil
}

func saveSpoofState(path string, st *spoofState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	st.UpdatedAt = time.Now()
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".spoof-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func loadAllSpoofStates(dir string) ([]spoofStateFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []spoofStateFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "spoof-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		p := filepath.Join(dir, name)
		st, err := loadSpoofState(p)
		if err != nil {
			continue
		}
		out = append(out, spoofStateFile{Path: p, State: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func blockStatesForMAC(states []spoofStateFile, iface, mac string) []spoofStateFile {
	var out []spoofStateFile
	for _, entry := range states {
		st := entry.State
		if st.Iface == iface && strings.EqualFold(st.MAC, mac) &&
			(hasPurpose(st, purposeManualBlock) || hasPurpose(st, purposeSchedBlock)) {
			out = append(out, entry)
		}
	}
	return out
}

func hasPurpose(st *spoofState, purpose string) bool {
	for _, p := range st.Purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

func addPurpose(st *spoofState, purpose string) bool {
	if hasPurpose(st, purpose) {
		return false
	}
	st.Purposes = append(st.Purposes, purpose)
	return true
}

func removePurpose(st *spoofState, purpose string) {
	out := st.Purposes[:0]
	for _, p := range st.Purposes {
		if p != purpose {
			out = append(out, p)
		}
	}
	st.Purposes = out
}

func spoofPIDMatches(pid int, iface, target string) bool {
	if pid <= 0 {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	if !strings.Contains(cmdline, iface) || !strings.Contains(cmdline, target) {
		return false
	}
	return strings.Contains(cmdline, "arpspoof") || strings.Contains(cmdline, spoofMarker)
}

func spoofStateAlive(st *spoofState) bool {
	if st == nil || len(st.PIDs) == 0 {
		return false
	}
	for _, pid := range st.PIDs {
		if !spoofPIDMatches(pid, st.Iface, st.Target) {
			return false
		}
	}
	return true
}

func killSpoofState(st *spoofState) error {
	var errs []error
	for _, pid := range st.PIDs {
		if !spoofPIDMatches(pid, st.Iface, st.Target) {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("kill spoof pid %d: %w", pid, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) killSpoofHandles(target string) error {
	var errs []error
	for _, suffix := range []string{"gw", "tgt"} {
		key := target + "_" + suffix
		cmd, ok := c.spoofProcs[key]
		if !ok {
			continue
		}
		delete(c.spoofProcs, key)
		if cmd.Process == nil {
			continue
		}
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			errs = append(errs, err)
		}
		if err := cmd.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			// Killed processes normally report "signal: killed"; that is expected.
		}
	}
	return errors.Join(errs...)
}

// cleanupStaleSpoofs is called while the CLI-wide lock is held. Scheduler
// purposes without a live daemon are stale; manual blocks are persistent.
// staleThrottle reports that tc state may also be left over.
func (c *Controller) cleanupStaleSpoofs(preserveScheduled bool) (staleThrottle bool, err error) {
	if c.stateDir == "" {
		return false, nil
	}
	states, err := loadAllSpoofStates(c.stateDir)
	if err != nil {
		return false, err
	}
	var errs []error
	for _, entry := range states {
		st := entry.State
		hasManual := hasPurpose(st, purposeManualBlock)
		hasSched := hasPurpose(st, purposeSchedBlock)
		hasThrottle := hasPurpose(st, purposeThrottle)

		if preserveScheduled && !hasThrottle {
			// The scheduler validates its own persisted state after creation.
			continue
		}
		if preserveScheduled && hasThrottle {
			// Only stale throttle ownership is cleaned; sched/manual block
			// state is left for the scheduler's startup reconciliation.
			staleThrottle = true
			removePurpose(st, purposeThrottle)
			if spoofStateAlive(st) && (hasManual || hasSched) {
				if err := saveSpoofState(entry.Path, st); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			if err := killSpoofState(st); err != nil {
				errs = append(errs, err)
			}
			if err := os.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}

		if hasSched {
			removePurpose(st, purposeSchedBlock)
			if err := c.deleteChainRulesOwner(st.Target, ruleOwnerSched); err != nil {
				errs = append(errs, err)
			}
		}
		if hasThrottle {
			staleThrottle = true
			removePurpose(st, purposeThrottle)
		}
		if hasManual && spoofStateAlive(st) {
			// Keep the manual block and its spoof, dropping only scheduler
			// and throttle ownership.
			if (hasSched || hasThrottle) && len(st.Purposes) > 0 {
				if err := saveSpoofState(entry.Path, st); err != nil {
					errs = append(errs, err)
				}
			}
			continue
		}
		if hasManual {
			// Manual block with a dead spoof: drop the state file, leave its
			// rules for an explicit unblock/reset.
			if err := os.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		// Scheduled/throttle-only leftovers are stale.
		if err := killSpoofState(st); err != nil {
			errs = append(errs, err)
		}
		if err := os.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return staleThrottle, errors.Join(errs...)
}

func (c *Controller) startSpoof(target, purpose, mac string) error {
	if err := c.ensureSpoofStateDir(); err != nil {
		return err
	}
	if target == "" {
		return fmt.Errorf("spoof target IP is empty")
	}
	mac = normalizeMAC(mac)
	if mac == "" {
		return fmt.Errorf("spoof target MAC is empty")
	}
	path := c.spoofStatePath(target)
	st, err := loadSpoofState(path)
	var preserved []string
	switch {
	case err == nil:
		sameMAC := st.MAC == "" || strings.EqualFold(st.MAC, mac)
		if st.Iface == c.iface && st.Target == target && sameMAC && spoofStateAlive(st) {
			changed := false
			if st.MAC == "" {
				st.MAC = mac
				changed = true
			}
			if addPurpose(st, purpose) {
				changed = true
			}
			if changed {
				if err := saveSpoofState(path, st); err != nil {
					return err
				}
			}
			return nil
		}
		if st.Iface == c.iface && st.Target == target && sameMAC {
			preserved = append(preserved, st.Purposes...)
		}
		// Stale entry: kill whatever is still identifiable and restart cleanly.
		_ = killSpoofState(st)
		_ = os.Remove(path)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("load spoof state: %w", err)
	}

	if err := c.killSpoofHandles(target); err != nil {
		return err
	}
	kind, pids, procs, err := c.spawnSpoof(target)
	if err != nil {
		return err
	}
	purposes := append([]string{}, preserved...)
	if !containsString(purposes, purpose) {
		purposes = append(purposes, purpose)
	}
	st = &spoofState{
		Iface:    c.iface,
		Target:   target,
		MAC:      mac,
		Kind:     kind,
		PIDs:     pids,
		Purposes: purposes,
	}
	if err := saveSpoofState(path, st); err != nil {
		for _, cmd := range procs {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}
		return fmt.Errorf("save spoof state: %w", err)
	}
	for suffix, cmd := range procs {
		c.spoofProcs[target+"_"+suffix] = cmd
	}
	return nil
}

func (c *Controller) stopSpoof(target, purpose string) error {
	if target == "" {
		return fmt.Errorf("spoof target IP is empty")
	}
	path := c.spoofStatePath(target)
	st, err := loadSpoofState(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			_ = c.killSpoofHandles(target)
			return fmt.Errorf("load spoof state: %w", err)
		}
		if err := c.killSpoofHandles(target); err != nil {
			return err
		}
		c.restoreARP(target)
		return nil
	}

	removePurpose(st, purpose)
	if len(st.Purposes) > 0 && spoofStateAlive(st) {
		return saveSpoofState(path, st)
	}

	var errs []error
	if err := c.killSpoofHandles(target); err != nil {
		errs = append(errs, err)
	}
	if err := killSpoofState(st); err != nil {
		errs = append(errs, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	c.restoreARP(target)
	return errors.Join(errs...)
}

// UnblockMAC removes all block rules and spoof purposes recorded for a MAC,
// regardless of which IP the device had when it was blocked.
func (c *Controller) UnblockMAC(mac string) (int, error) {
	if err := c.checkPrivileges(); err != nil {
		return 0, err
	}
	mac = normalizeMAC(mac)
	if mac == "" {
		return 0, fmt.Errorf("invalid MAC address")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	states, err := loadAllSpoofStates(c.stateDir)
	if err != nil {
		return 0, err
	}
	var errs []error
	removed := 0
	for _, entry := range blockStatesForMAC(states, c.iface, mac) {
		st := entry.State
		if err := errors.Join(c.deleteChainRules(st.Target), c.removeLegacyForwardDropRules(st.Target)); err != nil {
			errs = append(errs, err)
			continue
		}
		manualErr := c.stopSpoof(st.Target, purposeManualBlock)
		schedErr := c.stopSpoof(st.Target, purposeSchedBlock)
		if err := errors.Join(manualErr, schedErr); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

func (c *Controller) stopAllSpoofs() error {
	targets := make(map[string]bool)
	var errs []error
	for key, cmd := range c.spoofProcs {
		if i := strings.LastIndex(key, "_"); i > 0 {
			targets[key[:i]] = true
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		delete(c.spoofProcs, key)
	}

	states, err := loadAllSpoofStates(c.stateDir)
	if err != nil {
		errs = append(errs, err)
	}
	for _, entry := range states {
		if err := killSpoofState(entry.State); err != nil {
			errs = append(errs, err)
		}
		if err := os.Remove(entry.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
		targets[entry.State.Target] = true
	}
	for target := range targets {
		c.restoreARP(target)
	}
	return errors.Join(errs...)
}

func (c *Controller) spawnSpoof(target string) (string, []int, map[string]*exec.Cmd, error) {
	if c.gatewayIP == "" {
		return "", nil, nil, fmt.Errorf("gateway IP is unknown")
	}

	if arpspoof := findExecutable("arpspoof"); arpspoof != "" {
		c1 := exec.Command(arpspoof, "-i", c.iface, "-t", target, c.gatewayIP)
		if err := c1.Start(); err != nil {
			return "", nil, nil, fmt.Errorf("start arpspoof toward target: %w", err)
		}
		c2 := exec.Command(arpspoof, "-i", c.iface, "-t", c.gatewayIP, target)
		if err := c2.Start(); err != nil {
			killStarted(c1)
			return "", nil, nil, fmt.Errorf("start arpspoof toward gateway: %w", err)
		}
		if err := verifySpoofProcesses(c1, c2); err != nil {
			killStarted(c1, c2)
			return "", nil, nil, err
		}
		return "arpspoof", []int{c1.Process.Pid, c2.Process.Pid},
			map[string]*exec.Cmd{"gw": c1, "tgt": c2}, nil
	}

	python := findExecutable("python3")
	if python == "" {
		return "", nil, nil, fmt.Errorf("arpspoof not found and python3 is not installed; install dsniff or python3")
	}
	myMAC := normalizeMAC(c.getMyMAC())
	gatewayMAC := normalizeMAC(c.getGatewayMAC())
	targetMAC := normalizeMAC(c.getMAC(target))
	if myMAC == "" || gatewayMAC == "" || targetMAC == "" {
		return "", nil, nil, fmt.Errorf(
			"cannot spoof %s: missing MAC (local=%q gateway=%q target=%q); run 'sudo njanet scan' first",
			target, myMAC, gatewayMAC, targetMAC)
	}
	arg := func(senderIP, senderMAC, destIP, destMAC string) string {
		return spoofPythonSource + fmt.Sprintf("arp(%q, %q, %q, %q, %q)",
			c.iface, senderMAC, senderIP, destMAC, destIP)
	}

	c1 := exec.Command(python, "-c", arg(c.gatewayIP, myMAC, target, targetMAC))
	if err := c1.Start(); err != nil {
		return "", nil, nil, fmt.Errorf("start python spoof toward target: %w", err)
	}
	c2 := exec.Command(python, "-c", arg(target, myMAC, c.gatewayIP, gatewayMAC))
	if err := c2.Start(); err != nil {
		killStarted(c1)
		return "", nil, nil, fmt.Errorf("start python spoof toward gateway: %w", err)
	}
	if err := verifySpoofProcesses(c1, c2); err != nil {
		killStarted(c1, c2)
		return "", nil, nil, err
	}
	return "python", []int{c1.Process.Pid, c2.Process.Pid},
		map[string]*exec.Cmd{"gw": c1, "tgt": c2}, nil
}

func killStarted(cmds ...*exec.Cmd) {
	for _, cmd := range cmds {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
}

// verifySpoofProcesses catches children that exec successfully but exit right
// away (bad interface, missing CAP_NET_RAW, invalid target, broken python).
func verifySpoofProcesses(cmds ...*exec.Cmd) error {
	time.Sleep(120 * time.Millisecond)
	for _, cmd := range cmds {
		if cmd.Process == nil || !processRunning(cmd.Process.Pid) {
			return fmt.Errorf("spoof process exited immediately; check interface, permissions, and target MAC")
		}
	}
	return nil
}

func processRunning(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(data)
	if i := strings.LastIndex(s, ")"); i >= 0 && i+2 < len(s) {
		return s[i+2] != 'Z'
	}
	return false
}

func (c *Controller) restoreARP(target string) {
	for _, ip := range []string{c.gatewayIP, target} {
		if ip == "" {
			continue
		}
		_ = exec.Command("arp", "-d", ip).Run()
		_ = exec.Command("ping", "-c", "1", "-W", "1", ip).Run()
	}
}

func (c *Controller) getMyMAC() string {
	data, err := os.ReadFile("/sys/class/net/" + c.iface + "/address")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *Controller) getGatewayMAC() string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == c.gatewayIP && f[3] != "(incomplete)" {
			return strings.ToUpper(f[3])
		}
	}
	return ""
}

func (c *Controller) getMAC(ip string) string {
	read := func() string {
		data, err := os.ReadFile("/proc/net/arp")
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == ip && f[3] != "(incomplete)" {
				return strings.ToUpper(f[3])
			}
		}
		return ""
	}
	if mac := read(); mac != "" {
		return mac
	}
	_ = exec.Command("ping", "-c", "1", "-W", "1", ip).Run()
	return read()
}

func normalizeMAC(mac string) string {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return ""
	}
	for _, p := range parts {
		if len(p) != 2 {
			return ""
		}
		if _, err := strconv.ParseUint(p, 16, 8); err != nil {
			return ""
		}
	}
	return mac
}
