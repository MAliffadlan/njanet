package controller

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mectov/njanet/internal/db"
)

type Controller struct {
	mu            sync.Mutex
	iface         string
	gatewayIP     string
	stateDir      string
	tcPath        string
	iptablesPath  string
	activeDevices map[string]*DeviceRule
	spoofProcs    map[string]*exec.Cmd
	qdiscReady    bool
	ready         bool
}

type DeviceRule struct {
	MAC        string
	IP         string
	SpeedLimit int
	ClassID    int
}

const (
	htbHandle       = "1:"
	defaultClass    = "1:10"
	defaultRate     = "1000mbit"
	firewallChain   = "NJANET_FWD"
	ruleOwnerManual = "njanet:manual"
	ruleOwnerSched  = "njanet:sched"
)

func New(iface, gatewayIP, stateDir string, preserveScheduled bool) *Controller {
	c := &Controller{
		iface:         iface,
		gatewayIP:     gatewayIP,
		stateDir:      stateDir,
		tcPath:        findExecutable("tc"),
		iptablesPath:  findExecutable("iptables"),
		activeDevices: make(map[string]*DeviceRule),
		spoofProcs:    make(map[string]*exec.Cmd),
	}
	c.ready = os.Geteuid() == 0 && c.iptablesPath != "" && c.stateDir != ""
	if c.ready {
		// The CLI-wide lock guarantees no other NjaNet mutation is running.
		// Any non-block spoof state left here is from a crashed session.
		if staleThrottle, _ := c.cleanupStaleSpoofs(preserveScheduled); staleThrottle {
			_ = c.removeQdisc()
		}
	}
	return c
}

func (c *Controller) IsReady() bool { return c.ready }

func (c *Controller) checkPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root required: run with sudo for block/throttle")
	}
	if c.iptablesPath == "" {
		return fmt.Errorf("iptables is required but was not found")
	}
	if c.stateDir == "" {
		return fmt.Errorf("state directory is not configured")
	}
	return nil
}

func findExecutable(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func runCommand(path string, args ...string) error {
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", filepath.Base(path), strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", filepath.Base(path), strings.Join(args, " "), err)
	}
	return nil
}

func (c *Controller) runTC(args ...string) error {
	return runCommand(c.tcPath, args...)
}

func (c *Controller) outputTC(args ...string) (string, error) {
	out, err := exec.Command(c.tcPath, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (c *Controller) runIPTables(args ...string) error {
	return runCommand(c.iptablesPath, append([]string{"-w", "5"}, args...)...)
}

func (c *Controller) iptablesRuleExists(args ...string) (bool, error) {
	cmd := exec.Command(c.iptablesPath, append([]string{"-w", "5"}, args...)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	msg := strings.TrimSpace(string(out))
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		// iptables uses exit 1 for "no such rule/chain"; other failures must
		// not be mistaken for an absent rule (unblock would falsely succeed).
		if msg == "" || strings.Contains(msg, "does a matching rule exist") ||
			strings.Contains(msg, "No chain/target/match") || strings.Contains(msg, "No chain") {
			return false, nil
		}
	}
	return false, fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, msg)
}

func (c *Controller) enableForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable IP forwarding: %w", err)
	}
	return nil
}

func (c *Controller) ensureQdisc() error {
	if c.tcPath == "" {
		return fmt.Errorf("tc not installed (iproute2 is required for throttle)")
	}
	if c.qdiscReady {
		return nil
	}
	out, err := c.outputTC("qdisc", "show", "dev", c.iface)
	if err != nil {
		return err
	}
	root := rootQdiscLine(out)
	if strings.Contains(root, "qdisc htb "+htbHandle) {
		// We are the sole owner (CLI-wide lock): clear stale classes/filters
		// left by a previous session before reusing the handle.
		if err := c.runTC("qdisc", "del", "dev", c.iface, "root"); err != nil {
			return err
		}
	} else if hasCustomQdisc(root) {
		return fmt.Errorf("refusing to replace an existing custom qdisc on %s; remove it manually first", c.iface)
	}

	if err := c.runTC("qdisc", "replace", "dev", c.iface,
		"root", "handle", htbHandle, "htb", "default", "10"); err != nil {
		return err
	}
	if err := c.runTC("class", "add", "dev", c.iface,
		"parent", htbHandle, "classid", defaultClass,
		"htb", "rate", defaultRate); err != nil {
		if err2 := c.runTC("class", "change", "dev", c.iface,
			"parent", htbHandle, "classid", defaultClass,
			"htb", "rate", defaultRate); err2 != nil {
			return errors.Join(err, err2)
		}
	}
	c.qdiscReady = true
	return nil
}

func rootQdiscLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " root") {
			return line
		}
	}
	return out
}

func hasCustomQdisc(out string) bool {
	for _, marker := range []string{
		"qdisc htb ", "qdisc hfsc ", "qdisc cbq ", "qdisc tbf ",
		"qdisc netem ", "qdisc cake ", "qdisc ingress ",
		"qdisc prio ", "qdisc mqprio ", "qdisc pfifo ",
	} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

func (c *Controller) removeQdisc() error {
	if c.tcPath == "" {
		return nil
	}
	out, err := c.outputTC("qdisc", "show", "dev", c.iface)
	if err != nil {
		return err
	}
	if !strings.Contains(rootQdiscLine(out), "qdisc htb "+htbHandle) {
		return nil
	}
	if err := c.runTC("qdisc", "del", "dev", c.iface, "root"); err != nil {
		return err
	}
	c.qdiscReady = false
	return nil
}

func (c *Controller) ThrottleDevice(dev *db.Device, speedKbps int) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	if dev == nil || dev.IP == "" {
		return fmt.Errorf("device IP is empty")
	}
	if speedKbps > 0 && dev.MAC == "" {
		return fmt.Errorf("device MAC is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	rule, hadRule := c.activeDevices[dev.MAC]
	if speedKbps <= 0 {
		target := dev.IP
		if hadRule && rule.IP != "" {
			target = rule.IP
		}
		spoofErr := c.stopSpoof(target, purposeThrottle)
		tcErr := c.removeThrottle(dev)
		if !c.hasActiveThrottleRules() {
			// Clears both this process's last class and stale classes from a
			// crashed session (safe: the CLI-wide lock guarantees sole owner).
			if err := c.removeQdisc(); err != nil {
				tcErr = errors.Join(tcErr, err)
			}
		}
		return errors.Join(spoofErr, tcErr)
	}

	if err := c.enableForwarding(); err != nil {
		return err
	}
	if err := c.ensureQdisc(); err != nil {
		return err
	}

	oldIP, oldClass := "", 0
	if hadRule {
		oldIP, oldClass = rule.IP, rule.ClassID
	}
	if oldIP != "" && oldIP != dev.IP {
		if err := c.stopSpoof(oldIP, purposeThrottle); err != nil {
			return fmt.Errorf("stop spoof for old IP %s: %w", oldIP, err)
		}
	}
	if err := c.startSpoof(dev.IP, purposeThrottle, dev.MAC); err != nil {
		return err
	}
	rollbackSpoof := func() {
		_ = c.stopSpoof(dev.IP, purposeThrottle)
	}

	rule = c.getOrCreateRule(dev)
	newClass := rule.ClassID == 0
	classID := rule.ClassID
	if classID == 0 {
		classID = c.nextClassID()
		rule.ClassID = classID
	}
	classStr := fmt.Sprintf("1:%d", classID)
	rate := fmt.Sprintf("%dkbit", speedKbps)
	burst := fmt.Sprintf("%dkbit", speedKbps/10)
	if speedKbps/10 < 4 {
		burst = "4kbit"
	}

	if oldIP != "" && oldIP != dev.IP && oldClass != 0 {
		c.delThrottleFilters(oldIP, fmt.Sprintf("1:%d", oldClass))
	}
	// Remove a possible duplicate from a failed/repeated application first.
	c.delThrottleFilters(dev.IP, classStr)

	if err := c.runTC("class", "add", "dev", c.iface,
		"parent", htbHandle, "classid", classStr,
		"htb", "rate", rate, "ceil", rate, "burst", burst); err != nil {
		if err2 := c.runTC("class", "change", "dev", c.iface,
			"parent", htbHandle, "classid", classStr,
			"htb", "rate", rate, "ceil", rate, "burst", burst); err2 != nil {
			if newClass {
				rule.ClassID = 0
			}
			rollbackSpoof()
			return errors.Join(err, err2)
		}
	}
	for _, dir := range []string{"dst", "src"} {
		if err := c.runTC("filter", "add", "dev", c.iface,
			"parent", htbHandle, "protocol", "ip", "prio", "1", "u32",
			"match", "ip", dir, dev.IP, "flowid", classStr); err != nil {
			c.delThrottleFilters(dev.IP, classStr)
			_ = c.runTC("class", "del", "dev", c.iface, "classid", classStr)
			rule.ClassID = 0
			rollbackSpoof()
			return err
		}
	}

	rule.SpeedLimit = speedKbps
	return nil
}

func (c *Controller) delThrottleFilters(ip, classStr string) {
	for _, dir := range []string{"dst", "src"} {
		_ = c.runTC("filter", "del", "dev", c.iface, "parent", htbHandle,
			"protocol", "ip", "prio", "1", "u32",
			"match", "ip", dir, ip, "flowid", classStr)
	}
}

func (c *Controller) tcClassExists(classStr string) bool {
	out, err := c.outputTC("class", "show", "dev", c.iface, "classid", classStr)
	return err == nil && strings.TrimSpace(out) != ""
}

func (c *Controller) hasActiveThrottleRules() bool {
	for _, r := range c.activeDevices {
		if r.ClassID > 0 {
			return true
		}
	}
	return false
}

func (c *Controller) removeThrottle(dev *db.Device) error {
	rule, ok := c.activeDevices[dev.MAC]
	if !ok || rule.ClassID == 0 {
		return nil
	}
	classStr := fmt.Sprintf("1:%d", rule.ClassID)
	ip := dev.IP
	if rule.IP != "" {
		ip = rule.IP
	}
	c.delThrottleFilters(ip, classStr)
	if c.tcClassExists(classStr) {
		if err := c.runTC("class", "del", "dev", c.iface, "classid", classStr); err != nil {
			return err
		}
	}
	rule.SpeedLimit = 0
	rule.ClassID = 0
	return nil
}

// BlockDevice installs a manual block. Manual and scheduler rules carry
// different iptables comments so one owner can never remove the other.
func (c *Controller) BlockDevice(dev *db.Device) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	if dev == nil || dev.IP == "" || dev.MAC == "" {
		return fmt.Errorf("device MAC/IP is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureChain(); err != nil {
		return err
	}
	if err := c.enableForwarding(); err != nil {
		return err
	}
	if err := c.startSpoof(dev.IP, purposeManualBlock, dev.MAC); err != nil {
		return err
	}
	if _, err := c.ensureChainRule("-d", dev.IP, ruleOwnerManual); err != nil {
		_ = c.stopSpoof(dev.IP, purposeManualBlock)
		return err
	}
	if _, err := c.ensureChainRule("-s", dev.IP, ruleOwnerManual); err != nil {
		_ = c.deleteChainRuleOwner("-d", dev.IP, ruleOwnerManual)
		_ = c.stopSpoof(dev.IP, purposeManualBlock)
		return err
	}
	return nil
}

// BlockDeviceScheduled installs the scheduler-owned drop rules. It is
// idempotent and never touches manual rules for the same IP.
func (c *Controller) BlockDeviceScheduled(dev *db.Device) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	if dev == nil || dev.IP == "" || dev.MAC == "" {
		return fmt.Errorf("device MAC/IP is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureChain(); err != nil {
		return err
	}
	if err := c.enableForwarding(); err != nil {
		return err
	}
	if err := c.startSpoof(dev.IP, purposeSchedBlock, dev.MAC); err != nil {
		return err
	}
	if _, err := c.ensureChainRule("-d", dev.IP, ruleOwnerSched); err != nil {
		_ = c.stopSpoof(dev.IP, purposeSchedBlock)
		return err
	}
	if _, err := c.ensureChainRule("-s", dev.IP, ruleOwnerSched); err != nil {
		_ = c.deleteChainRuleOwner("-d", dev.IP, ruleOwnerSched)
		_ = c.stopSpoof(dev.IP, purposeSchedBlock)
		return err
	}
	return nil
}

func (c *Controller) UnblockDevice(dev *db.Device) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	if dev == nil || dev.IP == "" {
		return fmt.Errorf("device IP is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ruleErr := c.deleteChainRules(dev.IP)
	legacyErr := c.removeLegacyForwardDropRules(dev.IP)
	manualErr := c.stopSpoof(dev.IP, purposeManualBlock)
	schedErr := c.stopSpoof(dev.IP, purposeSchedBlock)
	return errors.Join(ruleErr, legacyErr, manualErr, schedErr)
}

// ManualBlockRulesExist reports whether manual or legacy (no-comment) drop
// rules exist for an IP. Used to preserve the DB blocked flag when a
// scheduler-owned rule is removed.
func (c *Controller) ManualBlockRulesExist(ip string) bool {
	if c.iptablesPath == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blockRulesExist(ip, ruleOwnerManual) || c.blockRulesExist(ip, "")
}

// UnblockScheduled removes only scheduler-owned rules and the scheduler spoof
// purpose. A manual block at the same IP remains untouched.
func (c *Controller) UnblockScheduled(dev *db.Device) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	if dev == nil || dev.IP == "" {
		return fmt.Errorf("device IP is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ruleErr := c.deleteChainRulesOwner(dev.IP, ruleOwnerSched)
	spoofErr := c.stopSpoof(dev.IP, purposeSchedBlock)
	return errors.Join(ruleErr, spoofErr)
}

func (c *Controller) ensureChain() error {
	exists, err := c.iptablesRuleExists("-S", firewallChain)
	if err != nil {
		return err
	}
	if !exists {
		if err := c.runIPTables("-N", firewallChain); err != nil {
			return fmt.Errorf("create firewall chain: %w", err)
		}
	}
	exists, err = c.iptablesRuleExists("-C", "FORWARD", "-j", firewallChain)
	if err != nil {
		return err
	}
	if !exists {
		if err := c.runIPTables("-I", "FORWARD", "1", "-j", firewallChain); err != nil {
			return fmt.Errorf("attach firewall chain: %w", err)
		}
	}
	return nil
}

func chainRuleArgs(action, dir, ip, owner string) []string {
	args := []string{action, firewallChain, dir, ip}
	if owner != "" {
		args = append(args, "-m", "comment", "--comment", owner)
	}
	return append(args, "-j", "DROP")
}

func (c *Controller) ensureChainRule(dir, ip, owner string) (bool, error) {
	exists, err := c.iptablesRuleExists(chainRuleArgs("-C", dir, ip, owner)...)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := c.runIPTables(chainRuleArgs("-A", dir, ip, owner)...); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Controller) deleteChainRuleOwner(dir, ip, owner string) error {
	exists, err := c.iptablesRuleExists(chainRuleArgs("-C", dir, ip, owner)...)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return c.runIPTables(chainRuleArgs("-D", dir, ip, owner)...)
}

func (c *Controller) blockRulesExist(ip, owner string) bool {
	if c.iptablesPath == "" {
		return false
	}
	dst, err := c.iptablesRuleExists(chainRuleArgs("-C", "-d", ip, owner)...)
	if err != nil || !dst {
		return false
	}
	src, err := c.iptablesRuleExists(chainRuleArgs("-C", "-s", ip, owner)...)
	return err == nil && src
}

// ScheduledBlockActive reports whether the scheduler still owns a live block
// for this MAC/IP. Manual rules are intentionally ignored.
func (c *Controller) ScheduledBlockActive(mac, ip string) bool {
	if c.stateDir == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.blockRulesExist(ip, ruleOwnerSched) {
		return false
	}
	st, err := loadSpoofState(c.spoofStatePath(ip))
	if err != nil {
		return false
	}
	return st.Iface == c.iface && st.Target == ip &&
		(st.MAC == "" || strings.EqualFold(st.MAC, mac)) &&
		hasPurpose(st, purposeSchedBlock) && spoofStateAlive(st)
}

func (c *Controller) deleteChainRulesOwner(ip, owner string) error {
	var errs []error
	for _, dir := range []string{"-d", "-s"} {
		for i := 0; i < 64; i++ {
			exists, err := c.iptablesRuleExists(chainRuleArgs("-C", dir, ip, owner)...)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if !exists {
				break
			}
			if err := c.runIPTables(chainRuleArgs("-D", dir, ip, owner)...); err != nil {
				errs = append(errs, err)
				break
			}
		}
	}
	return errors.Join(errs...)
}

// deleteChainRules removes manual, scheduler, and legacy (no-comment) rules
// for an IP. Used only by explicit user unblock/reset paths.
func (c *Controller) deleteChainRules(ip string) error {
	var errs []error
	for _, owner := range []string{ruleOwnerManual, ruleOwnerSched, ""} {
		if err := c.deleteChainRulesOwner(ip, owner); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RemoveForwardDropRules removes legacy rules created by older versions in
// the FORWARD chain. New rules live in the dedicated NJANET chain.
func (c *Controller) RemoveForwardDropRules(ip string) error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removeLegacyForwardDropRules(ip)
}

func (c *Controller) removeLegacyForwardDropRules(ip string) error {
	var errs []error
	for _, dir := range []string{"-d", "-s"} {
		for i := 0; i < 64; i++ {
			exists, err := c.iptablesRuleExists("-C", "FORWARD", dir, ip, "-j", "DROP")
			if err != nil {
				errs = append(errs, err)
				break
			}
			if !exists {
				break
			}
			if err := c.runIPTables("-D", "FORWARD", dir, ip, "-j", "DROP"); err != nil {
				errs = append(errs, err)
				break
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) Reset() error {
	if err := c.checkPrivileges(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	errs := []error{
		c.removeQdisc(),
		c.cleanupFirewall(),
		c.stopAllSpoofs(),
	}
	c.activeDevices = make(map[string]*DeviceRule)
	return errors.Join(errs...)
}

func (c *Controller) cleanupFirewall() error {
	var errs []error
	for i := 0; i < 64; i++ {
		exists, err := c.iptablesRuleExists("-C", "FORWARD", "-j", firewallChain)
		if err != nil {
			errs = append(errs, err)
			break
		}
		if !exists {
			break
		}
		if err := c.runIPTables("-D", "FORWARD", "-j", firewallChain); err != nil {
			errs = append(errs, err)
			break
		}
	}
	exists, err := c.iptablesRuleExists("-S", firewallChain)
	if err != nil {
		errs = append(errs, err)
	} else if exists {
		if err := c.runIPTables("-F", firewallChain); err != nil {
			errs = append(errs, err)
		}
		if err := c.runIPTables("-X", firewallChain); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) getOrCreateRule(dev *db.Device) *DeviceRule {
	if rule, ok := c.activeDevices[dev.MAC]; ok {
		rule.IP = dev.IP
		return rule
	}
	rule := &DeviceRule{MAC: dev.MAC, IP: dev.IP}
	c.activeDevices[dev.MAC] = rule
	return rule
}

func (c *Controller) nextClassID() int {
	used := make(map[int]bool)
	for _, r := range c.activeDevices {
		if r.ClassID > 0 {
			used[r.ClassID] = true
		}
	}
	for id := 11; id < 100; id++ {
		if !used[id] {
			return id
		}
	}
	return 99
}
