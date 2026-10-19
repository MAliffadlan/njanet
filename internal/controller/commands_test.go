package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fakeTool(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStartSpoofFailsCleanlyWhenSpawnFails(t *testing.T) {
	dir := t.TempDir()
	// A mode-0755 file without a valid executable format makes Start() fail,
	// exercising the path that used to leave a nil Process in spoofProcs.
	bad := filepath.Join(dir, "arpspoof")
	if err := os.WriteFile(bad, []byte("not an executable format"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	c := &Controller{
		iface:         "lo",
		gatewayIP:     "127.0.0.1",
		stateDir:      t.TempDir(),
		spoofProcs:    make(map[string]*exec.Cmd),
		activeDevices: make(map[string]*DeviceRule),
	}
	if err := c.startSpoof("127.0.0.2", purposeThrottle, "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Fatal("expected spawn failure")
	}
	if len(c.spoofProcs) != 0 {
		t.Fatalf("failed start left processes in map: %d", len(c.spoofProcs))
	}
	if _, err := os.Stat(c.spoofStatePath("127.0.0.2")); !os.IsNotExist(err) {
		t.Fatalf("failed start left a state file: %v", err)
	}
}

func TestStartSpoofRejectsImmediateExit(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "arpspoof")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	c := &Controller{
		iface:         "lo",
		gatewayIP:     "127.0.0.1",
		stateDir:      t.TempDir(),
		spoofProcs:    make(map[string]*exec.Cmd),
		activeDevices: make(map[string]*DeviceRule),
	}
	if err := c.startSpoof("127.0.0.2", purposeThrottle, "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Fatal("expected immediately-exiting spoof to fail")
	}
	if len(c.spoofProcs) != 0 {
		t.Fatalf("failed start left processes in map: %d", len(c.spoofProcs))
	}
	if _, err := os.Stat(c.spoofStatePath("127.0.0.2")); !os.IsNotExist(err) {
		t.Fatalf("failed start left a state file: %v", err)
	}
}

func TestEnsureChainBuildsDedicatedChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	t.Setenv("IPT_LOG", logPath)
	script := fakeTool(t, "iptables", `echo "$*" >> "$IPT_LOG"
case "$*" in
  *"-S `+firewallChain+`"*) exit 1 ;;
  *"-C FORWARD -j `+firewallChain+`"*) exit 1 ;;
  *) exit 0 ;;
esac
`)
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if err := c.ensureChain(); err != nil {
		t.Fatalf("ensureChain: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, want := range []string{
		"-w 5 -N " + firewallChain,
		"-w 5 -I FORWARD 1 -j " + firewallChain,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("iptables log missing %q:\n%s", want, log)
		}
	}
}

func TestEnsureChainRuleReportsOwnership(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	t.Setenv("IPT_LOG", logPath)

	existing := fakeTool(t, "iptables", `echo "$*" >> "$IPT_LOG"
case "$*" in
  *"-C `+firewallChain+`"*) exit 0 ;;
  *) exit 0 ;;
esac
`)
	c := &Controller{iptablesPath: existing, stateDir: t.TempDir()}
	added, err := c.ensureChainRule("-d", "192.168.1.5", ruleOwnerManual)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("pre-existing rule reported as newly added")
	}
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), "-A ") {
		t.Fatalf("existing rule was added again:\n%s", data)
	}

	missing := fakeTool(t, "iptables", `echo "$*" >> "$IPT_LOG"
case "$*" in
  *"-C `+firewallChain+`"*) exit 1 ;;
  *) exit 0 ;;
esac
`)
	c.iptablesPath = missing
	added, err = c.ensureChainRule("-d", "192.168.1.5", ruleOwnerManual)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("newly added rule not reported as owned")
	}
	data, _ = os.ReadFile(logPath)
	if !strings.Contains(string(data), "--comment "+ruleOwnerManual) {
		t.Fatalf("rule owner comment missing:\n%s", data)
	}
}

func TestBlockRulesExistForOwner(t *testing.T) {
	yes := fakeTool(t, "iptables", "exit 0\n")
	c := &Controller{iptablesPath: yes, stateDir: t.TempDir()}
	if !c.blockRulesExist("192.168.1.5", ruleOwnerSched) {
		t.Fatal("blockRulesExist = false when both rules exist")
	}
	no := fakeTool(t, "iptables", "exit 1\n")
	c.iptablesPath = no
	if c.blockRulesExist("192.168.1.5", ruleOwnerSched) {
		t.Fatal("blockRulesExist = true when rules are absent")
	}
}

func TestScheduledBlockActiveRequiresLiveSpoof(t *testing.T) {
	yes := fakeTool(t, "iptables", "exit 0\n")
	c := &Controller{
		iface:         "eth0",
		iptablesPath:  yes,
		stateDir:      t.TempDir(),
		activeDevices: make(map[string]*DeviceRule),
		spoofProcs:    make(map[string]*exec.Cmd),
	}
	if c.ScheduledBlockActive("AA:BB:CC:DD:EE:FF", "192.168.1.5") {
		t.Fatal("chain rules without a live scheduled spoof reported as active")
	}
}

func TestDeleteChainRuleOwnerIsScoped(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	t.Setenv("IPT_LOG", logPath)
	script := fakeTool(t, "iptables", `echo "$*" >> "$IPT_LOG"
exit 0
`)
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if err := c.deleteChainRuleOwner("-d", "192.168.1.5", ruleOwnerSched); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	if !strings.Contains(log, "--comment "+ruleOwnerSched) {
		t.Fatalf("scheduled owner comment missing:\n%s", log)
	}
	if strings.Contains(log, ruleOwnerManual) {
		t.Fatalf("manual owner was touched:\n%s", log)
	}
}

func TestDeleteChainRuleOwnerPropagatesIptablesError(t *testing.T) {
	script := fakeTool(t, "iptables", "exit 4\n")
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if err := c.deleteChainRuleOwner("-d", "192.168.1.5", ruleOwnerSched); err == nil {
		t.Fatal("iptables exit 4 was treated as rule absent")
	}
}

func TestManualBlockRulesExistIncludesLegacy(t *testing.T) {
	script := fakeTool(t, "iptables", `case "$*" in
  *"--comment `+ruleOwnerManual+`"*) exit 1 ;;
  *) exit 0 ;;
esac
`)
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if !c.ManualBlockRulesExist("192.168.1.5") {
		t.Fatal("legacy no-comment manual rule not recognized")
	}
	none := fakeTool(t, "iptables", "exit 1\n")
	c.iptablesPath = none
	if c.ManualBlockRulesExist("192.168.1.5") {
		t.Fatal("rules reported when none exist")
	}
}

func TestEnsureChainRulePropagatesFailure(t *testing.T) {
	script := fakeTool(t, "iptables", "exit 1\n")
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if _, err := c.ensureChainRule("-d", "192.168.1.5", ruleOwnerManual); err == nil {
		t.Fatal("expected iptables failure to propagate")
	}
}
