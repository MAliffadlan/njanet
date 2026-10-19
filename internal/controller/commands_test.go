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
	if err := c.startSpoof("127.0.0.2", purposeThrottle); err == nil {
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
	if err := c.startSpoof("127.0.0.2", purposeThrottle); err == nil {
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

func TestEnsureChainRulePropagatesFailure(t *testing.T) {
	script := fakeTool(t, "iptables", "exit 1\n")
	c := &Controller{iptablesPath: script, stateDir: t.TempDir()}
	if err := c.ensureChainRule("-d", "192.168.1.5"); err == nil {
		t.Fatal("expected iptables failure to propagate")
	}
}
