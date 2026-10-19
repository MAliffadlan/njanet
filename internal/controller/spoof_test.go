package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoofStateRoundTrip(t *testing.T) {
	c := &Controller{iface: "eth0", stateDir: t.TempDir()}
	st := &spoofState{
		Iface:    "eth0",
		Target:   "192.168.1.5",
		Kind:     "arpspoof",
		PIDs:     []int{999999, 999998},
		Purposes: []string{purposeThrottle},
	}
	path := c.spoofStatePath("192.168.1.5")
	if err := saveSpoofState(path, st); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %o, want 600", perm)
	}

	got, err := loadSpoofState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Target != st.Target || got.Kind != st.Kind || len(got.PIDs) != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !hasPurpose(got, purposeThrottle) {
		t.Fatal("throttle purpose lost")
	}
	if !addPurpose(got, purposeBlock) {
		t.Fatal("block purpose should be added")
	}
	if addPurpose(got, purposeBlock) {
		t.Fatal("duplicate block purpose was added")
	}
	removePurpose(got, purposeThrottle)
	if hasPurpose(got, purposeThrottle) || !hasPurpose(got, purposeBlock) {
		t.Fatalf("purpose removal wrong: %+v", got.Purposes)
	}
}

func TestCleanupStaleSpoofs(t *testing.T) {
	c := &Controller{iface: "eth0", stateDir: t.TempDir()}
	st := &spoofState{
		Iface:    "eth0",
		Target:   "192.168.1.5",
		Kind:     "arpspoof",
		PIDs:     []int{999999, 999998}, // not running
		Purposes: []string{purposeThrottle},
	}
	path := c.spoofStatePath(st.Target)
	if err := saveSpoofState(path, st); err != nil {
		t.Fatal(err)
	}
	stale, err := c.cleanupStaleSpoofs()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !stale {
		t.Fatal("stale throttle state not reported")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale throttle state still exists: %v", err)
	}
}

func TestRootQdiscDetection(t *testing.T) {
	out := "qdisc ingress ffff: parent ffff:fff1\nqdisc fq_codel 0: root refcnt 2 limit 10240p"
	root := rootQdiscLine(out)
	if !strings.Contains(root, "fq_codel") {
		t.Fatalf("root line = %q", root)
	}
	if hasCustomQdisc(root) {
		t.Fatal("fq_codel must not be treated as custom")
	}
	if !hasCustomQdisc("qdisc htb 2: root refcnt 2") {
		t.Fatal("foreign HTB must be treated as custom")
	}
	ours := rootQdiscLine("qdisc htb 1: root refcnt 2\ngdisc ingress ffff:")
	if !strings.Contains(ours, "qdisc htb "+htbHandle) {
		t.Fatalf("our HTB root not detected: %q", ours)
	}
}

func TestNormalizeMAC(t *testing.T) {
	for _, in := range []string{"aa:bb:cc:dd:ee:ff", " AA:BB:CC:DD:EE:FF "} {
		if got := normalizeMAC(in); got != "AA:BB:CC:DD:EE:FF" {
			t.Errorf("normalizeMAC(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:GG", "AA-BB-CC-DD-EE-FF"} {
		if got := normalizeMAC(in); got != "" {
			t.Errorf("normalizeMAC(%q) = %q, want empty", in, got)
		}
	}
}

func TestSpoofStatePathIsStable(t *testing.T) {
	dir := t.TempDir()
	a := &Controller{iface: "eth0", stateDir: dir}
	b := &Controller{iface: "eth0", stateDir: dir}
	if a.spoofStatePath("192.168.1.5") != b.spoofStatePath("192.168.1.5") {
		t.Fatal("state path must be stable")
	}
	if a.spoofStatePath("192.168.1.5") == a.spoofStatePath("192.168.1.6") {
		t.Fatal("state paths must differ per target")
	}
	if filepath.Dir(a.spoofStatePath("192.168.1.5")) != dir {
		t.Fatal("state path outside state dir")
	}
}
