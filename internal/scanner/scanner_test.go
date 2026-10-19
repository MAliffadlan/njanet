package scanner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/mectov/njanet/internal/db"
)

func testScanner(cidr, myIP string) *Scanner {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return &Scanner{myIP: net.ParseIP(myIP), subnet: subnet}
}

func TestHostAddrsSlash24(t *testing.T) {
	s := testScanner("192.168.1.0/24", "192.168.1.10")
	ips := s.hostAddrs(1024)
	if len(ips) != 255 {
		t.Fatalf("got %d hosts, want 255", len(ips))
	}
	seen := make(map[string]bool)
	for _, ip := range ips {
		if !s.subnet.Contains(ip) {
			t.Errorf("%s outside subnet", ip)
		}
		if ip.Equal(s.myIP) {
			t.Errorf("own IP %s included", ip)
		}
		seen[ip.String()] = true
	}
	if !seen["192.168.1.1"] || !seen["192.168.1.254"] {
		t.Error("expected edge hosts missing")
	}
}

func TestHostAddrsNonSlash24(t *testing.T) {
	// /23 spans two third-octet ranges — the old ip[3]-only math broke here.
	s := testScanner("192.168.0.0/23", "192.168.0.5")
	ips := s.hostAddrs(1024)
	if len(ips) != 511 {
		t.Fatalf("got %d hosts, want 511", len(ips))
	}
	seen := make(map[string]bool)
	for _, ip := range ips {
		if !s.subnet.Contains(ip) {
			t.Errorf("%s outside /23 subnet", ip)
		}
		seen[ip.String()] = true
	}
	for _, want := range []string{"192.168.0.1", "192.168.0.255", "192.168.1.0", "192.168.1.254"} {
		if !seen[want] {
			t.Errorf("expected host %s missing", want)
		}
	}
}

func TestHostAddrsLimit(t *testing.T) {
	s := testScanner("10.0.0.0/16", "10.0.0.1")
	ips := s.hostAddrs(512)
	// 512 addresses scanned, minus our own IP.
	if len(ips) != 511 {
		t.Fatalf("got %d hosts, want capped 511", len(ips))
	}
}

func TestNetworkHostsRespectsSubnet(t *testing.T) {
	s := testScanner("192.168.7.0/24", "192.168.7.77")
	for _, ip := range s.networkHosts() {
		if !s.subnet.Contains(ip) {
			t.Fatalf("%s outside subnet", ip)
		}
	}
}

func TestNmapGreppableParsing(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "nmap")
	script := `#!/bin/sh
printf 'Host: 192.168.1.5\tStatus: Up\n'
printf 'Host: 192.168.1.6 (phone.lan)\tStatus: Up\tMAC Address: 11:22:33:44:55:66 (Acme)\n'
printf 'Host: 192.168.1.7\tStatus: Up\tMAC Address: AA:BB:CC:DD:EE:FF (Vendor)\n'
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := testScanner("192.168.1.0/24", "192.168.1.10")
	s.ouiDB = map[string]string{"112233": "Acme", "AABBCC": "Vendor"}

	devices, err := s.nmapARPScan(context.Background(), fake)
	if err != nil {
		t.Fatalf("nmapARPScan: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2 (host without MAC must be skipped)", len(devices))
	}
	got := make(map[string]*db.Device)
	for _, d := range devices {
		got[d.IP] = d
	}
	if d := got["192.168.1.6"]; d == nil || d.MAC != "11:22:33:44:55:66" || d.Hostname != "phone.lan" {
		t.Errorf("named host parsed as %+v", d)
	}
	if d := got["192.168.1.7"]; d == nil || d.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("unnamed host parsed as %+v", d)
	}
}

func TestDetectWirelessEmptyMAC(t *testing.T) {
	s := &Scanner{}
	if s.detectWireless("") {
		t.Fatal("empty MAC must not be reported as wireless")
	}
	if s.detectWireless("AA:BB") {
		t.Fatal("short MAC must not be reported as wireless")
	}
}
