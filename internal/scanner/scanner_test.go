package scanner

import (
	"net"
	"testing"
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
