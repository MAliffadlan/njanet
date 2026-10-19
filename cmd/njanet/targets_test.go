package main

import (
	"path/filepath"
	"testing"

	"github.com/mectov/njanet/internal/db"
)

func testTargetDB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestResolveLiveTargetMACUsesARPOverStaleDB(t *testing.T) {
	d := testTargetDB(t)
	if _, err := d.UpsertDevice(&db.Device{
		MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.1.50", Online: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDeviceNickname("AA:BB:CC:DD:EE:FF", "phone"); err != nil {
		t.Fatal(err)
	}
	entries := []arpEntry{{IP: "192.168.1.60", MAC: "AA:BB:CC:DD:EE:FF"}}

	dev, err := resolveLiveTarget("aa:bb:cc:dd:ee:ff", d, entries)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if dev.IP != "192.168.1.60" || dev.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("dev = %+v", dev)
	}
	if dev.Nickname != "phone" {
		t.Errorf("nickname lost: %q", dev.Nickname)
	}

	devices, err := d.GetAllDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("GetAllDevices = %d, %v", len(devices), err)
	}
	if devices[0].IP != "192.168.1.60" {
		t.Errorf("DB IP = %q, want 192.168.1.60", devices[0].IP)
	}
}

func TestResolveLiveTargetIPUsesLiveMAC(t *testing.T) {
	d := testTargetDB(t)
	if _, err := d.UpsertDevice(&db.Device{
		MAC: "00:00:00:00:00:01", IP: "192.168.1.60", Online: true,
	}); err != nil {
		t.Fatal(err)
	}
	entries := []arpEntry{{IP: "192.168.1.60", MAC: "AA:BB:CC:DD:EE:FF"}}

	dev, err := resolveLiveTarget("192.168.1.60", d, entries)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if dev.MAC != "AA:BB:CC:DD:EE:FF" || dev.IP != "192.168.1.60" {
		t.Fatalf("dev = %+v", dev)
	}
	devices, _ := d.GetAllDevices()
	found := false
	for _, got := range devices {
		if got.MAC == "AA:BB:CC:DD:EE:FF" && got.IP == "192.168.1.60" {
			found = true
		}
	}
	if !found {
		t.Fatalf("live MAC was not upserted: %+v", devices)
	}
}

func TestFindVerifiedDeviceByMACRejectsReusedIP(t *testing.T) {
	d := testTargetDB(t)
	if _, err := d.UpsertDevice(&db.Device{
		MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.1.50", Online: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := findVerifiedDeviceByMAC(d, "AA:BB:CC:DD:EE:FF", []arpEntry{
		{IP: "192.168.1.50", MAC: "11:22:33:44:55:66"},
	}); got != nil {
		t.Fatalf("reused IP accepted as the stored MAC: %+v", got)
	}
	if got := findVerifiedDeviceByMAC(d, "AA:BB:CC:DD:EE:FF", []arpEntry{
		{IP: "192.168.1.50", MAC: "AA:BB:CC:DD:EE:FF"},
	}); got == nil {
		t.Fatal("live matching IP/MAC rejected")
	}
}

func TestResolveLiveTargetRejectsOfflineTarget(t *testing.T) {
	d := testTargetDB(t)
	if _, err := resolveLiveTarget("192.168.1.99", d, nil); err == nil {
		t.Fatal("offline IP target accepted")
	}
	if _, err := resolveLiveTarget("AA:BB:CC:DD:EE:FF", d, nil); err == nil {
		t.Fatal("offline MAC target accepted")
	}
}
