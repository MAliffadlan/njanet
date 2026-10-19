package db

import (
	"os"
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *Database {
	t.Helper()
	d, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestMigrateCreatesTables(t *testing.T) {
	d := openTestDB(t)
	for _, table := range []string{"devices", "scan_history", "protected_ips", "watchlist", "schedules"} {
		var name string
		err := d.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

func TestUpsertDevice(t *testing.T) {
	d := openTestDB(t)

	if _, err := d.UpsertDevice(&Device{IP: "192.168.1.8", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "hp", Vendor: "Xiaomi", Online: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	devices, err := d.GetAllDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("GetAllDevices = %d, %v; want 1, nil", len(devices), err)
	}

	// Upsert MAC yang sama = update, bukan baris baru. IP ikut baru,
	// hostname/vendor lama dipertahankan bila yang baru kosong.
	if _, err := d.UpsertDevice(&Device{IP: "192.168.1.9", MAC: "AA:BB:CC:DD:EE:FF"}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	devices, _ = d.GetAllDevices()
	if len(devices) != 1 {
		t.Fatalf("after re-upsert got %d rows, want 1", len(devices))
	}
	got := devices[0]
	if got.IP != "192.168.1.9" {
		t.Errorf("IP = %q, want 192.168.1.9", got.IP)
	}
	if got.Hostname != "hp" || got.Vendor != "Xiaomi" {
		t.Errorf("hostname/vendor overwritten: %q/%q", got.Hostname, got.Vendor)
	}

	if err := d.UpdateDeviceBlock(got.MAC, true); err != nil {
		t.Fatalf("UpdateDeviceBlock: %v", err)
	}
	if err := d.UpdateDeviceSpeed(got.MAC, 64); err != nil {
		t.Fatalf("UpdateDeviceSpeed: %v", err)
	}
	devices, _ = d.GetAllDevices()
	if !devices[0].Blocked || devices[0].SpeedLimit != 64 {
		t.Errorf("flags not persisted: %+v", devices[0])
	}
}

func TestScanHistory(t *testing.T) {
	d := openTestDB(t)

	if _, _, _, ok := d.GetLatestScan(); ok {
		t.Fatal("GetLatestScan should report empty before any scan")
	}
	if err := d.LogScan(10, 7); err != nil {
		t.Fatalf("LogScan: %v", err)
	}
	if err := d.LogScan(12, 9); err != nil {
		t.Fatalf("LogScan: %v", err)
	}
	total, online, at, ok := d.GetLatestScan()
	if !ok {
		t.Fatal("GetLatestScan should report data after logging")
	}
	if total != 12 || online != 9 {
		t.Errorf("latest = (%d,%d), want (12,9)", total, online)
	}
	if at.IsZero() {
		t.Error("scan timestamp not parsed")
	}
}

func TestSchedules(t *testing.T) {
	d := openTestDB(t)

	id, err := d.AddSchedule("AA:BB:CC:DD:EE:FF", "192.168.1.8", "block", 0, 0, 360, "*")
	if err != nil || id == 0 {
		t.Fatalf("AddSchedule: id=%d, err=%v", id, err)
	}
	list, err := d.GetSchedules()
	if err != nil || len(list) != 1 {
		t.Fatalf("GetSchedules = %d, %v; want 1, nil", len(list), err)
	}
	if list[0].Action != "block" || list[0].EndMin != 360 {
		t.Errorf("schedule mismatch: %+v", list[0])
	}

	if err := d.UpdateScheduleIP("AA:BB:CC:DD:EE:FF", "192.168.1.20"); err != nil {
		t.Fatalf("UpdateScheduleIP: %v", err)
	}
	list, _ = d.GetSchedules()
	if list[0].IP != "192.168.1.20" {
		t.Errorf("IP = %q, want 192.168.1.20", list[0].IP)
	}

	ok, err := d.RemoveScheduleByID(999)
	if err != nil || ok {
		t.Errorf("RemoveScheduleByID(999) = (%v,%v), want (false,nil)", ok, err)
	}
	ok, err = d.RemoveScheduleByMAC("AA:BB:CC:DD:EE:FF")
	if err != nil || !ok {
		t.Errorf("RemoveScheduleByMAC = (%v,%v), want (true,nil)", ok, err)
	}
	list, _ = d.GetSchedules()
	if len(list) != 0 {
		t.Errorf("after remove got %d schedules, want 0", len(list))
	}
}

func TestDatabaseFilesArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	dbPath := filepath.Join(dir, "njanet.db")
	d, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir mode = %o, want 700", perm)
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, perm)
		}
	}
}

func TestRefusesSymlinkedDatabase(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "njanet.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link); err == nil {
		t.Fatal("New accepted a symlinked database")
	}
}

func TestSecureStateFilesRefusesSymlinkSidecar(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "njanet.db")
	if err := os.WriteFile(dbPath, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, dbPath+"-wal"); err != nil {
		t.Fatal(err)
	}
	if err := secureStateFiles(dbPath, nil); err == nil {
		t.Fatal("secureStateFiles accepted a symlinked sidecar")
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("symlink target modified: %q", data)
	}
}

func TestRemoveSchedulesByIP(t *testing.T) {
	d := openTestDB(t)
	if _, err := d.AddSchedule("AA:BB:CC:DD:EE:FF", "192.168.1.5", "block", 0, 0, 60, "*"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddSchedule("11:22:33:44:55:66", "192.168.1.6", "block", 0, 0, 60, "*"); err != nil {
		t.Fatal(err)
	}
	ok, err := d.RemoveSchedulesByIP("192.168.1.5")
	if err != nil || !ok {
		t.Fatalf("RemoveSchedulesByIP = (%v,%v), want (true,nil)", ok, err)
	}
	list, err := d.GetSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].MAC != "11:22:33:44:55:66" {
		t.Fatalf("wrong rows removed: %+v", list)
	}
	ok, err = d.RemoveSchedulesByIP("192.168.1.99")
	if err != nil || ok {
		t.Fatalf("missing IP = (%v,%v), want (false,nil)", ok, err)
	}
}

func TestProtectedAndWatch(t *testing.T) {
	d := openTestDB(t)

	if err := d.AddProtectedMAC("AA:BB:CC:DD:EE:FF", "Server"); err != nil {
		t.Fatalf("AddProtectedMAC: %v", err)
	}
	macs, err := d.GetProtectedMACs()
	if err != nil || len(macs) != 1 || macs[0] != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("GetProtectedMACs = %v, %v", macs, err)
	}
	if err := d.RemoveProtectedMAC("AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatalf("RemoveProtectedMAC: %v", err)
	}

	if err := d.AddWatch("AA:BB:CC:DD:EE:FF", "192.168.1.8", "throttle", 64, false); err != nil {
		t.Fatalf("AddWatch: %v", err)
	}
	watch, err := d.GetWatchlist()
	if err != nil || len(watch) != 1 || watch[0].SpeedKbps != 64 {
		t.Fatalf("GetWatchlist = %+v, %v", watch, err)
	}
	if err := d.DeactivateWatch("AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatalf("DeactivateWatch: %v", err)
	}
	watch, _ = d.GetWatchlist()
	if len(watch) != 0 {
		t.Errorf("after deactivate got %d entries, want 0", len(watch))
	}
}
