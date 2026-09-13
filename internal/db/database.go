package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	*sql.DB
	path string
}

func New(path string) (*Database, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	d := &Database{DB: db, path: path}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		mac TEXT NOT NULL UNIQUE,
		hostname TEXT DEFAULT '',
		vendor TEXT DEFAULT '',
		device_type TEXT DEFAULT 'unknown',
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		online BOOLEAN DEFAULT 1,
		signal INTEGER DEFAULT 0,
		rssi INTEGER DEFAULT 0,
		traffic_in INTEGER DEFAULT 0,
		traffic_out INTEGER DEFAULT 0,
		blocked BOOLEAN DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		priority INTEGER DEFAULT 3,
		nickname TEXT DEFAULT '',
		is_wireless BOOLEAN DEFAULT 0,
		open_ports TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
	CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(online);

	CREATE TABLE IF NOT EXISTS scan_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_devices INTEGER DEFAULT 0,
		online_devices INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS protected_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		label TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
		CREATE TABLE IF NOT EXISTS watchlist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT NOT NULL,
		ip TEXT NOT NULL,
		rule_type TEXT NOT NULL DEFAULT 'throttle',
		speed_kbps INTEGER DEFAULT 0,
		blocked BOOLEAN DEFAULT 0,
		active BOOLEAN DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS schedules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT NOT NULL,
		ip TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT 'block',
		speed_kbps INTEGER DEFAULT 0,
		start_min INTEGER NOT NULL DEFAULT 0,
		end_min INTEGER NOT NULL DEFAULT 0,
		days TEXT NOT NULL DEFAULT '*',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_schedules_mac ON schedules(mac);

	`
	if _, err := d.Exec(schema); err != nil {
		return err
	}

	// Older databases were created without a UNIQUE constraint on watchlist.mac,
	// which made AddWatch's INSERT OR REPLACE insert duplicate rows. Dedupe and index.
	if _, err := d.Exec(`DELETE FROM watchlist WHERE id NOT IN (SELECT MIN(id) FROM watchlist GROUP BY mac)`); err != nil {
		return err
	}
	_, err := d.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_watchlist_mac ON watchlist(mac)`)
	return err
}

// --- Device CRUD ---

func (d *Database) UpsertDevice(dev *Device) (int64, error) {
	now := time.Now()
	query := `
	INSERT INTO devices (ip, mac, hostname, vendor, device_type, first_seen, last_seen, online, signal, rssi, is_wireless)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		ip = excluded.ip,
		hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
		vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE vendor END,
		last_seen = excluded.last_seen,
		online = excluded.online,
		signal = CASE WHEN excluded.signal > 0 THEN excluded.signal ELSE signal END,
		rssi = CASE WHEN excluded.rssi != 0 THEN excluded.rssi ELSE rssi END
	RETURNING id`

	var id int64
	err := d.QueryRow(query,
		dev.IP, dev.MAC, dev.Hostname, dev.Vendor, dev.DeviceType,
		now, now, dev.Online, dev.Signal, dev.RSSI, dev.IsWireless,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert device: %w", err)
	}
	return id, nil
}

func (d *Database) GetAllDevices() ([]*Device, error) {
	rows, err := d.Query(`
		SELECT id, ip, mac, hostname, vendor, device_type,
			first_seen, last_seen, online, signal, rssi,
			traffic_in, traffic_out, blocked, speed_limit,
			priority, nickname, is_wireless, open_ports
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		dev := &Device{}
		var firstSeen, lastSeen string
		var openPorts string
		err := rows.Scan(&dev.ID, &dev.IP, &dev.MAC, &dev.Hostname, &dev.Vendor,
			&dev.DeviceType, &firstSeen, &lastSeen, &dev.Online,
			&dev.Signal, &dev.RSSI, &dev.TrafficIn, &dev.TrafficOut,
			&dev.Blocked, &dev.SpeedLimit, &dev.Priority, &dev.Nickname,
			&dev.IsWireless, &openPorts)
		if err != nil {
			return nil, err
		}
		dev.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
		dev.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)
		devices = append(devices, dev)
	}
	return devices, nil
}

func (d *Database) UpdateDeviceBlock(mac string, blocked bool) error {
	_, err := d.Exec("UPDATE devices SET blocked = ? WHERE mac = ?", blocked, mac)
	return err
}

func (d *Database) UpdateDeviceSpeed(mac string, speedKbps int) error {
	_, err := d.Exec("UPDATE devices SET speed_limit = ? WHERE mac = ?", speedKbps, mac)
	return err
}

func (d *Database) UpdateDeviceNickname(mac, nickname string) error {
	_, err := d.Exec("UPDATE devices SET nickname = ? WHERE mac = ?", nickname, mac)
	return err
}

// --- Protected Devices (by MAC) ---

func (d *Database) AddProtectedMAC(mac, label string) error {
	_, err := d.Exec("INSERT OR IGNORE INTO protected_ips (ip, label) VALUES (?, ?)", mac, label)
	return err
}

func (d *Database) RemoveProtectedMAC(mac string) error {
	_, err := d.Exec("DELETE FROM protected_ips WHERE ip = ?", mac)
	return err
}

func (d *Database) RemoveProtectedByIP(ip string) error {
	_, err := d.Exec("DELETE FROM protected_ips WHERE ip = ?", ip)
	return err
}

func (d *Database) GetProtectedMACs() ([]string, error) {
	rows, err := d.Query("SELECT ip FROM protected_ips ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var macs []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			return nil, err
		}
		macs = append(macs, mac)
	}
	return macs, nil
}

func (d *Database) FindMACByIP(ip string) (string, error) {
	var mac string
	err := d.QueryRow("SELECT mac FROM devices WHERE ip = ?", ip).Scan(&mac)
	return mac, err
}

// --- Watchlist ---

type WatchEntry struct {
	ID        int64
	MAC       string
	IP        string
	RuleType  string
	SpeedKbps int
	Blocked   bool
	Active    bool
}

func (d *Database) AddWatch(mac, ip, ruleType string, speedKbps int, blocked bool) error {
	_, err := d.Exec("INSERT OR REPLACE INTO watchlist (mac, ip, rule_type, speed_kbps, blocked) VALUES (?, ?, ?, ?, ?)",
		mac, ip, ruleType, speedKbps, blocked)
	return err
}

func (d *Database) RemoveWatch(mac string) error {
	_, err := d.Exec("DELETE FROM watchlist WHERE mac = ?", mac)
	return err
}

func (d *Database) GetWatchlist() ([]*WatchEntry, error) {
	rows, err := d.Query("SELECT id, mac, ip, rule_type, speed_kbps, blocked, active FROM watchlist WHERE active = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*WatchEntry
	for rows.Next() {
		e := &WatchEntry{}
		if err := rows.Scan(&e.ID, &e.MAC, &e.IP, &e.RuleType, &e.SpeedKbps, &e.Blocked, &e.Active); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (d *Database) UpdateWatchIP(mac, newIP string) error {
	_, err := d.Exec("UPDATE watchlist SET ip = ? WHERE mac = ?", newIP, mac)
	return err
}

func (d *Database) DeactivateWatch(mac string) error {
	_, err := d.Exec("UPDATE watchlist SET active = 0 WHERE mac = ?", mac)
	return err
}

// --- Scan History ---

func (d *Database) LogScan(total, online int) error {
	_, err := d.Exec("INSERT INTO scan_history (total_devices, online_devices) VALUES (?, ?)", total, online)
	return err
}

// --- Schedules ---

// Schedule is one automatic rule: during [StartMin,EndMin) on Days,
// apply Action ("block" or "throttle" at SpeedKbps). Outside the window
// the device is restored to normal.
type Schedule struct {
	ID        int64
	MAC       string
	IP        string
	Action    string // "block" or "throttle"
	SpeedKbps int
	StartMin  int    // minutes since midnight, 0-1439
	EndMin    int    // minutes since midnight, 0-1439
	Days      string // "*" = daily, or comma list like "mon,tue"
}

func (d *Database) AddSchedule(mac, ip, action string, speedKbps, startMin, endMin int, days string) (int64, error) {
	res, err := d.Exec(`INSERT INTO schedules (mac, ip, action, speed_kbps, start_min, end_min, days)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, mac, ip, action, speedKbps, startMin, endMin, days)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *Database) GetSchedules() ([]*Schedule, error) {
	rows, err := d.Query(`SELECT id, mac, ip, action, speed_kbps, start_min, end_min, days
		FROM schedules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Schedule
	for rows.Next() {
		s := &Schedule{}
		if err := rows.Scan(&s.ID, &s.MAC, &s.IP, &s.Action, &s.SpeedKbps,
			&s.StartMin, &s.EndMin, &s.Days); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *Database) RemoveScheduleByID(id int64) (bool, error) {
	res, err := d.Exec("DELETE FROM schedules WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *Database) RemoveScheduleByMAC(mac string) (bool, error) {
	res, err := d.Exec("DELETE FROM schedules WHERE mac = ?", mac)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *Database) UpdateScheduleIP(mac, ip string) error {
	_, err := d.Exec("UPDATE schedules SET ip = ? WHERE mac = ?", ip, mac)
	return err
}
