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

	CREATE TABLE IF NOT EXISTS traffic_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER REFERENCES devices(id),
		mac TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		bytes_in INTEGER DEFAULT 0,
		bytes_out INTEGER DEFAULT 0,
		dest_ip TEXT DEFAULT '',
		dest_port INTEGER DEFAULT 0,
		protocol TEXT DEFAULT '',
		host TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_traffic_mac ON traffic_log(mac);
	CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_log(timestamp);

	CREATE TABLE IF NOT EXISTS block_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER REFERENCES devices(id),
		mac TEXT NOT NULL,
		active BOOLEAN DEFAULT 1,
		schedule_start TEXT DEFAULT '',
		schedule_end TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS speed_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER REFERENCES devices(id),
		mac TEXT NOT NULL,
		speed_kbps INTEGER NOT NULL,
		active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

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
	`
	_, err := d.Exec(schema)
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

func (d *Database) GetDeviceByMAC(mac string) (*Device, error) {
	dev := &Device{}
	var firstSeen, lastSeen, openPorts string
	err := d.QueryRow(`
		SELECT id, ip, mac, hostname, vendor, device_type,
			first_seen, last_seen, online, signal, rssi,
			traffic_in, traffic_out, blocked, speed_limit,
			priority, nickname, is_wireless, open_ports
		FROM devices WHERE mac = ?`, mac).Scan(
		&dev.ID, &dev.IP, &dev.MAC, &dev.Hostname, &dev.Vendor,
		&dev.DeviceType, &firstSeen, &lastSeen, &dev.Online,
		&dev.Signal, &dev.RSSI, &dev.TrafficIn, &dev.TrafficOut,
		&dev.Blocked, &dev.SpeedLimit, &dev.Priority, &dev.Nickname,
		&dev.IsWireless, &openPorts)
	if err != nil {
		return nil, err
	}
	dev.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
	dev.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)
	return dev, nil
}

func (d *Database) UpdateDeviceOnline(mac string, online bool) error {
	_, err := d.Exec("UPDATE devices SET online = ?, last_seen = CURRENT_TIMESTAMP WHERE mac = ?", online, mac)
	return err
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

func (d *Database) DeleteDevice(mac string) error {
	_, err := d.Exec("DELETE FROM devices WHERE mac = ?", mac)
	return err
}

// --- Traffic ---

func (d *Database) LogTraffic(t *TrafficRecord) error {
	_, err := d.Exec(`
		INSERT INTO traffic_log (device_id, mac, bytes_in, bytes_out, dest_ip, dest_port, protocol, host)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.DeviceID, t.MAC, t.BytesIn, t.BytesOut, t.DestIP, t.DestPort, t.Protocol, t.Host)
	return err
}

func (d *Database) GetTrafficByMAC(mac string, since time.Time) ([]*TrafficRecord, error) {
	rows, err := d.Query(`
		SELECT id, device_id, mac, timestamp, bytes_in, bytes_out, dest_ip, dest_port, protocol, host
		FROM traffic_log WHERE mac = ? AND timestamp >= ? ORDER BY timestamp DESC LIMIT 100`,
		mac, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*TrafficRecord
	for rows.Next() {
		t := &TrafficRecord{}
		var ts string
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.MAC, &ts, &t.BytesIn, &t.BytesOut,
			&t.DestIP, &t.DestPort, &t.Protocol, &t.Host); err != nil {
			return nil, err
		}
		t.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		records = append(records, t)
	}
	return records, nil
}

func (d *Database) GetTopTalkers(limit int) ([]*Device, error) {
	rows, err := d.Query(`
		SELECT ip, mac, hostname, vendor, traffic_in, traffic_out
		FROM devices WHERE online = 1
		ORDER BY (traffic_in + traffic_out) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		dev := &Device{}
		if err := rows.Scan(&dev.IP, &dev.MAC, &dev.Hostname, &dev.Vendor,
			&dev.TrafficIn, &dev.TrafficOut); err != nil {
			return nil, err
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// --- Block/Speed Rules ---

func (d *Database) AddBlockRule(mac string, deviceID int64) error {
	_, err := d.Exec("INSERT INTO block_rules (mac, device_id) VALUES (?, ?)", mac, deviceID)
	return err
}

func (d *Database) RemoveBlockRule(mac string) error {
	_, err := d.Exec("DELETE FROM block_rules WHERE mac = ?", mac)
	return err
}

func (d *Database) GetBlockRules() ([]*BlockRule, error) {
	rows, err := d.Query("SELECT id, device_id, mac, active, schedule_start, schedule_end, created_at FROM block_rules WHERE active = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*BlockRule
	for rows.Next() {
		r := &BlockRule{}
		var createdAt string
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.MAC, &r.Active,
			&r.ScheduleStart, &r.ScheduleEnd, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		rules = append(rules, r)
	}
	return rules, nil
}


// --- Protected Devices (by MAC) ---

func (d *Database) AddProtectedMAC(mac, label string) error {
	_, err := d.Exec("INSERT OR IGNORE INTO protected_ips (ip, label) VALUES (?, ?)", mac, label)
	return err
}

func (d *Database) RemoveProtectedMAC(mac string) error {
	// Remove by exact MAC
	_, err := d.Exec("DELETE FROM protected_ips WHERE ip = ?", mac)
	// Also try removing by IP (for backward compatibility)
	d.Exec("DELETE FROM protected_ips WHERE ip = ?", mac)
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

func (d *Database) IsProtectedMAC(mac string) (bool, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM protected_ips WHERE ip = ?", mac).Scan(&count)
	return count > 0, err
}

// --- Scan History ---

func (d *Database) LogScan(total, online int) error {
	_, err := d.Exec("INSERT INTO scan_history (total_devices, online_devices) VALUES (?, ?)", total, online)
	return err
}

func (d *Database) GetRecentScans(limit int) ([]struct{ ScannedAt time.Time; Total, Online int }, error) {
	rows, err := d.Query(
		"SELECT scanned_at, total_devices, online_devices FROM scan_history ORDER BY scanned_at DESC LIMIT ?",
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []struct {
		ScannedAt time.Time
		Total, Online int
	}
	for rows.Next() {
		var s struct {
			ScannedAt time.Time
			Total, Online int
		}
		var ts string
		if err := rows.Scan(&ts, &s.Total, &s.Online); err != nil {
			return nil, err
		}
		s.ScannedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
		scans = append(scans, s)
	}
	return scans, nil
}
