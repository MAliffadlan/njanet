package db

import (
	"net"
	"time"
)

type Device struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`
	DeviceType string   `json:"device_type"` // phone, laptop, tv, iot, etc
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
	Signal    int       `json:"signal"`
	RSSI      int       `json:"rssi"`

	TrafficIn  int64 `json:"traffic_in"`  // bytes
	TrafficOut int64 `json:"traffic_out"` // bytes

	Blocked    bool `json:"blocked"`
	SpeedLimit int  `json:"speed_limit"` // Kbps, 0 = unlimited
	Priority   int  `json:"priority"`    // 1-5, 5=highest

	// Friendly name set by user
	Nickname string `json:"nickname"`

	// Connection type
	IsWireless bool `json:"is_wireless"`

	// Open ports
	OpenPorts []int `json:"open_ports,omitempty"`
}

func (d *Device) MACAddr() net.HardwareAddr {
	mac, _ := net.ParseMAC(d.MAC)
	return mac
}

func (d *Device) UpdateFrom(other *Device) {
	if other.Hostname != "" {
		d.Hostname = other.Hostname
	}
	if other.Vendor != "" {
		d.Vendor = other.Vendor
	}
	d.LastSeen = other.LastSeen
	d.Online = other.Online
	if other.Signal > 0 {
		d.Signal = other.Signal
	}
	if other.RSSI > 0 {
		d.RSSI = other.RSSI
	}
}

type TrafficRecord struct {
	ID        int64     `json:"id"`
	DeviceID  int64     `json:"device_id"`
	MAC       string    `json:"mac"`
	Timestamp time.Time `json:"timestamp"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	Protocol  string    `json:"protocol"`
	Host      string    `json:"host"` // DNS name / SNI
}

type BlockRule struct {
	ID        int64     `json:"id"`
	DeviceID  int64     `json:"device_id"`
	MAC       string    `json:"mac"`
	Active    bool      `json:"active"`
	ScheduleStart string `json:"schedule_start,omitempty"` // "22:00"
	ScheduleEnd   string `json:"schedule_end,omitempty"`   // "06:00"
	CreatedAt time.Time `json:"created_at"`
}

type SpeedRule struct {
	ID        int64     `json:"id"`
	DeviceID  int64     `json:"device_id"`
	MAC       string    `json:"mac"`
	SpeedKbps int       `json:"speed_kbps"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}
