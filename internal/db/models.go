package db

import (
	"time"
)

type Device struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	Hostname   string    `json:"hostname"`
	Vendor     string    `json:"vendor"`
	DeviceType string    `json:"device_type"` // phone, laptop, tv, iot, etc
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Online     bool      `json:"online"`
	Signal     int       `json:"signal"`
	RSSI       int       `json:"rssi"`

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
