package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mectov/njanet/internal/db"
)

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidMAC(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

type arpEntry struct {
	IP  string
	MAC string
}

func readARPEntries() []arpEntry {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	var entries []arpEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip := f[0]
		mac := strings.ToUpper(f[3])
		if net.ParseIP(ip) == nil || mac == "(INCOMPLETE)" ||
			mac == "00:00:00:00:00:00" || !isValidMAC(mac) {
			continue
		}
		entries = append(entries, arpEntry{IP: ip, MAC: mac})
	}
	return entries
}

func findDevice(target string, database *db.Database) *db.Device {
	devices, _ := database.GetAllDevices()
	for _, d := range devices {
		if d.IP == target || d.MAC == target {
			return d
		}
	}
	if net.ParseIP(target) != nil {
		mac := resolveMAC(target)
		if mac != "" {
			return findDeviceByMAC(database, mac)
		}
	}
	return nil
}

func findDeviceByMAC(database *db.Database, mac string) *db.Device {
	devices, _ := database.GetAllDevices()
	for _, d := range devices {
		if strings.EqualFold(d.MAC, mac) {
			return d
		}
	}
	return nil
}

// resolveLiveTarget maps a user-supplied IP or MAC to the device that
// currently owns that address in the live ARP table. Stale DB rows must not
// decide which device receives a block or throttle rule.
func resolveLiveTarget(target string, database *db.Database, entries []arpEntry) (*db.Device, error) {
	var ip, mac string
	switch {
	case isValidIP(target):
		ip = target
		for _, e := range entries {
			if e.IP == ip {
				mac = e.MAC
				break
			}
		}
		if mac == "" {
			return nil, fmt.Errorf("target %s tidak ada di ARP (offline atau beda interface)", target)
		}
	case isValidMAC(target):
		mac = strings.ToUpper(target)
		for _, e := range entries {
			if strings.EqualFold(e.MAC, mac) {
				ip = e.IP
				mac = e.MAC
				break
			}
		}
		if ip == "" {
			return nil, fmt.Errorf("MAC %s tidak ada di ARP (offline)", mac)
		}
	default:
		return nil, fmt.Errorf("IP atau MAC tidak valid: %s", target)
	}

	dev := findDeviceByMAC(database, mac)
	if dev == nil {
		dev = &db.Device{MAC: mac}
	}
	dev.MAC = mac
	dev.IP = ip
	dev.Online = true
	if _, err := database.UpsertDevice(dev); err != nil {
		return nil, err
	}
	return dev, nil
}

func findVerifiedDeviceByMAC(database *db.Database, mac string, entries []arpEntry) *db.Device {
	dev := findDeviceByMAC(database, mac)
	if dev == nil || !isValidIP(dev.IP) {
		return nil
	}
	for _, e := range entries {
		if e.IP == dev.IP && strings.EqualFold(e.MAC, mac) {
			return dev
		}
	}
	return nil
}

func resolveMAC(ip string) string {
	for _, e := range readARPEntries() {
		if e.IP == ip {
			return e.MAC
		}
	}
	return ""
}

// resolveCleanupDevice allows an offline IP/MAC for removing an existing
// throttle. It never uses a stored IP to create a new rule.
func resolveCleanupDevice(target string, database *db.Database) (*db.Device, error) {
	if isValidIP(target) {
		if dev := findDevice(target, database); dev != nil {
			dev.IP = target
			return dev, nil
		}
		return &db.Device{IP: target}, nil
	}
	if isValidMAC(target) {
		mac := strings.ToUpper(target)
		if dev := findDeviceByMAC(database, mac); dev != nil && isValidIP(dev.IP) {
			return dev, nil
		}
		return nil, fmt.Errorf("MAC %s offline dan tidak punya IP tersimpan; gunakan 'sudo njanet reset'", mac)
	}
	return nil, fmt.Errorf("IP atau MAC tidak valid: %s", target)
}

// guardSelfTarget menolak operasi yang akan mematikan konektivitas sendiri:
// target = IP laptop ini atau IP gateway. Mengembalikan true jika pemanggil
// harus batal (pesan sudah dicetak).
func guardSelfTarget(candidates []string, ifaceName string) bool {
	myIP := getMyIP(ifaceName)
	gw := getGatewayIP()
	for _, ip := range candidates {
		if ip == "" {
			continue
		}
		if ip == myIP {
			fmt.Fprintf(os.Stderr, "Ditolak: %s adalah IP laptop ini.\n", ip)
			return true
		}
		if ip == gw {
			fmt.Fprintf(os.Stderr, "Ditolak: %s adalah gateway — memblokirnya mematikan seluruh jaringan.\n", ip)
			return true
		}
	}
	return false
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
