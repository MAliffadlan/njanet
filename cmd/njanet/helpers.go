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

func findDevice(target string, database *db.Database) *db.Device {
	devices, _ := database.GetAllDevices()
	for _, d := range devices {
		if d.IP == target || d.MAC == target {
			return d
		}
	}
	// Not found in DB — try to resolve MAC from ARP table
	if net.ParseIP(target) != nil {
		mac := resolveMAC(target)
		if mac != "" {
			for _, d := range devices {
				if d.MAC == mac {
					return d
				}
			}
		}
	}
	return nil
}

func resolveMAC(ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == ip && f[3] != "(incomplete)" {
			return strings.ToUpper(f[3])
		}
	}
	return ""
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

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}
