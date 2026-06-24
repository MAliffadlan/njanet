package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mectov/njanet/internal/db"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	vendorDBURL = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
	ouiDBPath   = "/tmp/netctl_oui.db"
)

type Scanner struct {
	iface       *net.Interface
	myIP        net.IP
	subnet      *net.IPNet
	vendorCache map[string]string
	mu          sync.RWMutex
	results     []*db.Device
	devicesMu   sync.RWMutex
	ouiDB       map[string]string
}

type ScanResult struct {
	Devices  []*db.Device `json:"devices"`
	Duration string       `json:"duration"`
	Total    int          `json:"total"`
	Online   int          `json:"online"`
}

func New(ifaceName string) (*Scanner, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get addrs: %w", err)
	}

	var myIP net.IP
	var subnet *net.IPNet
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				myIP = ipnet.IP
				subnet = ipnet
				break
			}
		}
	}

	if myIP == nil {
		return nil, fmt.Errorf("no IPv4 address on interface %s", ifaceName)
	}

	return &Scanner{
		iface:       iface,
		myIP:        myIP,
		subnet:      subnet,
		vendorCache: make(map[string]string),
		ouiDB:       make(map[string]string),
	}, nil
}

func (s *Scanner) MyIP() net.IP       { return s.myIP }
func (s *Scanner) Subnet() *net.IPNet { return s.subnet }
func (s *Scanner) Interface() *net.Interface { return s.iface }

// LoadOUI loads embedded manufacturer database
func (s *Scanner) LoadOUI() error {
	builtin := map[string]string{
		// Apple
		"00:25:00": "Apple",
		"00:26:08": "Apple",
		"00:26:BB": "Apple",
		"6C:70:9F": "Apple",
		"04:D4:C4": "Apple",
		"00:03:93": "Apple",
		"00:0D:93": "Apple",
		"00:0A:27": "Apple",
		"00:0A:95": "Apple",
		"00:1B:63": "Apple",
		"00:1E:C2": "Apple",
		"00:1F:5B": "Apple",
		"00:1F:F3": "Apple",
		"00:21:E9": "Apple",
		"00:22:41": "Apple",
		"00:23:32": "Apple",
		"00:23:6C": "Apple",
		"00:24:36": "Apple",
		"00:25:BC": "Apple",
		"00:26:B0": "Apple",
		"F8:1E:DF": "Apple",
		"00:50:56": "VMware",

		// ASUS
		"0C:9D:92": "ASUS",
		"00:1E:06": "ASUS",
		"00:1B:FC": "ASUS",
		"10:BF:48": "ASUS",
		"18:3E:EF": "ASUS",
		"60:A4:4C": "ASUS",
		"70:4D:7B": "ASUS",
		"94:D9:B3": "ASUS",
		"BC:AE:C5": "ASUS",
		"C8:FC:80": "ASUS",
		"E0:3F:49": "ASUS",
		"28:6C:07": "ASUS",
		"20:CF:30": "ASUS",

		// Intel
		"50:6A:03": "Intel",
		"30:46:9A": "Intel",
		"E0:5A:1F": "Intel",
		"F4:6D:04": "Intel",
		"C4:03:A8": "Intel",
		"00:08:A2": "Intel",
		"00:0E:0C": "Intel",
		"00:12:7B": "Intel",
		"00:13:E8": "Intel",
		"00:15:17": "Intel",
		"00:16:6F": "Intel",
		"00:18:DE": "Intel",
		"00:19:D1": "Intel",
		"00:1C:BF": "Intel",
		"00:1D:72": "Intel",
		"00:1E:67": "Intel",
		"00:21:6B": "Intel",
		"00:23:02": "Intel",
		"00:24:D6": "Intel",
		"00:26:C6": "Intel",
		"3C:97:0E": "Intel",
		"54:EE:75": "Intel",
		"84:8F:69": "Intel",
		"98:90:96": "Intel",
		"E0:B9:A5": "Intel",
		"F0:1F:AF": "Intel",

		// Samsung
		"00:1C:42": "Samsung",
		"08:00:46": "Samsung",
		"64:1C:AE": "Samsung",
		"58:A0:23": "Samsung",
		"00:17:E5": "Samsung",
		"50:9B:0C": "Samsung",
		"54:2A:9E": "Samsung",
		"60:02:92": "Samsung",
		"84:2B:2B": "Samsung",
		"AC:5F:3E": "Samsung",
		"BC:0F:2B": "Samsung",
		"C8:94:02": "Samsung",
		"E0:63:DA": "Samsung",
		"F0:6E:0B": "Samsung",
		"9C:F4:8E": "Samsung",
		"8C:45:00": "Samsung",
		"EC:0E:C4": "Samsung",

		// Xiaomi
		"00:1E:C1": "Xiaomi",
		"18:FE:34": "Xiaomi",
		"48:02:2A": "Xiaomi",
		"28:6D:CD": "Xiaomi",
		"04:CF:8C": "Xiaomi",
		"C8:84:47": "Xiaomi",
		"10:08:B1": "Xiaomi",
		"F0:FE:6B": "Xiaomi",
		"9C:C7:A6": "Xiaomi",
		"B0:4E:26": "Xiaomi",
		"B0:68:E6": "Xiaomi",
		"FC:B4:E6": "Xiaomi",
		"7C:DD:90": "Xiaomi",
		"D8:5C:79": "Xiaomi",
		"C0:EE:FB": "Xiaomi",

		// Huawei
		"00:1E:53": "Huawei",
		"38:59:F9": "Huawei",
		"68:EF:BD": "Huawei",
		"48:22:54": "Huawei",
		"88:25:2C": "Huawei",
		"A0:55:DE": "Huawei",
		"A4:77:33": "Huawei",
		"E0:0E:DA": "Huawei",
		"F4:96:34": "Huawei",
		"9C:95:F8": "Huawei",
		"28:6E:D4": "Huawei",

		// Cisco
		"00:1B:21": "Cisco",
		"00:1E:13": "Cisco",
		"00:1A:A1": "Cisco",
		"00:14:6C": "Cisco",
		"00:0D:65": "Cisco",
		"00:0F:F7": "Cisco",
		"00:1A:30": "Cisco",
		"00:1C:B0": "Cisco",
		"00:21:1C": "Cisco",
		"00:24:97": "Cisco",
		"40:4A:03": "Cisco",
		"54:6A:01": "Cisco",
		"6C:41:6A": "Cisco",
		"C4:7D:4F": "Cisco",
		"E4:AA:5D": "Cisco",

		// TP-Link
		"00:24:18": "TP-Link",
		"14:CC:20": "TP-Link",
		"50:C7:BF": "TP-Link",
		"5C:49:79": "TP-Link",
		"E8:48:B8": "TP-Link",
		"78:8C:B5": "TP-Link",
		"A0:F3:C1": "TP-Link",
		"54:E6:FC": "TP-Link",
		"30:B5:C2": "TP-Link",
		"04:66:CF": "TP-Link",
		"6C:5A:B0": "TP-Link",
		"B0:BE:76": "TP-Link",
		"C0:4A:00": "TP-Link",
		"D4:6E:0E": "TP-Link",

		// Dell
		"00:1A:4A": "Dell",
		"00:21:70": "Dell",
		"00:23:AE": "Dell",
		"00:14:22": "Dell",
		"00:0B:DB": "Dell",
		"00:12:3F": "Dell",
		"00:15:C5": "Dell",
		"00:18:8B": "Dell",
		"00:1C:23": "Dell",
		"00:1D:09": "Dell",
		"00:1F:1F": "Dell",
		"00:21:9B": "Dell",
		"00:26:55": "Dell",
		"34:E6:D7": "Dell",
		"B8:CA:3A": "Dell",

		// HP / Hewlett Packard
		"00:03:0F": "HP",
		"00:17:A4": "HP",
		"00:1A:4B": "HP",
		"00:1E:0B": "HP",
		"00:21:5A": "HP",
		"00:22:64": "HP",
		"00:23:7D": "HP",
		"00:24:2B": "HP",
		"3C:D9:2B": "HP",
		"68:B5:99": "HP",
		"9C:B6:54": "HP",
		"B4:51:A9": "HP",
		"BC:EA:2B": "HP",
		"E0:07:1B": "HP",
		"E4:C7:22": "HP",

		// Google / Nest
		"00:1A:11": "Google",
		"AC:37:43": "Google",
		"8C:FD:F0": "Google",
		"BC:6A:29": "Google",
		"F8:CF:C5": "Google",
		"18:B4:30": "Google",
		"3C:5A:37": "Google",
		"6C:9C:ED": "Google",
		"B4:45:06": "Google",

		// Realtek
		"40:16:9E": "Realtek",
		"00:E0:4C": "Realtek",
		"00:0A:EB": "Realtek",
		"00:13:46": "Realtek",

		// Qualcomm / Atheros
		"00:1A:64": "Qualcomm",
		"50:20:38": "Qualcomm",
		"00:0A:F5": "Qualcomm",
		"00:03:7F": "Qualcomm/Atheros",
		"00:0B:6B": "Qualcomm/Atheros",
		"00:11:92": "Qualcomm/Atheros",
		"00:13:74": "Qualcomm/Atheros",
		"00:15:6D": "Qualcomm/Atheros",
		"00:1C:DF": "Qualcomm/Atheros",
		"00:20:A6": "Qualcomm/Atheros",
		"20:4C:9E": "Qualcomm/Atheros",
		"98:52:3D": "Qualcomm/Atheros",
		"C8:3A:35": "Qualcomm/Atheros",

		// Broadcom
		"00:10:18": "Broadcom",
		"00:0A:D5": "Broadcom",
		"00:11:43": "Broadcom",
		"00:14:BF": "Broadcom",
		"00:17:F2": "Broadcom",
		"00:1C:C0": "Broadcom",
		"00:1E:6C": "Broadcom",
		"00:22:4D": "Broadcom",
		"84:16:16": "Broadcom",
		"E0:69:95": "Broadcom",
		"08:26:AE": "Broadcom",

		// MediaTek
		"00:0C:E7": "MediaTek",
		"00:1A:8C": "MediaTek",
		"04:18:D6": "MediaTek",
		"A4:5E:60": "MediaTek",
		"C0:74:AD": "MediaTek",
		"E8:6C:5B": "MediaTek",

		// NVIDIA
		"E0:06:E6": "NVIDIA",
		"00:25:22": "NVIDIA",

		// Sony
		"00:0D:67": "Sony",
		"00:1A:80": "Sony",
		"00:23:CD": "Sony",
		"7C:46:85": "Sony",
		"8C:F1:FE": "Sony",
		"B8:6C:E8": "Sony",
		"E0:98:61": "Sony",

		// LG
		"00:1E:60": "LG",
		"54:5F:23": "LG",
		"6C:1B:40": "LG",
		"7C:49:EB": "LG",
		"80:C6:3C": "LG",
		"BC:AD:AB": "LG",
		"F4:56:8A": "LG",

		// OnePlus
		"00:12:D2": "OnePlus",

		// Oppo
		"80:CB:34": "Oppo",
		"AC:0D:1E": "Oppo",
		"C4:07:2F": "Oppo",

		// Motorola
		"00:23:76": "Motorola",
		"DC:0C:2E": "Motorola",
		"70:6A:CB": "Motorola",
		"AC:84:C6": "Motorola",
		"F0:0D:5C": "Motorola",

		// Nokia
		"00:22:55": "Nokia",
		"00:1A:44": "Nokia",
		"00:0B:DD": "Nokia",
		"08:00:37": "Nokia",
		"C8:0C:44": "Nokia",

		// HTC
		"00:1C:B3": "HTC",
		"24:0A:C4": "HTC",

		// BlackBerry
		"00:0D:97": "BlackBerry",

		// Raspberry Pi
		"B8:27:EB": "Raspberry Pi",
		"DC:A6:32": "Raspberry Pi",
		"E4:5F:01": "Raspberry Pi",

		// Docker / Virtual / Containers
		"02:42:AC": "Docker",
		"02:42:0A": "Docker",
		"52:54:00": "QEMU",
		"00:0C:29": "VMware",
		"00:05:69": "VMware",
		"08:00:27": "VirtualBox",
		"00:15:5D": "Hyper-V",

		// Network Equipment
		"D0:04:92": "Fiberhome",
		"00:30:18": "Jetway",
		"4C:5E:0C": "MikroTik",
		"64:D1:54": "MikroTik",
		"74:83:C2": "Ubiquiti",
		"B4:6D:83": "Ubiquiti",
		"00:04:5A": "Zyxel",
		"5C:57:C8": "Zyxel",
		"00:1C:F0": "D-Link",
		"28:10:7B": "D-Link",
		"58:6D:8F": "D-Link",
		"B0:C5:54": "D-Link",
		"CC:B2:55": "D-Link",
		"F4:B7:E2": "Aruba",
		"8C:EB:EA": "Aruba",
		"20:E5:2A": "Netgear",
		"84:1B:5E": "Netgear",
		"C0:3F:0E": "Netgear",
		"E0:91:53": "Netgear",
		"F4:3A:92": "Netgear",
		"00:0F:B5": "Netgear",
		"64:70:02": "EnGenius",
		"00:12:17": "EnGenius",

		// IoT / Smart Home
		"B0:CE:18": "Ring",
		"74:75:48": "Ring",
		"68:57:2D": "Ring",
		"00:16:2C": "Sonos",
		"B8:E9:37": "Sonos",
		"94:10:3E": "Sonos",
		"E0:27:6A": "Sonos",
		"EC:45:F2": "TP-Link IoT",
		"50:02:91": "TP-Link IoT",
		"68:C6:3A": "TP-Link IoT",
		"00:1C:33": "Amazon",
		"74:C2:46": "Amazon",
		"AC:63:BE": "Amazon",
		"F0:27:65": "Amazon",
		"00:0E:6D": "Xbox",
		"00:50:F2": "Microsoft/Xbox",
		"58:FB:84": "Nintendo Switch",
		"00:22:AA": "Canon",
		"00:1E:8C": "Epson",
		"00:23:BB": "Samsung Printer",
		"00:15:99": "Brother",

		// Random/PC vendors

	// More Campus / Indonesian common vendors
	"CC:2D:21": "Tenda",
	"D0:C5:D3": "AzureWave",
	"C4:FE:5B": "OPPO",
	"30:F6:EF": "Tenda",
	"8C:A9:82": "Xiaomi",
	"C8:5B:76": "Huawei",
	"F4:1E:57": "TP-Link",
	"EC:2E:4E": "Huawei",
	"5C:02:14": "Vivo",
	"A8:72:2D": "OnePlus",
	"90:4A:1C": "Nokia",
	"28:E3:47": "Samsung",
	"DC:2C:6E": "Cisco Meraki",
	"20:2B:20": "Samsung",
	"74:AC:B9": "Huawei",
	"14:14:16": "Xiaomi",
	"F8:D1:11": "Huawei",
	"18:02:AE": "Xiaomi",
	"50:C2:E8": "Intel",
	"34:02:86": "Samsung",
	"CC:B8:5E": "Intel",
	"00:80:48": "Xerox",
	"00:1D:60": "Foxconn",
	"38:D5:47": "Lenovo",
	"00:1B:24": "Lenovo",
	"00:21:CC": "Lenovo",
	"B8:88:E3": "Lenovo",
	"E4:1F:13": "Lenovo",
	"FC:AA:14": "Lenovo",
	"00:09:0D": "Acer",
	"00:1C:25": "Acer",
	"00:23:5A": "Acer",
	"F8:2F:A8": "Acer",
	"2C:FD:A1": "Acer",
	"00:1E:58": "Toshiba",
	"00:24:4B": "Toshiba",
	"00:17:08": "Panasonic",
	"00:1C:CE": "Panasonic",
	"00:24:44": "Panasonic",
	"00:1D:7D": "Sharp",
	"00:03:77": "Palm",
	"00:0D:4E": "Palm",
	// Automotive
	"00:01:5E": "Tesla",
	"98:F0:AB": "Tesla",
	"00:04:3E": "Ford",
	"00:1B:EB": "BMW",
	}

	for k, v := range builtin {
		s.ouiDB[strings.ToUpper(strings.ReplaceAll(k, ":", ""))[:6]] = v
	}
	return nil
}

// LookupVendor returns the vendor name for a given MAC address
func (s *Scanner) LookupVendor(mac string) string {
	// Normalize MAC: remove separators, take first 6 hex digits
	clean := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	clean = strings.ReplaceAll(clean, "-", "")
	if len(clean) < 6 {
		return "Unknown"
	}
	oui := clean[:6]

	s.mu.RLock()
	vendor, ok := s.ouiDB[oui]
	s.mu.RUnlock()
	if ok {
		return vendor
	}

	// Try online API fallback (cached)
	vendor = s.lookupOnline(oui)
	if vendor != "" {
		s.mu.Lock()
		s.ouiDB[oui] = vendor
		s.mu.Unlock()
		return vendor
	}

	return "Unknown"
}

// lookupOnline queries macvendors.com for unknown MAC OUIs
func (s *Scanner) lookupOnline(oui string) string {
	url := "https://api.macvendors.com/" + oui[:2] + ":" + oui[2:4] + ":" + oui[4:6]
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NjaNet/1.0")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	result := strings.TrimSpace(string(body))
	if len(result) > 0 && len(result) < 100 {
		return result
	}
	return ""
}

// PingScan sends ICMP echo requests to all hosts in subnet
func (s *Scanner) PingScan(ctx context.Context, timeout time.Duration) ([]net.IP, error) {
	ips := s.networkHosts()
	var alive []net.IP
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // limit concurrency

	for _, ip := range ips {
		if ip.Equal(s.myIP) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			// Fast check: try TCP connection to common ports
			if s.tcpPing(ip, 80, 200*time.Millisecond) ||
				s.tcpPing(ip, 443, 200*time.Millisecond) ||
				s.tcpPing(ip, 22, 200*time.Millisecond) ||
				s.tcpPing(ip, 8080, 200*time.Millisecond) ||
				s.icmpPing(ip, 500*time.Millisecond) {
				mu.Lock()
				alive = append(alive, ip)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return alive, nil
}

// ARPScan discovers devices using ARP (via nmap or raw socket)
func (s *Scanner) ARPScan(ctx context.Context) ([]*db.Device, error) {
	var devices []*db.Device

	// Try arp-scan first (fastest)
	if arpScanPath, err := exec.LookPath("arp-scan"); err == nil {
		devices, _ = s.arpScanWithTool(ctx, arpScanPath)
		if len(devices) > 0 {
			return devices, nil
		}
	}

		// Fall back to nmap ARP scan
	if nmapPath, err := exec.LookPath("nmap"); err == nil {
		devices, _ = s.nmapARPScan(ctx, nmapPath)
		if len(devices) > 1 {
			return devices, nil
		}
	}

	s.pingSweep()

	devices, _ = s.rawARPScan(ctx)
	if len(devices) > 1 {
		return devices, nil
	}

	return s.readARPTable(), nil
}

func (s *Scanner) arpScanWithTool(ctx context.Context, arpScanPath string) ([]*db.Device, error) {
	cmd := exec.CommandContext(ctx, arpScanPath,
		"--localnet",
		"--interface", s.iface.Name,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var devices []*db.Device
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "Interface") || strings.Contains(line, "Starting") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			mac := strings.ToUpper(parts[1])
			if net.ParseIP(ip) == nil || !s.isValidMAC(mac) {
				continue
			}

			hostname := ""
			if len(parts) >= 3 {
				hostname = strings.Join(parts[2:], " ")
			}

			dev := &db.Device{
				IP:        ip,
				MAC:       mac,
				Hostname:  hostname,
				Vendor:    s.LookupVendor(mac),
				Online:    true,
				LastSeen:  time.Now(),
				FirstSeen: time.Now(),
			}

			// Try to detect device type
			dev.DeviceType = s.detectDeviceType(dev)
			devices = append(devices, dev)
		}
	}

	return devices, nil
}

func (s *Scanner) nmapARPScan(ctx context.Context, nmapPath string) ([]*db.Device, error) {
	subnetStr := s.subnet.String()
	cmd := exec.CommandContext(ctx, nmapPath,
		"-sn", "-n",
		subnetStr,
		"-oG", "-",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var devices []*db.Device
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Host:") {
			continue
		}

		// Parse nmap greppable output
		parts := strings.Split(line, "\t")
		for _, part := range parts {
			if strings.HasPrefix(part, "Host:") {
				ipStr := strings.TrimSpace(strings.TrimPrefix(part, "Host:"))
				ip := net.ParseIP(ipStr)
				if ip == nil || ip.Equal(s.myIP) {
					continue
				}

				dev := &db.Device{
					IP:        ipStr,
					Online:    true,
					LastSeen:  time.Now(),
					FirstSeen: time.Now(),
				}

				// Look for MAC in other parts
				for _, p := range parts {
					if strings.Contains(p, "MAC:") {
						macPart := strings.TrimSpace(strings.TrimPrefix(p, "MAC:"))
						if idx := strings.Index(macPart, " "); idx > 0 {
							dev.MAC = strings.ToUpper(macPart[:idx])
						} else {
							dev.MAC = strings.ToUpper(macPart)
						}
					}
				}

				dev.Vendor = s.LookupVendor(dev.MAC)
				dev.DeviceType = s.detectDeviceType(dev)
				devices = append(devices, dev)
			}
		}
	}

	return devices, nil
}

// pingSweep pings subnet to populate ARP cache (fast)
func (s *Scanner) pingSweep() {
	ones, bits := s.subnet.Mask.Size()
	n := 1 << uint(bits-ones)
	if n > 512 {
		n = 512
	}
	ip := make(net.IP, len(s.myIP))
	copy(ip, s.myIP)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	for i := 1; i < n; i++ {
		ip[3] = byte(i)
		if ip.Equal(s.myIP) {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			exec.Command("timeout", "0.3", "ping", "-c", "1", "-q", addr).Run()
		}(ip.String())
	}
	// Wait for all to complete (with ~5s max for /24)
	wg.Wait()
}

func (s *Scanner) rawARPScan(ctx context.Context) ([]*db.Device, error) {
	// Use ARP table + ping combination
	devices := s.readARPTable()

	// Ping all hosts to discover new ones
	alive, err := s.PingScan(ctx, 2*time.Second)
	if err == nil {
		for _, ip := range alive {
			found := false
			for _, d := range devices {
				if d.IP == ip.String() {
					found = true
					break
				}
			}
			if !found {
				mac := s.resolveMAC(ip)
				dev := &db.Device{
					IP:        ip.String(),
					MAC:       mac,
					Vendor:    s.LookupVendor(mac),
					Online:    true,
					LastSeen:  time.Now(),
					FirstSeen: time.Now(),
				}
				dev.DeviceType = s.detectDeviceType(dev)
				devices = append(devices, dev)
			}
		}
	}

	return devices, nil
}

func (s *Scanner) readARPTable() []*db.Device {
	// Read /proc/net/arp for known devices
	content, err := exec.Command("cat", "/proc/net/arp").Output()
	if err != nil {
		return nil
	}

	var devices []*db.Device
	scanner := bufio.NewScanner(bytes.NewReader(content))
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip := fields[0]
			mac := strings.ToUpper(fields[3])
			if mac == "" || mac == "(incomplete)" || mac == "00:00:00:00:00:00" {
				continue
			}
			if !s.isValidMAC(mac) {
				continue
			}

			dev := &db.Device{
				IP:        ip,
				MAC:       mac,
				Vendor:    s.LookupVendor(mac),
				Online:    true,
				LastSeen:  time.Now(),
				FirstSeen: time.Now(),
			}
			dev.DeviceType = s.detectDeviceType(dev)
			devices = append(devices, dev)
		}
	}

	return devices
}

// EnrichDevice adds extra info to a device
func (s *Scanner) EnrichDevice(ctx context.Context, dev *db.Device) {
	if dev.Hostname == "" {
		// 1. nmap -sL (reverse DNS)
		if names, err := net.LookupAddr(dev.IP); err == nil && len(names) > 0 {
			dev.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	if dev.Hostname == "" {
		// 2. Try /etc/hosts
		if hostname := s.checkHostsFile(dev.IP); hostname != "" {
			dev.Hostname = hostname
		}
	}

	if dev.Hostname == "" {
		// 3. Try nmblookup (NetBIOS name, useful for Windows devices)
		if hostname := s.netbiosLookup(dev.IP); hostname != "" {
			dev.Hostname = hostname
		}
	}

	if dev.Hostname == "" {
		// 4. Try avahi-resolve (mDNS/Bonjour)
		if hostname := s.mdnsLookup(dev.IP); hostname != "" {
			dev.Hostname = hostname
		}
	}

	// Port scan for open ports
	ports := s.quickPortScan(ctx, dev.IP)
	dev.OpenPorts = ports

	// Detect wireless via OUI
	dev.IsWireless = s.detectWireless(dev.MAC)
}

func (s *Scanner) quickPortScan(ctx context.Context, ip string) []int {
	commonPorts := []int{22, 80, 443, 554, 8080, 8443, 21, 23, 25, 53, 139, 445, 3389, 5900, 5901}
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func (s *Scanner) detectWireless(mac string) bool {
	// Common wireless interface OUI prefixes
	wirelessPrefixes := []string{
		"00:1A:11", // Google/Nest
		"00:25:00", // Apple
		"08:00:46", // Samsung
		"00:1E:06", // ASUS
	}
	prefix := strings.ToUpper(mac[:8])
	for _, p := range wirelessPrefixes {
		if strings.HasPrefix(prefix, p) {
			return true
		}
	}
	// Most consumer devices are wireless, return true if it's a known mobile/consumer vendor
	vendor := s.LookupVendor(mac)
	mobileVendors := []string{"Apple", "Samsung", "Xiaomi", "Huawei", "OnePlus", "Oppo", "Google"}
	for _, v := range mobileVendors {
		if strings.Contains(vendor, v) {
			return true
		}
	}
	return false
}

func (s *Scanner) checkHostsFile(ip string) string {
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == ip {
			return fields[1]
		}
	}
	return ""
}

func (s *Scanner) netbiosLookup(ip string) string {
	out, err := exec.Command("nmblookup", "-A", ip).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "<00>") && strings.Contains(line, "UNIQUE") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	return ""
}

func (s *Scanner) mdnsLookup(ip string) string {
	out, err := exec.Command("avahi-resolve", "-a", ip).Output()
	if err == nil {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			return strings.TrimSuffix(parts[1], ".local")
		}
	}
	out, err = exec.Command("resolvectl", "query", ip).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, ip) && strings.Contains(line, "->") {
				parts := strings.Split(line, "->")
				if len(parts) >= 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}
func (s *Scanner) detectDeviceType(dev *db.Device) string {
	vendor := strings.ToLower(dev.Vendor)
	mac := strings.ToUpper(dev.MAC)
	hostname := strings.ToLower(dev.Hostname)

	// By hostname patterns
	if strings.Contains(hostname, "tv") || strings.Contains(hostname, "samsung") && !strings.Contains(hostname, "phone") {
		return "tv"
	}
	if strings.Contains(hostname, "printer") || strings.Contains(hostname, "print") {
		return "printer"
	}
	if strings.Contains(hostname, "router") || strings.Contains(hostname, "ap") ||
		strings.Contains(hostname, "wifi") {
		return "router"
	}
	if strings.Contains(hostname, "camera") || strings.Contains(hostname, "cam") ||
		strings.Contains(hostname, "ipcam") {
		return "camera"
	}
	if strings.Contains(hostname, "switch") || strings.Contains(hostname, "hub") {
		return "switch"
	}
	if strings.Contains(hostname, "thermostat") || strings.Contains(hostname, "bulb") ||
		strings.Contains(hostname, "light") {
		return "iot"
	}

	// By vendor patterns
	if strings.Contains(vendor, "apple") || strings.Contains(vendor, "iphone") ||
		strings.Contains(vendor, "ipad") {
		return "phone"
	}
	if strings.Contains(vendor, "samsung") && strings.Contains(hostname, "phone") {
		return "phone"
	}
	if strings.Contains(vendor, "samsung") {
		return "phone"
	}
	if strings.Contains(vendor, "tp-link") || strings.Contains(vendor, "tplink") {
		return "router"
	}
	if strings.Contains(vendor, "raspberry") {
		return "server"
	}

	// By MAC OUI for specific types
	knownRouters := []string{"50:C7:BF", "14:CC:20", "78:8C:B5", "A0:F3:C1", "54:E6:FC"}
	for _, r := range knownRouters {
		if strings.HasPrefix(mac, r) {
			return "router"
		}
	}

	return "unknown"
}

func (s *Scanner) resolveHostnameMDNS(ip string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try reverse lookup first
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		return names
	}

	return nil
}

func (s *Scanner) tcpPing(ip net.IP, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func (s *Scanner) icmpPing(ip net.IP, timeout time.Duration) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("netctl-ping"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: ip}); err != nil {
		return false
	}

	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return false
		}
		if peer.(*net.IPAddr).IP.Equal(ip) {
			recvMsg, err := icmp.ParseMessage(1, reply[:n])
			if err != nil {
				continue
			}
			if recvMsg.Type == ipv4.ICMPTypeEchoReply {
				return true
			}
		}
	}
}

func (s *Scanner) resolveMAC(ip net.IP) string {
	// Try reading ARP table
	content, err := exec.Command("cat", "/proc/net/arp").Output()
	if err != nil {
		return ""
	}

	ipStr := ip.String()
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ipStr {
			mac := strings.ToUpper(fields[3])
			if mac != "(incomplete)" && mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}

	return ""
}

func (s *Scanner) isValidMAC(mac string) bool {
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

func isMulticastMAC(mac string) bool {
	// MAC addresses starting with 01:00:5E, 01:80:C2, 33:33, etc are multicast
	parts := strings.Split(mac, ":")
	if len(parts) >= 1 {
		first, err := strconv.ParseUint(parts[0], 16, 8)
		if err == nil && first&0x01 == 1 {
			return true
		}
	}
	return false
}

func (s *Scanner) networkHosts() []net.IP {
	var ips []net.IP
	ones, bits := s.subnet.Mask.Size()
	numIPs := 1 << uint(bits-ones)
	if numIPs > 1024 {
		numIPs = 1024 // limit scan to /22
	}

	ip := make(net.IP, len(s.myIP))
	copy(ip, s.myIP)
	for i := 0; i < numIPs; i++ {
		ip[3] = byte(i)
		if !ip.Equal(s.myIP) {
			ips = append(ips, make(net.IP, len(ip)))
			copy(ips[len(ips)-1], ip)
		}
	}
	return ips
}

// Scan performs a full network scan
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	start := time.Now()

	// 1. ARP scan for quick device discovery
	arpDevices, err := s.ARPScan(ctx)
	if err != nil {
		return nil, fmt.Errorf("arp scan: %w", err)
	}

	// 2. Enrich each device
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for _, dev := range arpDevices {
		wg.Add(1)
		sem <- struct{}{}
		go func(d *db.Device) {
			defer wg.Done()
			defer func() { <-sem }()
			s.EnrichDevice(ctx, d)
		}(dev)
	}
	wg.Wait()

	// 3. Add my own device
	myMAC := s.iface.HardwareAddr.String()
	myDev := &db.Device{
		IP:         s.myIP.String(),
		MAC:        strings.ToUpper(myMAC),
		Hostname:   "netctl-host",
		Vendor:     s.LookupVendor(strings.ToUpper(myMAC)),
		DeviceType: "computer",
		Online:     true,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}

	allDevices := []*db.Device{myDev}
	onlineCount := 1
	seen := make(map[string]bool)
	seen[myDev.MAC] = true

	for _, dev := range arpDevices {
		if !seen[dev.MAC] {
			allDevices = append(allDevices, dev)
			seen[dev.MAC] = true
			if dev.Online {
				onlineCount++
			}
		}
	}

	// 4. Read /proc/net/arp for any extra entries not caught by scan
	knownMACs := make(map[string]bool)
	for _, d := range allDevices {
		knownMACs[d.MAC] = true
	}

	extraDevices := s.readARPTable()
	for _, dev := range extraDevices {
		if !knownMACs[dev.MAC] && !isMulticastMAC(dev.MAC) {
			dev.Online = true
			s.EnrichDevice(ctx, dev)
			allDevices = append(allDevices, dev)
			knownMACs[dev.MAC] = true
			onlineCount++
		}
	}

	return &ScanResult{
		Devices:  allDevices,
		Duration: time.Since(start).Round(time.Millisecond).String(),
		Total:    len(allDevices),
		Online:   onlineCount,
	}, nil
}

// Helper to convert IP to uint32 for subnet calculation
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
