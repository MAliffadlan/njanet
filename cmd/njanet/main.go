package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mectov/njanet/internal/api"
	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
)

var dbPath string

const apiPort = 8484

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	// Determine network interface
	ifaceName := os.Getenv("NJANET_IFACE")
	if ifaceName == "" {
			ifaceName = autoDetectInterface()
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan":
		cmdScan(ifaceName)
	case "web":
		cmdWeb(ifaceName)
	case "list", "ls":
		cmdList(ifaceName)
	case "protect":
		cmdProtect(ifaceName)
	case "rename", "name":
		cmdRename(ifaceName)
	case "block":
		cmdBlock(ifaceName)
	case "unblock":
		cmdUnblock(ifaceName)
	case "throttle":
		cmdThrottle(ifaceName)
	case "hog", "monopoly", "prioritize":
		cmdHog(ifaceName)
	case "reset":
		cmdReset(ifaceName)
	case "stats":
		cmdStats(ifaceName)
	case "defend":
		cmdDefend(ifaceName)
	case "monitor":
		cmdMonitor(ifaceName)
	case "help", "-h", "--help":
		printUsage()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`NjaNet — Network Controller v0.1

Usage:
  njanet scan              Scan network for devices
  njanet list              List known devices
  njanet block <mac/ip>    Block device
  njanet unblock <mac/ip>  Unblock device
  njanet throttle <mac/ip> <speed> [--watch]  Limit bandwidth
  njanet protect           Manage protected IPs (excluded from hog)
  njanet hog <speed>       Throttle ALL devices except you
  njanet stats             Show network stats
  njanet defend            ARP spoof defense monitor
  njanet reset             Reset all rules
  njanet monitor           Live monitor network

Environment:
  NJANET_IFACE  Network interface (default: enp2s0)

Examples:
  njanet scan
  njanet block 192.168.1.100
  njanet throttle 192.168.1.100 1024
`)
}

func initDB() *db.Database {
	database, err := db.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	return database
}

func initScanner(ifaceName string) *scanner.Scanner {
	sc, err := scanner.New(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing scanner: %v\n", err)
		os.Exit(1)
	}
	if err := sc.LoadOUI(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: OUI load: %v\n", err)
	}
	return sc
}

func initController(ifaceName string) *controller.Controller {
	return controller.New(ifaceName, getMyIP(ifaceName), getGatewayIP())
}

func autoDetectInterface() string {
	// Try NJANET_IFACE env first
	if env := os.Getenv("NJANET_IFACE"); env != "" {
		return env
	}
	// Auto-detect: find interface with default route + IPv4
	out, _ := exec.Command("ip", "-4", "route", "show", "default").Output()
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 5 {
			iface := parts[4]
			// Verify it has an IP
			ipOut, _ := exec.Command("ip", "-4", "addr", "show", iface).Output()
			if strings.Contains(string(ipOut), "inet ") {
				return iface
			}
		}
	}
	return "enp2s0"
}

func getMyIP(ifaceName string) string {
	cmd := exec.Command("ip", "-4", "addr", "show", ifaceName)
	out, _ := cmd.Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.Split(parts[1], "/")[0]
			}
		}
	}
	return "192.168.1.10"
}

func getGatewayIP() string {
	cmd := exec.Command("ip", "route", "show", "default")
	out, _ := cmd.Output()
	parts := strings.Fields(string(out))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "192.168.1.1"
}

func cmdScan(ifaceName string) {
	database := initDB()
	sc := initScanner(ifaceName)
	defer database.Close()

	fmt.Println("🔍 Scanning network...")
	fmt.Printf("   Interface: %s\n", ifaceName)
	fmt.Printf("   Subnet:    %s\n", sc.Subnet())
	fmt.Println()

	ctx := context.Background()
	result, err := sc.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	// Save to DB
	for _, dev := range result.Devices {
		database.UpsertDevice(dev)
	}
	database.LogScan(result.Total, result.Online)

	fmt.Printf("✅ Scan completed in %s\n", result.Duration)
	fmt.Printf("   Devices found: %d (%d online)\n", result.Total, result.Online)
	fmt.Println()

	fmt.Printf("%-16s %-18s %-20s %-12s %s\n",
		"IP", "MAC", "Hostname", "Vendor", "Status")
	fmt.Println(string(repeatChar('-', 80)))

	for _, dev := range result.Devices {
		status := "🟢"
		if !dev.Online {
			status = "⚪"
		}
		hostname := dev.Nickname
		if hostname == "" {
			hostname = dev.Hostname
		}
		if hostname == "" {
			hostname = "-"
		}
		vendor := dev.Vendor
		if vendor == "" {
			vendor = "-"
		}
		fmt.Printf("%-16s %-18s %-20s %-12s %s\n",
			dev.IP, dev.MAC, truncate(hostname, 20), truncate(vendor, 12), status)
	}
}

func cmdList(ifaceName string) {
	database := initDB()
	defer database.Close()

	devices, err := database.GetAllDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(devices) == 0 {
		fmt.Println("No devices found. Run 'njanet scan' first.")
		return
	}

	fmt.Printf("%-3s %-16s %-18s %-20s %-15s %s\n",
		"#", "IP", "MAC", "Hostname", "Type", "Speed")
	fmt.Println(string(repeatChar('-', 90)))

	for i, dev := range devices {
		status := ""
		if dev.Blocked {
			status = "🔴 BLOCKED"
		} else if dev.SpeedLimit > 0 {
			status = fmt.Sprintf("🐢 %dKbps", dev.SpeedLimit)
		} else {
			status = "⚡ FULL"
		}
		hostname := dev.Nickname
		if hostname == "" {
			hostname = dev.Hostname
		}
		if hostname == "" {
			hostname = "-"
		}
		fmt.Printf("%-3d %-16s %-18s %-20s %-15s %s\n",
			i+1, dev.IP, dev.MAC, truncate(hostname, 20),
			truncate(dev.DeviceType, 15), status)
	}
	fmt.Printf("\n%d devices total\n", len(devices))
}

func cmdProtect(ifaceName string) {
	database := initDB()
	defer database.Close()

	if len(os.Args) < 3 {
		macs, _ := database.GetProtectedMACs()
		if len(macs) == 0 {
			fmt.Println("No protected devices.")
			fmt.Println("Usage: njanet protect add <ip> [label]")
			fmt.Println("       njanet protect remove <ip>")
			fmt.Println("       njanet protect list")
			return
		}
		fmt.Println("Protected devices (excluded from hog):")
		for _, m := range macs {
			devices, _ := database.GetAllDevices()
			label := m
			for _, d := range devices {
				if d.MAC == m {
					label = fmt.Sprintf("%s (%s)", d.Nickname, d.IP)
					if d.Nickname == "" {
						label = fmt.Sprintf("%s (%s)", d.Hostname, d.IP)
					}
					break
				}
			}
			fmt.Printf("  - %s\n", label)
		}
		return
	}

	sub := os.Args[2]
	switch sub {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: njanet protect add <ip>")
			return
		}
		target := os.Args[3]
		if !isValidIP(target) && !isValidMAC(target) {
			fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
			os.Exit(1)
		}
		label := ""
		if len(os.Args) >= 5 {
			label = os.Args[4]
		}

		// Try to resolve IP to MAC
		mac, err := database.FindMACByIP(target)
		if err == nil && mac != "" {
			database.AddProtectedMAC(mac, label)
			fmt.Printf("Protected: %s (MAC: %s)\n", target, mac)
		} else if len(target) == 17 && strings.Contains(target, ":") {
			// It's already a MAC
			database.AddProtectedMAC(target, label)
			fmt.Printf("Protected: %s\n", target)
		} else {
			// Unknown device, just use IP
			database.AddProtectedMAC(target, label)
			fmt.Printf("Protected: %s (IP based - may not work across networks)\n", target)
		}

	case "remove", "rm", "delete":
		if len(os.Args) < 4 {
			fmt.Println("Usage: njanet protect remove <ip>")
			return
		}
		target := os.Args[3]
		if !isValidIP(target) && !isValidMAC(target) {
			fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
			os.Exit(1)
		}
		// Remove by MAC and by IP (for backward compatibility)
		mac, _ := database.FindMACByIP(target)
		if mac != "" {
			database.RemoveProtectedMAC(mac)
		}
		database.RemoveProtectedByIP(target)
		fmt.Printf("Removed protection: %s\n", target)

	case "list", "ls":
		macs, _ := database.GetProtectedMACs()
		if len(macs) == 0 {
			fmt.Println("No protected devices.")
			return
		}
		fmt.Println("Protected devices:")
		for _, m := range macs {
			devices, _ := database.GetAllDevices()
			label := m
			for _, d := range devices {
				if d.MAC == m {
					name := d.Nickname
					if name == "" {
						name = d.Hostname
					}
					if name != "" {
						label = fmt.Sprintf("%s (%s - %s)", name, d.IP, m)
					} else {
						label = fmt.Sprintf("%s (%s)", d.IP, m)
					}
					break
				}
			}
			fmt.Printf("  - %s\n", label)
		}

	default:
		fmt.Println("Usage: njanet protect add <ip> [label]")
		fmt.Println("       njanet protect remove <ip>")
		fmt.Println("       njanet protect list")
	}
}

func cmdRename(ifaceName string) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: njanet rename <ip> <nickname>")
		return
	}
	target := os.Args[2]
	if !isValidIP(target) && !isValidMAC(target) {
		fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
		os.Exit(1)
	}
	name := os.Args[3]

	database := initDB()
	defer database.Close()

	devices, _ := database.GetAllDevices()
	for _, d := range devices {
		if d.IP == target || d.MAC == target {
			database.UpdateDeviceNickname(d.MAC, name)
			fmt.Printf("✅ %s (%s) renamed to: %s\n", d.IP, d.MAC, name)
			return
		}
	}
	fmt.Printf("Device %s not found. Run 'njanet scan' first.\n", target)
}

func cmdBlock(ifaceName string) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: njanet block <ip-address>")
		return
	}
	target := os.Args[2]
	if !isValidIP(target) && !isValidMAC(target) {
		fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
		os.Exit(1)
	}

	database := initDB()
	ctrl := initController(ifaceName)
	defer database.Close()

	dev := findDevice(target, database)
	if dev == nil {
		dev = &db.Device{MAC: "00:00:00:00:00:00", IP: target}
	}

	if err := ctrl.BlockDevice(dev); err != nil {
		fmt.Fprintf(os.Stderr, "Block failed: %v\n", err)
		os.Exit(1)
	}
	database.UpdateDeviceBlock(dev.MAC, true)
	fmt.Printf("🔴 Blocked: %s (%s)\n", target, dev.MAC)
}

func cmdUnblock(ifaceName string) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: njanet unblock <ip-address>")
		return
	}
	target := os.Args[2]
	if !isValidIP(target) && !isValidMAC(target) {
		fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
		os.Exit(1)
	}

	database := initDB()
	ctrl := initController(ifaceName)
	defer database.Close()

	dev := findDevice(target, database)
	if dev == nil {
		dev = &db.Device{MAC: "00:00:00:00:00:00", IP: target}
	}

	if err := ctrl.UnblockDevice(dev); err != nil {
		fmt.Fprintf(os.Stderr, "Unblock failed: %v\n", err)
		os.Exit(1)
	}
	database.UpdateDeviceBlock(dev.MAC, false)
	fmt.Printf("🟢 Unblocked: %s (%s)\n", target, dev.MAC)
}

func cmdThrottle(ifaceName string) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: njanet throttle <ip-address> <speed-kbps>")
		fmt.Println("       njanet throttle <ip-address> 0  (unlimited)")
		return
	}
	target := os.Args[2]
	if !isValidIP(target) && !isValidMAC(target) {
		fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
		os.Exit(1)
	}
	speed, err := parseInt(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid speed: %s\n", os.Args[3])
		os.Exit(1)
	}

	database := initDB()
	ctrl := initController(ifaceName)
	defer database.Close()

	dev := findDevice(target, database)
	if dev == nil {
		dev = &db.Device{MAC: "00:00:00:00:00:00", IP: target}
	}
	// Check for --watch flag
	watchMode := false
	for _, a := range os.Args {
		if a == "--watch" || a == "-w" {
			watchMode = true
		}
	}

	if speed == 0 {
		ctrl.ThrottleDevice(dev, 0)
		database.UpdateDeviceSpeed(dev.MAC, 0)
		fmt.Printf("⚡ Unlimited: %s\n", target)
		return
	}

	if err := ctrl.ThrottleDevice(dev, speed); err != nil {
		fmt.Fprintf(os.Stderr, "Throttle failed: %v\n", err)
		os.Exit(1)
	}
	database.UpdateDeviceSpeed(dev.MAC, speed)

	if watchMode && dev.MAC != "00:00:00:00:00:00" {
		database.AddWatch(dev.MAC, dev.IP, "throttle", speed, false)
		fmt.Printf("🔍 Watch active for %s (MAC: %s)\n", target, dev.MAC)
		fmt.Println("   Auto-track IP changes every 10s")
	}

	fmt.Printf("🐢 Throttled: %s -> %d Kbps\n", target, speed)
	fmt.Println("⏳ Press Ctrl+C to stop")
	fmt.Println()

	// Start watch loop if enabled
	if watchMode && dev.MAC != "00:00:00:00:00:00" {
		sc := initScanner(ifaceName)
		go func() {
			for {
				entries, _ := database.GetWatchlist()
				for _, e := range entries {
					if !e.Active || e.MAC == "" {
						continue
					}
					ctx := context.Background()
					result, err := sc.Scan(ctx)
					if err != nil {
						continue
					}
					for _, d := range result.Devices {
						if d.MAC == e.MAC && d.IP != e.IP {
							fmt.Printf("\n🔍 %s changed IP: %s -> %s\n", e.MAC, e.IP, d.IP)
							ctrl.ThrottleDevice(d, e.SpeedKbps)
							database.UpdateWatchIP(e.MAC, d.IP)
							fmt.Printf("   Re-applied throttle to %s\n", d.IP)
						}
					}
				}
				time.Sleep(10 * time.Second)
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🔄 Restoring network...")
	ctrl.ThrottleDevice(dev, 0)
	database.UpdateDeviceSpeed(dev.MAC, 0)
	if dev.MAC != "00:00:00:00:00:00" {
		database.DeactivateWatch(dev.MAC)
	}
	fmt.Println("✅ Network restored")
}

func cmdReset(ifaceName string) {
	ctrl := initController(ifaceName)
	if err := ctrl.Reset(); err != nil {
		fmt.Fprintf(os.Stderr, "Reset failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ All rules reset")
}

func cmdStats(ifaceName string) {
	database := initDB()
	defer database.Close()

	devices, _ := database.GetAllDevices()
	online := 0
	blocked := 0
	var totalIn, totalOut int64

	for _, d := range devices {
		if d.Online {
			online++
		}
		if d.Blocked {
			blocked++
		}
		totalIn += d.TrafficIn
		totalOut += d.TrafficOut
	}

	fmt.Printf("📊 NjaNet Statistics\n")
	fmt.Printf(string(repeatChar('-', 40)) + "\n")
	fmt.Printf("Total devices:   %d\n", len(devices))
	fmt.Printf("Online devices:  %d\n", online)
	fmt.Printf("Blocked devices: %d\n", blocked)
	fmt.Printf("Traffic in:      %s\n", formatBytes(totalIn))
	fmt.Printf("Traffic out:     %s\n", formatBytes(totalOut))
}

func cmdDefend(ifaceName string) {
	gatewayIP := getGatewayIP()
	gatewayMAC := resolveGatewayMAC()

	if gatewayMAC == "" {
		fmt.Println("❌ Cannot determine gateway MAC. Run 'njanet scan' first.")
		return
	}

	fmt.Printf("🛡️  NjaNet ARP Defense\n")
	fmt.Printf("   Gateway:  %s → %s (trusted)\n", gatewayIP, gatewayMAC)
	fmt.Println()

	defender := scanner.NewARPDefender(ifaceName, gatewayIP, gatewayMAC, getMyIP(ifaceName), getLocalMAC(ifaceName))
	defender.SetAlertFunc(func(alert scanner.ARPSpoofAlert) {
		fmt.Println()
		fmt.Println("══════════════════════════════════════════")
		fmt.Println("⚠️  ARP SPOOFING ATTACK DETECTED!")
		fmt.Println("══════════════════════════════════════════")
		if alert.SpooferIP != "" && alert.SpooferIP != "multiple" {
			fmt.Printf("👤 Attacker:    %s (MAC: %s)\n", alert.SpooferIP, alert.FakeMAC)
			fmt.Printf("   💡 Run: sudo njanet block %s\n", alert.SpooferIP)
			fmt.Printf("   💡 Or:   sudo njanet throttle %s 64\n", alert.SpooferIP)
		}
		fmt.Println("══════════════════════════════════════════")
	})

	defender.Start(true)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	defender.Stop()
}

func getLocalMAC(ifaceName string) string {
	data, err := os.ReadFile("/sys/class/net/" + ifaceName + "/address")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func resolveGatewayMAC() string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	gatewayIP := getGatewayIP()
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == gatewayIP && fields[3] != "(incomplete)" {
			return strings.ToUpper(fields[3])
		}
	}
	return ""
}

func cmdMonitor(ifaceName string) {
	sc := initScanner(ifaceName)
	ctx := context.Background()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("📡 Network Monitor (Ctrl+C to stop)")
	fmt.Println()

	for {
		select {
		case <-sigCh:
			fmt.Println("\nMonitor stopped.")
			return
		default:
			result, err := sc.Scan(ctx)
			if err == nil {
				// Save to DB
				database := initDB()
				for _, dev := range result.Devices {
					database.UpsertDevice(dev)
				}
				database.Close()

				// Clear screen and print
				fmt.Print("\033[H\033[2J")
				fmt.Printf("📡 %s — %d devices (%d online)\n",
					time.Now().Format("15:04:05"), result.Total, result.Online)
				fmt.Println(strings.Repeat("─", 70))
				fmt.Printf("%-18s %-20s %-12s %s\n", "IP", "Hostname", "Vendor", "Status")
				fmt.Println(strings.Repeat("─", 70))

				for _, dev := range result.Devices {
					hostname := dev.Nickname
					if hostname == "" {
						hostname = dev.Hostname
					}
					if hostname == "" {
						hostname = "-"
					}
					status := "up"
					if !dev.Online {
						status = "off"
					}
					fmt.Printf("%-18s %-20s %-12s %s\n",
						dev.IP, truncate(hostname, 18), truncate(dev.Vendor, 10), status)
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func cmdWeb(ifaceName string) {
	database := initDB()
	sc := initScanner(ifaceName)
	ctrl := initController(ifaceName)
	defer database.Close()

	apiServer := api.New(database, sc, ctrl)

	fmt.Printf("🌐 NjaNet Web Dashboard\n")
	fmt.Printf("   Listening on: http://localhost:%d\n", apiPort)
	fmt.Printf("   Interface:    %s\n", ifaceName)
	fmt.Printf("   Subnet:       %s\n", sc.Subnet())
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	go func() {
		// Do an initial scan
		ctx := context.Background()
		result, err := sc.Scan(ctx)
		if err == nil {
			for _, dev := range result.Devices {
				database.UpsertDevice(dev)
			}
			database.LogScan(result.Total, result.Online)
			fmt.Printf("   Initial scan: %d devices found\n", result.Total)
		}
	}()

	if err := apiServer.Start(apiPort); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}


func cmdHog(ifaceName string) {
	speed := 64
	if len(os.Args) >= 3 {
		s, err := strconv.Atoi(os.Args[2])
		if err == nil && s > 0 {
			speed = s
		}
	}

	database := initDB()
	defer database.Close()

	// Scan to get current devices
	fmt.Println("🔍 Scanning network for devices...")
	sc := initScanner(ifaceName)
	ctx := context.Background()
	result, err := sc.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	myIP := getMyIP(ifaceName)
	fmt.Printf("   Your IP: %s\n", myIP)
	fmt.Printf("   Devices found: %d\n", len(result.Devices))
	fmt.Println()

	ctrl := initController(ifaceName)

	// Load protected IPs
	protectedMACs, _ := database.GetProtectedMACs()
	protected := make(map[string]bool)
	for _, mac := range protectedMACs {
		protected[mac] = true
	}
	if len(protectedMACs) > 0 {
		fmt.Printf("   Protected: %v\n", protectedMACs)
	}

	count := 0
	for _, dev := range result.Devices {
		if dev.IP == myIP {
			fmt.Printf("   ⏭️  Skip: %s (your device)\n", dev.IP)
			continue
		}
		if protected[dev.MAC] {
			fmt.Printf("   Skip: %s (protected)\n", dev.IP)
			continue
		}
		if dev.MAC == "00:00:00:00:00:00" {
			continue
		}
		fmt.Printf("   Throttling %s -> %d Kbps\n", dev.IP, speed)
		ctrl.ThrottleDevice(dev, speed)
		database.UpdateDeviceSpeed(dev.MAC, speed)
		count++
	}

	fmt.Printf("\n✅ %d devices throttled to %d Kbps\n", count, speed)
	fmt.Println("⏳ Press Ctrl+C to stop hogging and restore all")
	fmt.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Restore all
	fmt.Println("\n🔄 Restoring all devices...")
	for _, dev := range result.Devices {
		if dev.IP == myIP || dev.MAC == "00:00:00:00:00:00" {
			continue
		}
		if protected[dev.MAC] {
			continue
		}
		ctrl.ThrottleDevice(dev, 0)
		database.UpdateDeviceSpeed(dev.MAC, 0)
	}
	fmt.Println("✅ All devices restored")
}

// --- Helpers ---

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
	// Try by IP first
	devices, _ := database.GetAllDevices()
	for _, d := range devices {
		if d.IP == target || d.MAC == target {
			return d
		}
	}
	return nil
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
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

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot get home dir: %v, using /tmp\n", err)
		home = "/tmp"
	}
	dbPath = filepath.Join(home, ".njanet", "njanet.db")

	// Handle JSON output for commands
	if len(os.Args) > 1 && os.Args[1] == "--json" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		os.Setenv("NJANET_JSON", "1")
	}
}

func printJSON(v interface{}) {
	if os.Getenv("NJANET_JSON") == "1" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
	}
}
