package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mectov/njanet/internal/api"
	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
	"github.com/mectov/njanet/internal/ui/tui"
)

const (
	dbPath = "/home/mectov/.njanet/njanet.db"
	apiPort = 8484
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	// Determine network interface
	ifaceName := os.Getenv("NETCTL_IFACE")
	if ifaceName == "" {
			ifaceName = autoDetectInterface()
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan":
		cmdScan(ifaceName)
	case "web":
		cmdWeb(ifaceName)
	case "dashboard", "dash", "tui", "top":
		cmdDashboard(ifaceName)
	case "list", "ls":
		cmdList(ifaceName)
	case "rename", "name":
		cmdRename(ifaceName)
	case "block":
		cmdBlock(ifaceName)
	case "unblock":
		cmdUnblock(ifaceName)
	case "throttle":
		cmdThrottle(ifaceName)
	case "reset":
		cmdReset(ifaceName)
	case "stats":
		cmdStats(ifaceName)
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
  njanet dashboard         Interactive TUI dashboard (like htop)
  njanet web               Start web dashboard
  njanet block <mac/ip>    Block device
  njanet unblock <mac/ip>  Unblock device
  njanet throttle <mac/ip> <speed_kbps>  Limit bandwidth
  njanet rename <ip> <name>  Set device nickname
  njanet stats             Show network stats
  njanet reset             Reset all rules
  njanet monitor           Live monitor network

Environment:
  NETCTL_IFACE  Network interface (default: enp2s0)

Examples:
  njanet scan
  njanet dashboard
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
	// Try NETCTL_IFACE env first
	if env := os.Getenv("NETCTL_IFACE"); env != "" {
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

func cmdRename(ifaceName string) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: njanet rename <ip> <nickname>")
		return
	}
	target := os.Args[2]
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

		fmt.Printf("🐢 Throttled: %s -> %d Kbps\n", target, speed)
		fmt.Println("⏳ Press Ctrl+C to stop throttling")
		fmt.Println()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		fmt.Println("\n🔄 Restoring network...")
		ctrl.ThrottleDevice(dev, 0)
		database.UpdateDeviceSpeed(dev.MAC, 0)
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

func cmdMonitor(ifaceName string) {
	fmt.Println("📡 Monitoring network (Ctrl+C to stop)...")
	fmt.Println()

	// Simple monitor: scan every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Initial scan
	sc := initScanner(ifaceName)
	ctx := context.Background()

	doScan := func() {
		result, err := sc.Scan(ctx)
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			return
		}
		fmt.Printf("\r[%s] %d devices online    ", time.Now().Format("15:04:05"), result.Online)
	}

	doScan()

	for {
		select {
		case <-ticker.C:
			doScan()
		case <-sigCh:
			fmt.Println("\n\nMonitor stopped.")
			return
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

func cmdDashboard(ifaceName string) {
	database := initDB()
	sc := initScanner(ifaceName)
	ctrl := initController(ifaceName)
	defer database.Close()

	fmt.Print("\033[2J\033[H")
	fmt.Println("📡  NjaNet Dashboard — starting...")
	fmt.Println("   Scanning network for devices...")
	fmt.Println()

	ctx := context.Background()
	result, err := sc.Scan(ctx)
	if err == nil {
		for _, dev := range result.Devices {
			database.UpsertDevice(dev)
		}
		database.LogScan(result.Total, result.Online)
	}

	if !ctrl.IsReady() {
		fmt.Println("   ⚠️  Run with 'sudo njanet dashboard' to enable block/throttle features")
		fmt.Println("   📡 View-only mode — scan & monitor still work\n")
		time.Sleep(2 * time.Second)
	}

	dash := tui.New(sc, ctrl, database)
	if err := dash.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		os.Exit(1)
	}
}

// --- Helpers ---

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

// For JSON pretty printing
func init() {
	// Handle JSON output for commands
	if len(os.Args) > 1 && os.Args[1] == "--json" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		os.Setenv("NETCTL_JSON", "1")
	}
}

func printJSON(v interface{}) {
	if os.Getenv("NETCTL_JSON") == "1" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
	}
}
