package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
)

// --- Scan ---

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

	for _, dev := range result.Devices {
		database.UpsertDevice(dev)
	}
	database.LogScan(result.Total, result.Online)

	fmt.Printf("✅ Scan completed in %s\n", result.Duration)
	fmt.Printf("   Devices found: %d (%d online)\n", result.Total, result.Online)
	fmt.Println()

	fmt.Printf("%-16s %-18s %-20s %-12s %s\n",
		"IP", "MAC", "Hostname", "Vendor", "Status")
	fmt.Println(strings.Repeat("-", 80))

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

// --- List ---

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
	fmt.Println(strings.Repeat("-", 90))

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

// --- Protect ---

func cmdProtect(ifaceName string) {
	database := initDB()
	defer database.Close()

	if len(os.Args) < 3 {
		macs, _ := database.GetProtectedMACs()
		if len(macs) == 0 {
			fmt.Println("No protected devices.")
			fmt.Println("Usage: njanet protect add <ip> [label]  (p a)")
			fmt.Println("       njanet protect remove <ip>       (p r)")
			fmt.Println("       njanet protect list              (p l)")
			return
		}
		fmt.Println("Protected devices (excluded from hog):")
		devices, _ := database.GetAllDevices()
		byMAC := make(map[string]*db.Device, len(devices))
		for _, d := range devices {
			byMAC[d.MAC] = d
		}
		for _, m := range macs {
			label := m
			if d, ok := byMAC[m]; ok {
				name := d.Nickname
				if name == "" {
					name = d.Hostname
				}
				if name != "" {
					label = fmt.Sprintf("%s (%s)", name, d.IP)
				} else {
					label = fmt.Sprintf("%s (%s)", d.IP, m)
				}
			}
			fmt.Printf("  - %s\n", label)
		}
		return
	}

	sub := os.Args[2]
	switch sub {
	case "add", "a":
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

		mac, err := database.FindMACByIP(target)
		if err == nil && mac != "" {
			database.AddProtectedMAC(mac, label)
			fmt.Printf("Protected: %s (MAC: %s)\n", target, mac)
		} else if len(target) == 17 && strings.Contains(target, ":") {
			database.AddProtectedMAC(target, label)
			fmt.Printf("Protected: %s\n", target)
		} else {
			database.AddProtectedMAC(target, label)
			fmt.Printf("Protected: %s (IP based - may not work across networks)\n", target)
		}

	case "remove", "rm", "delete", "r":
		if len(os.Args) < 4 {
			fmt.Println("Usage: njanet protect remove <ip>")
			return
		}
		target := os.Args[3]
		if !isValidIP(target) && !isValidMAC(target) {
			fmt.Fprintf(os.Stderr, "Invalid IP or MAC address: %s\n", target)
			os.Exit(1)
		}
		mac, _ := database.FindMACByIP(target)
		if mac != "" {
			database.RemoveProtectedMAC(mac)
		}
		database.RemoveProtectedByIP(target)
		fmt.Printf("Removed protection: %s\n", target)

	case "list", "ls", "l":
		macs, _ := database.GetProtectedMACs()
		if len(macs) == 0 {
			fmt.Println("No protected devices.")
			return
		}
		fmt.Println("Protected devices:")
		devices, _ := database.GetAllDevices()
		byMAC := make(map[string]*db.Device, len(devices))
		for _, d := range devices {
			byMAC[d.MAC] = d
		}
		for _, m := range macs {
			label := m
			if d, ok := byMAC[m]; ok {
				name := d.Nickname
				if name == "" {
					name = d.Hostname
				}
				if name != "" {
					label = fmt.Sprintf("%s (%s - %s)", name, d.IP, m)
				} else {
					label = fmt.Sprintf("%s (%s)", d.IP, m)
				}
			}
			fmt.Printf("  - %s\n", label)
		}

	default:
		fmt.Println("Usage: njanet protect add <ip> [label]  (p a)")
		fmt.Println("       njanet protect remove <ip>       (p r)")
		fmt.Println("       njanet protect list              (p l)")
	}
}

// --- Rename ---

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

// --- Block / Unblock ---

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
		resolvedMAC := resolveMAC(target)
		dev = &db.Device{MAC: resolvedMAC, IP: target}
		if resolvedMAC != "" {
			database.UpsertDevice(dev)
		}
	}

	if dev.MAC == "" {
		fmt.Fprintf(os.Stderr, "Perangkat %s tidak dikenal (MAC tidak ketemu). Jalankan 'sudo njanet scan' dan pastikan perangkat online.\n", target)
		os.Exit(1)
	}
	if guardSelfTarget([]string{target, dev.IP}, ifaceName) {
		os.Exit(1)
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
		resolvedMAC := resolveMAC(target)
		dev = &db.Device{MAC: resolvedMAC, IP: target}
		if resolvedMAC != "" {
			database.UpsertDevice(dev)
		}
	}

	if err := ctrl.UnblockDevice(dev); err != nil {
		fmt.Fprintf(os.Stderr, "Unblock failed: %v\n", err)
		os.Exit(1)
	}
	database.UpdateDeviceBlock(dev.MAC, false)
	fmt.Printf("🟢 Unblocked: %s (%s)\n", target, dev.MAC)
}

// --- Throttle ---

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
		resolvedMAC := resolveMAC(target)
		dev = &db.Device{MAC: resolvedMAC, IP: target}
		if resolvedMAC != "" {
			database.UpsertDevice(dev)
		}
	}

	if dev.MAC == "" {
		fmt.Fprintf(os.Stderr, "Perangkat %s tidak dikenal (MAC tidak ketemu). Jalankan 'sudo njanet scan' dan pastikan perangkat online.\n", target)
		os.Exit(1)
	}
	if guardSelfTarget([]string{target, dev.IP}, ifaceName) {
		os.Exit(1)
	}

	watchMode := false
	for _, a := range os.Args {
		if a == "--watch" || a == "-w" {
			watchMode = true
		}
	}

	if speed == 0 {
		if err := ctrl.ThrottleDevice(dev, 0); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove throttle: %v\n", err)
			os.Exit(1)
		}
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

	var watchWG sync.WaitGroup
	stopWatch := make(chan struct{})
	if watchMode && dev.MAC != "00:00:00:00:00:00" {
		sc := initScanner(ifaceName)
		watchWG.Add(1)
		go func() {
			defer watchWG.Done()
			for {
				// Scan once per tick, then match every active watch entry against it.
				entries, _ := database.GetWatchlist()
				ctx := context.Background()
				result, err := sc.Scan(ctx)
				if err == nil {
					for _, e := range entries {
						if !e.Active || e.MAC == "" {
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
				}
				select {
				case <-stopWatch:
					return
				case <-time.After(10 * time.Second):
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🔄 Restoring network...")
	if watchMode && dev.MAC != "00:00:00:00:00:00" {
		close(stopWatch)
	}
	ctrl.ThrottleDevice(dev, 0)
	database.UpdateDeviceSpeed(dev.MAC, 0)
	if dev.MAC != "00:00:00:00:00:00" {
		database.DeactivateWatch(dev.MAC)
	}
	// Wait for the watch goroutine to stop before the deferred DB close.
	watchWG.Wait()
	fmt.Println("✅ Network restored")
}

// --- Hog ---

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

	ctrl := initController(ifaceName)
	if !ctrl.IsReady() {
		fmt.Fprintf(os.Stderr, "❌ Root required: run with sudo for hog\n")
		os.Exit(1)
	}

	fmt.Println("🔍 Scanning network for devices...")
	sc := initScanner(ifaceName)
	ctx := context.Background()
	result, err := sc.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	myIP := getMyIP(ifaceName)
	gatewayIP := getGatewayIP()
	fmt.Printf("   Your IP: %s\n", myIP)
	fmt.Printf("   Devices found: %d\n", len(result.Devices))
	fmt.Println()

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
		if dev.IP == gatewayIP {
			fmt.Printf("   ⏭️  Skip: %s (gateway)\n", dev.IP)
			continue
		}
		if protected[dev.MAC] {
			fmt.Printf("   Skip: %s (protected)\n", dev.IP)
			continue
		}
		if dev.MAC == "00:00:00:00:00:00" {
			continue
		}
		if err := ctrl.ThrottleDevice(dev, speed); err != nil {
			fmt.Printf("   ⚠️  Failed: %s (%v)\n", dev.IP, err)
			continue
		}
		fmt.Printf("   Throttling %s -> %d Kbps\n", dev.IP, speed)
		database.UpdateDeviceSpeed(dev.MAC, speed)
		count++
	}

	fmt.Printf("\n✅ %d devices throttled to %d Kbps\n", count, speed)
	fmt.Println("⏳ Press Ctrl+C to stop hogging and restore all")
	fmt.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n🔄 Restoring all devices...")
	for _, dev := range result.Devices {
		if dev.IP == myIP || dev.IP == gatewayIP || dev.MAC == "00:00:00:00:00:00" {
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

// --- Monitor ---

func cmdMonitor(ifaceName string) {
	sc := initScanner(ifaceName)
	database := initDB()
	defer database.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Println("📡 Network Monitor (Ctrl+C to stop)")
	fmt.Println()

	for {
		if ctx.Err() != nil {
			return
		}

		result, err := sc.Scan(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		for _, dev := range result.Devices {
			database.UpsertDevice(dev)
		}

		fmt.Printf("\n📡 %s — %d devices (%d online)\n",
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

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// --- Stats ---

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
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Total devices:   %d\n", len(devices))
	fmt.Printf("Online devices:  %d\n", online)
	fmt.Printf("Blocked devices: %d\n", blocked)
	fmt.Printf("Traffic in:      %s\n", formatBytes(totalIn))
	fmt.Printf("Traffic out:     %s\n", formatBytes(totalOut))
}

// --- Defend ---

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

// --- Reset ---

func cmdReset(ifaceName string) {
	database := initDB()
	defer database.Close()
	ctrl := initController(ifaceName)

	// Remove only the FORWARD DROP rules NjaNet created for each blocked device.
	// Never flush whole iptables chains — that would wipe other firewall rules (ufw/firewalld).
	devices, _ := database.GetAllDevices()
	for _, dev := range devices {
		if dev.Blocked {
			ctrl.RemoveForwardDropRules(dev.IP)
			database.UpdateDeviceBlock(dev.MAC, false)
		}
		if dev.SpeedLimit > 0 {
			database.UpdateDeviceSpeed(dev.MAC, 0)
		}
	}

	if err := ctrl.Reset(); err != nil {
		fmt.Fprintf(os.Stderr, "Reset failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ All NjaNet rules reset")
}

// --- Router Web Scan ---

func cmdRouter(ifaceName string) {
	gateway := getGatewayIP()
	ports := []int{80, 443, 8080, 8443, 3000, 5000, 7001, 9000, 9090, 10000}

	fmt.Printf("🔍 Scanning router web interface: %s\n\n", gateway)

	// Timeout prevents hanging on ports that accept TCP but never respond to HTTP
	client := &http.Client{Timeout: 3 * time.Second}

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", gateway, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// Try to get the title/name
		protocol := "http"
		if port == 443 || port == 8443 {
			protocol = "https"
		}
		title := ""
		url := fmt.Sprintf("%s://%s:%d", protocol, gateway, port)
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			// Extract title
			content := string(body)
			if start := strings.Index(content, "<title>"); start != -1 {
				start += 7
				if end := strings.Index(content[start:], "</title>"); end != -1 {
					title = strings.TrimSpace(content[start : start+end])
					if len(title) > 60 {
						title = title[:60] + "..."
					}
				}
			}
		}

		status := "🔴"
		if title != "" {
			status = "🟢"
		}
		fmt.Printf("  %s  Port %d", status, port)
		if title != "" {
			fmt.Printf("  →  %s", title)
		}
		fmt.Println()
	}
	fmt.Println()
	fmt.Println("✅ Scan complete")
}
