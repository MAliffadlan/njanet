package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
	"github.com/mectov/njanet/internal/scanner"
)

type Dashboard struct {
	scanner    *scanner.Scanner
	controller *controller.Controller
	db         *db.Database

	devices []*db.Device
	mu      sync.RWMutex
	running bool
	refresh time.Duration

	selectedRow int
	mode        string // "overview", "detail", "help"
	selectedMAC string
	searchQuery string

	// Stats
	startTime    time.Time
	totalScans   int
	totalDevices int
}

func New(sc *scanner.Scanner, ctrl *controller.Controller, database *db.Database) *Dashboard {
	return &Dashboard{
		scanner:    sc,
		controller: ctrl,
		db:         database,
		refresh:    3 * time.Second,
		selectedRow: 1,
		mode:       "overview",
		startTime:  time.Now(),
	}
}

func (d *Dashboard) Run() error {
	d.running = true

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)

	// Initial scan
	go d.doScan()

	ticker := time.NewTicker(d.refresh)
	defer ticker.Stop()

	// Set terminal to raw mode (from Run, not from goroutine)
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "-echo").Run()

	// Hide cursor
	fmt.Print("\033[?25l")
	fmt.Print("\033[2J")
	fmt.Print("\033[H")

	// THIS is the critical fix: restore terminal fully on exit
	defer func() {
		// Show cursor
		fmt.Print("\033[?25h")
		fmt.Print("\033[2J")
		fmt.Print("\033[H")

		// FULL terminal reset — this fixes the "can't type after quit" bug
		exec.Command("stty", "-F", "/dev/tty", "sane").Run()
		exec.Command("stty", "-F", "/dev/tty", "echo").Run()
		exec.Command("stty", "-F", "/dev/tty", "cooked").Run()
	}()

	// Start input reader (raw mode already set above)
	go d.readInput()

	// Get terminal size
	termWidth, termHeight := d.getTermSize()

	for d.running {
		select {
		case <-ticker.C:
			d.mu.RLock()
			mode := d.mode
			d.mu.RUnlock()
			if mode != "detail" {
				go d.doScan()
			}
		case <-sigCh:
			d.running = false
		default:
			// Render
			d.render(termWidth, termHeight)
			time.Sleep(100 * time.Millisecond)

			// Re-check terminal size
			if w, h := d.getTermSize(); w != termWidth || h != termHeight {
				termWidth, termHeight = w, h
			}
		}
	}

	return nil
}

func (d *Dashboard) doScan() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := d.scanner.Scan(ctx)
	if err != nil {
		return
	}

	d.mu.Lock()
	d.devices = result.Devices
	d.totalScans++
	d.mu.Unlock()

	// Save to DB
	for _, dev := range result.Devices {
		d.db.UpsertDevice(dev)
	}
	d.db.LogScan(result.Total, result.Online)
}

func (d *Dashboard) render(w, h int) {
	buf := &strings.Builder{}

	d.mu.RLock()
	mode := d.mode
	selectedMAC := d.selectedMAC
	selectedRow := d.selectedRow
	devices := d.devices
	d.mu.RUnlock()

	// Ensure devices is never nil
	if devices == nil {
		devices = []*db.Device{}
	}

	// Sort: online first, then by IP
	sorted := make([]*db.Device, len(devices))
	copy(sorted, devices)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Online != sorted[j].Online {
			return sorted[i].Online
		}
		return sorted[i].IP < sorted[j].IP
	})

	// Bound selected row
	if selectedRow < 1 {
		selectedRow = 1
	}
	if selectedRow > len(sorted) && len(sorted) > 0 {
		selectedRow = len(sorted)
	}

	if mode == "overview" {
		d.renderOverview(buf, sorted, selectedRow, w, h)
	} else if mode == "detail" && selectedMAC != "" {
		d.renderDetail(buf, selectedMAC, w, h)
	} else if mode == "help" {
		d.renderHelp(buf, w, h)
	}

	// Render status bar at bottom
	d.renderStatusBar(buf, w, h)

	// Write to terminal
	fmt.Print("\033[H") // move cursor to home
	fmt.Print(buf.String())
}

func (d *Dashboard) renderOverview(buf *strings.Builder, devices []*db.Device, selectedRow, w, h int) {
	// Header
	buf.WriteString(d.styleHeader(" 📡 NETCTL — Network Dashboard ", w))
	buf.WriteString("\n")

	// Summary bar
	onlineCount := 0
	blockedCount := 0
	throttledCount := 0
	for _, dev := range devices {
		if dev.Online {
			onlineCount++
		}
		if dev.Blocked {
			blockedCount++
		}
		if dev.SpeedLimit > 0 {
			throttledCount++
		}
	}

	summary := fmt.Sprintf("  🟢 %d Online  🔴 %d Blocked  🐢 %d Throttled  📊 %d Total\n",
		onlineCount, blockedCount, throttledCount, len(devices))
	buf.WriteString(d.styleSummary(summary, w))
	buf.WriteString("  " + strings.Repeat("─", w-4) + "\n")

	// Table header
	header := fmt.Sprintf("  %-3s %-16s %-18s %-20s %-12s %-10s %s\n",
		"#", "IP", "MAC", "Hostname", "Vendor", "Type", "Control")
	buf.WriteString(d.styleTableHeader(header))

	// Devices
	for i, dev := range devices {
		if i > h-10 { // limit to terminal height
			buf.WriteString(fmt.Sprintf("  \033[2m... %d more devices\033[0m\n", len(devices)-i))
			break
		}

		isSelected := (i+1) == selectedRow
		prefix := "  "
		if isSelected {
			prefix = " ▸"
		}

		hostname := dev.Hostname
		if hostname == "" {
			hostname = dev.Nickname
		}
		if hostname == "" {
			hostname = "-"
		}

		vendor := dev.Vendor
		if vendor == "" {
			vendor = "-"
		}

		devType := dev.DeviceType
		if devType == "" {
			devType = "?"
		}

		control := ""
		if dev.Blocked {
			control = "\033[31mBLOCKED\033[0m"
		} else if dev.SpeedLimit > 0 {
			control = fmt.Sprintf("\033[33m%dK\033[0m", dev.SpeedLimit)
		} else {
			control = "\033[32mFULL\033[0m"
		}

		line := fmt.Sprintf("%s %-3d %-16s %-18s %-20s %-12s %-10s %s\n",
			prefix, i+1, dev.IP, dev.MAC,
			d.truncate(hostname, 20),
			d.truncate(vendor, 12),
			d.truncate(devType, 10), control)

		if isSelected {
			buf.WriteString(d.styleSelected(line))
		} else {
			buf.WriteString(line)
		}
	}
}

func (d *Dashboard) renderDetail(buf *strings.Builder, mac string, w, h int) {
	// Find device
	var dev *db.Device
	d.mu.RLock()
	for _, d2 := range d.devices {
		if d2.MAC == mac {
			dev = d2
			break
		}
	}
	d.mu.RUnlock()

	if dev == nil {
		buf.WriteString("  Device not found.\n")
		buf.WriteString("  \033[36mPress ESC to go back\033[0m\n")
		return
	}

	buf.WriteString(d.styleHeader(fmt.Sprintf(" 📋 Device Details — %s ", dev.IP), w))
	buf.WriteString("\n")

	lines := [][2]string{
		{"IP Address", dev.IP},
		{"MAC Address", dev.MAC},
		{"Hostname", dev.Hostname},
		{"Nickname", dev.Nickname},
		{"Vendor", dev.Vendor},
		{"Device Type", dev.DeviceType},
		{"Status", d.statusText(dev)},
		{"First Seen", dev.FirstSeen.Format("2006-01-02 15:04:05")},
		{"Last Seen", dev.LastSeen.Format("2006-01-02 15:04:05")},
	}

	if dev.SpeedLimit > 0 {
		lines = append(lines, [2]string{"Speed Limit", fmt.Sprintf("%d Kbps", dev.SpeedLimit)})
	}
	if dev.Blocked {
		lines = append(lines, [2]string{"Blocked", "Yes"})
	}
	if dev.OpenPorts != nil && len(dev.OpenPorts) > 0 {
		portStrs := make([]string, len(dev.OpenPorts))
		for i, p := range dev.OpenPorts {
			portStrs[i] = strconv.Itoa(p)
		}
		lines = append(lines, [2]string{"Open Ports", strings.Join(portStrs, ", ")})
	}

	for _, line := range lines {
		buf.WriteString(fmt.Sprintf("  \033[2m%-15s\033[0m %s\n", line[0], line[1]))
	}

	buf.WriteString("\n")
	buf.WriteString("  \033[36m[ESC]\033[0m Back  ")
	buf.WriteString(fmt.Sprintf(" \033[36m[B]\033[0m %s  ", d.blockUnblockText(dev)))
	buf.WriteString(fmt.Sprintf(" \033[36m[1-9]\033[0m Set speed limit  \n"))
}

func (d *Dashboard) renderHelp(buf *strings.Builder, w, h int) {
	buf.WriteString(d.styleHeader(" 📖 NETCTL — Help ", w))
	buf.WriteString("\n\n")
	buf.WriteString("  \033[36mKeyboard Shortcuts\033[0m\n")
	buf.WriteString("  ─────────────────────────────────────────────\n")
	buf.WriteString("  \033[33m↑/↓\033[0m       Navigate device list\n")
	buf.WriteString("  \033[33mEnter\033[0m     View device details\n")
	buf.WriteString("  \033[33mESC/q\033[0m    Back / Quit\n")
	buf.WriteString("  \033[33mb\033[0m        Block/Unblock selected device\n")
	buf.WriteString("  \033[33m0-9\033[0m      Set speed limit (0=unlimited)\n")
	buf.WriteString("  \033[33mt\033[0m        Throttle menu\n")
	buf.WriteString("  \033[33mr\033[0m        Refresh scan now\n")
	buf.WriteString("  \033[33mR\033[0m        Reset all rules\n")
	buf.WriteString("  \033[33m?\033[0m        Show this help\n")
	buf.WriteString("  \033[33m/\033[0m        Search\n")
	buf.WriteString("\n")
	buf.WriteString("  \033[36mCommands\033[0m (also available from terminal):\n")
	buf.WriteString("  ─────────────────────────────────────────────\n")
	buf.WriteString("  netctl scan              Scan network\n")
	buf.WriteString("  netctl list              List devices\n")
	buf.WriteString("  netctl block  <ip>       Block device\n")
	buf.WriteString("  netctl unblock <ip>      Unblock device\n")
	buf.WriteString("  netctl throttle <ip> <k> Limit bandwidth\n")
	buf.WriteString("  netctl reset             Reset all rules\n")
	buf.WriteString("  netctl stats             Show statistics\n")
	buf.WriteString("\n")
	buf.WriteString("  Press \033[33mESC\033[0m or \033[33mq\033[0m to go back\n")
}

func (d *Dashboard) renderStatusBar(buf *strings.Builder, w, h int) {
	d.mu.RLock()
	devCount := len(d.devices)
	mode := d.mode
	totalScans := d.totalScans
	d.mu.RUnlock()

	uptime := time.Since(d.startTime).Round(time.Second).String()

	var modeStr string
	switch mode {
	case "overview":
		modeStr = "DASHBOARD"
	case "detail":
		modeStr = "DETAIL"
	case "help":
		modeStr = "HELP"
	}

	bar := fmt.Sprintf("\033[30;46m %-30s | Devices: %d | Scans: %d | Uptime: %s | [?] Help | [q] Quit \033[0m",
		modeStr, devCount, totalScans, uptime)
	buf.WriteString(bar)

	// Fill remaining space
	if len(bar)-30 < w {
		buf.WriteString(strings.Repeat(" ", w-len(bar)+30))
	}
	buf.WriteString("\n")
}

func (d *Dashboard) readInput() {
	// Terminal raw mode is set by Run() — just read input directly
	buf := make([]byte, 3)
	for d.running {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}

		if n == 1 {
			switch buf[0] {
			case 'q', 3: // q or Ctrl+C
				d.running = false
				return
			case '?':
				d.mu.Lock()
				d.mode = "help"
				d.mu.Unlock()
			case 27: // ESC
				d.mu.Lock()
				if d.mode == "detail" || d.mode == "help" {
					d.mode = "overview"
				} else {
					d.running = false
				}
				d.mu.Unlock()
			case 13: // Enter
				d.mu.RLock()
				devices := d.devices
				selected := d.selectedRow
				d.mu.RUnlock()
				if selected > 0 && selected <= len(devices) {
					sorted := make([]*db.Device, len(devices))
					copy(sorted, devices)
					sort.Slice(sorted, func(i, j int) bool {
						if sorted[i].Online != sorted[j].Online {
							return sorted[i].Online
						}
						return sorted[i].IP < sorted[j].IP
					})
					if selected <= len(sorted) {
						d.mu.Lock()
						d.selectedMAC = sorted[selected-1].MAC
						d.mode = "detail"
						d.mu.Unlock()
					}
				}
			case 'b':
				d.toggleBlock()
			case 'r':
				go d.doScan()
			case 'R':
				d.controller.Reset()
				go d.doScan()
			case '0':
				d.setSpeed(0)
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				speed := int(buf[0]-'0') * 1024 // 1-9 Mbps in Kbps
				d.setSpeed(speed)
			}
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
			// Arrow keys
			switch buf[2] {
			case 'A': // Up
				d.mu.Lock()
				if d.selectedRow > 1 {
					d.selectedRow--
				}
				d.mu.Unlock()
			case 'B': // Down
				d.mu.Lock()
				d.selectedRow++
				d.mu.Unlock()
			case 'C': // Right
			case 'D': // Left
			}
		}
	}
}

func (d *Dashboard) toggleBlock() {
	d.mu.RLock()
	mode := d.mode
	selectedMAC := d.selectedMAC
	d.mu.RUnlock()

	if mode != "detail" || selectedMAC == "" {
		return
	}

	// Find device
	dev := d.findDevice(selectedMAC)
	if dev == nil {
		return
	}

	if dev.Blocked {
		d.controller.UnblockDevice(dev)
		d.db.UpdateDeviceBlock(dev.MAC, false)
		dev.Blocked = false
	} else {
		d.controller.BlockDevice(dev)
		d.db.UpdateDeviceBlock(dev.MAC, true)
		dev.Blocked = true
	}
}

func (d *Dashboard) setSpeed(speed int) {
	d.mu.RLock()
	mode := d.mode
	selectedMAC := d.selectedMAC
	d.mu.RUnlock()

	if mode != "detail" || selectedMAC == "" {
		return
	}

	dev := d.findDevice(selectedMAC)
	if dev == nil {
		return
	}

	if speed == 0 {
		d.controller.ThrottleDevice(dev, 0)
		d.db.UpdateDeviceSpeed(dev.MAC, 0)
		dev.SpeedLimit = 0
	} else {
		d.controller.ThrottleDevice(dev, speed)
		d.db.UpdateDeviceSpeed(dev.MAC, speed)
		dev.SpeedLimit = speed
	}
}

func (d *Dashboard) findDevice(mac string) *db.Device {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, dev := range d.devices {
		if dev.MAC == mac {
			return dev
		}
	}
	return nil
}

func (d *Dashboard) statusText(dev *db.Device) string {
	if dev.Blocked {
		return "\033[31m🔴 Blocked\033[0m"
	}
	if dev.Online {
		return "\033[32m🟢 Online\033[0m"
	}
	return "\033[90m⚪ Offline\033[0m"
}

func (d *Dashboard) blockUnblockText(dev *db.Device) string {
	if dev.Blocked {
		return "Unblock"
	}
	return "Block"
}

func (d *Dashboard) styleHeader(title string, w int) string {
	titleLen := len([]rune(title))
	if titleLen > w-4 {
		title = title[:w-7] + "... "
		titleLen = len([]rune(title))
	}
	padding := w - titleLen - 4
	if padding < 2 {
		padding = 2
	}
	leftPad := padding / 2
	rightPad := padding - leftPad
	return fmt.Sprintf("\033[1;37;44m%s%s%s\033[0m",
		strings.Repeat(" ", leftPad), title, strings.Repeat(" ", rightPad))
}

func (d *Dashboard) styleSummary(text string, w int) string {
	return fmt.Sprintf("\033[40m%s\033[0m", text)
}

func (d *Dashboard) styleTableHeader(text string) string {
	return fmt.Sprintf("\033[1;30;47m%s\033[0m", text)
}

func (d *Dashboard) styleSelected(text string) string {
	return fmt.Sprintf("\033[7m%s\033[0m", text)
}

func (d *Dashboard) truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

func (d *Dashboard) getTermSize() (int, int) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return 80, 24
	}

	parts := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(parts) != 2 {
		return 80, 24
	}

	h, _ := strconv.Atoi(parts[0])
	w, _ := strconv.Atoi(parts[1])
	if w < 80 {
		w = 80
	}
	if h < 12 {
		h = 12
	}
	return w, h
}

