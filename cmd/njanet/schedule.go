package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mectov/njanet/internal/controller"
	"github.com/mectov/njanet/internal/db"
)

// --- Schedule: automatic block/throttle by time window ---

func cmdSchedule(ifaceName string) {
	if len(os.Args) < 3 {
		schedList()
		return
	}
	switch os.Args[2] {
	case "add", "a":
		schedAdd(ifaceName)
	case "remove", "rm", "r", "del", "delete":
		schedRemove()
	case "list", "ls", "l":
		schedList()
	case "run":
		cmdSchedRun(ifaceName)
	default:
		printSchedUsage()
	}
}

func printSchedUsage() {
	fmt.Println(`Usage:
  njanet sched add <ip|mac> <block|kbps> <HH:MM-HH:MM> [days]  Tambah jadwal
  njanet sched list              Lihat semua jadwal
  njanet sched remove <id|ip|mac>  Hapus jadwal
  sudo njanet sched run [--every 30s]  Jalankan penjadwal (daemon)

Contoh:
  njanet sched add 192.168.1.8 block 00:00-06:00
  njanet sched add 192.168.1.8 64 22:00-06:00 weekdays
  njanet sched add AA:BB:CC:DD:EE:FF block 08:00-17:00 weekend

days: daily (default), weekdays, weekend, atau mon,tue,wed,thu,fri,sat,sun
Window boleh lewat tengah malam, mis. 22:00-06:00.`)
}

// --- add ---

func schedAdd(ifaceName string) {
	if len(os.Args) < 6 {
		printSchedUsage()
		return
	}
	target := os.Args[3]
	actionArg := strings.ToLower(os.Args[4])
	windowArg := os.Args[5]
	daysArg := "daily"
	if len(os.Args) >= 7 {
		daysArg = os.Args[6]
	}

	action := ""
	speed := 0
	if actionArg == "block" {
		action = "block"
	} else {
		s, err := strconv.Atoi(actionArg)
		if err != nil || s <= 0 {
			fmt.Fprintf(os.Stderr, "Aksi tidak valid: %s (pakai 'block' atau angka Kbps, mis. 64)\n", os.Args[4])
			os.Exit(1)
		}
		action = "throttle"
		speed = s
	}

	startMin, endMin, err := parseWindow(windowArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Window tidak valid: %v\n", err)
		os.Exit(1)
	}

	days, err := parseDays(daysArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hari tidak valid: %v\n", err)
		os.Exit(1)
	}

	database := initDB()
	defer database.Close()

	mac, ip := resolveSchedTarget(target, database)
	if mac == "" {
		fmt.Fprintf(os.Stderr, "Perangkat %s tidak dikenal. Jalankan 'sudo njanet scan' dulu dan pastikan perangkat online.\n", target)
		os.Exit(1)
	}

	// Jangan izinkan jadwal untuk laptop sendiri / gateway.
	cands := []string{ip}
	if isValidIP(target) {
		cands = append(cands, target)
	}
	if guardSelfTarget(cands, ifaceName) {
		os.Exit(1)
	}

	// Tolak aturan yang tumpang tindih untuk MAC yang sama — dua aturan
	// aktif bersamaan untuk satu perangkat akan saling menimpa tiap tick.
	existing, _ := database.GetSchedules()
	for _, e := range existing {
		if e.MAC == mac && daysIntersect(e.Days, days) &&
			windowsOverlap(e.StartMin, e.EndMin, startMin, endMin) {
			fmt.Fprintf(os.Stderr, "Jadwal #%d untuk %s sudah mencakup %s pada %s — hapus dulu sebelum tambah yang baru.\n",
				e.ID, mac, fmtDays(e.Days), fmtWindow(e.StartMin, e.EndMin))
			os.Exit(1)
		}
	}

	id, err := database.AddSchedule(mac, ip, action, speed, startMin, endMin, days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gagal simpan jadwal: %v\n", err)
		os.Exit(1)
	}

	desc := "block"
	if action == "throttle" {
		desc = fmt.Sprintf("throttle %d Kbps", speed)
	}
	fmt.Printf("✅ Jadwal #%d: %s (%s) → %s, %s, %s\n", id, ipOrDash(ip), mac, desc,
		fmtWindow(startMin, endMin), fmtDays(days))
	if ip == "" {
		fmt.Println("   Perangkat sedang offline — aturan aktif otomatis saat muncul di jaringan.")
	}
	fmt.Println("   Jalankan daemon: sudo njanet sched run")
}

// resolveSchedTarget turns an IP or MAC into a (MAC, IP) pair.
// An IP target must be confirmed by the current ARP table: falling back to a
// stale DB row could schedule an innocent device that received the IP later.
// IP may be empty for MAC targets that are currently offline.
func resolveSchedTarget(target string, database *db.Database) (mac, ip string) {
	if !isValidIP(target) && !isValidMAC(target) {
		fmt.Fprintf(os.Stderr, "IP atau MAC tidak valid: %s\n", target)
		os.Exit(1)
	}
	if isValidIP(target) {
		m := resolveMAC(target)
		if m == "" {
			return "", ""
		}
		database.UpsertDevice(&db.Device{MAC: m, IP: target})
		return m, target
	}
	m := strings.ToUpper(target)
	ip = resolveIPByMAC(m)
	if ip == "" {
		// DB IP is for display only; the daemon never enforces a MAC target
		// unless that MAC is currently visible in ARP.
		if dev := findDevice(m, database); dev != nil {
			ip = dev.IP
		}
	}
	return m, ip
}

// --- remove ---

func schedRemove() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: njanet sched remove <id|ip|mac>")
		return
	}
	arg := os.Args[3]

	database := initDB()
	defer database.Close()

	if id, err := strconv.ParseInt(arg, 10, 64); err == nil {
		if ok, err := database.RemoveScheduleByID(id); err != nil {
			fmt.Fprintf(os.Stderr, "Gagal hapus jadwal: %v\n", err)
			os.Exit(1)
		} else if ok {
			fmt.Printf("✅ Jadwal #%d dihapus\n", id)
		} else {
			fmt.Printf("Jadwal #%d tidak ketemu.\n", id)
		}
		return
	}

	mac := ""
	if isValidMAC(arg) {
		mac = strings.ToUpper(arg)
	} else if isValidIP(arg) {
		// Prefer the live ARP entry; the DB may still map the IP to an old MAC.
		mac = resolveMAC(arg)
		if mac == "" {
			if m, err := database.FindMACByIP(arg); err == nil {
				mac = m
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Argumen tidak valid: %s (pakai id, IP, atau MAC)\n", arg)
		os.Exit(1)
	}
	if mac == "" {
		fmt.Printf("Tidak ada jadwal untuk %s.\n", arg)
		return
	}
	if ok, err := database.RemoveScheduleByMAC(mac); err != nil {
		fmt.Fprintf(os.Stderr, "Gagal hapus jadwal: %v\n", err)
		os.Exit(1)
	} else if ok {
		fmt.Printf("✅ Jadwal untuk %s dihapus\n", mac)
	} else {
		fmt.Printf("Tidak ada jadwal untuk %s.\n", mac)
	}
}

// --- list ---

func schedList() {
	database := initDB()
	defer database.Close()

	schedules, err := database.GetSchedules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if len(schedules) == 0 {
		fmt.Println("Belum ada jadwal. Contoh:")
		fmt.Println("  njanet sched add 192.168.1.8 block 00:00-06:00")
		return
	}

	devices, _ := database.GetAllDevices()
	byMAC := make(map[string]*db.Device, len(devices))
	for _, d := range devices {
		byMAC[d.MAC] = d
	}

	now := time.Now()
	nowMin := now.Hour()*60 + now.Minute()
	fmt.Printf("%-4s %-16s %-18s %-14s %-13s %-10s %s\n",
		"ID", "IP", "MAC", "Aksi", "Window", "Hari", "Status")
	fmt.Println(strings.Repeat("-", 95))
	for _, s := range schedules {
		action := "block"
		if s.Action == "throttle" {
			action = fmt.Sprintf("%dKbps", s.SpeedKbps)
		}
		ip := s.IP
		if d, ok := byMAC[s.MAC]; ok {
			if d.IP != "" {
				ip = d.IP
			}
			name := d.Nickname
			if name == "" {
				name = d.Hostname
			}
			if name != "" {
				ip = fmt.Sprintf("%s (%s)", ip, name)
			}
		}
		status := "off"
		if dayMatches(s.Days, now) && inWindow(s.StartMin, s.EndMin, nowMin) {
			status = "🟢 ON"
		}
		fmt.Printf("%-4d %-16s %-18s %-14s %-13s %-10s %s\n",
			s.ID, truncate(ipOrDash(ip), 16), s.MAC, action,
			fmtWindow(s.StartMin, s.EndMin), truncate(fmtDays(s.Days), 10), status)
	}
	fmt.Printf("\n%d jadwal. Daemon: sudo njanet sched run\n", len(schedules))
}

// --- daemon ---

type appliedSched struct {
	action string
	speed  int
	ip     string
	mac    string
}

func cmdSchedRun(ifaceName string) {
	every := 30 * time.Second
	for i, a := range os.Args {
		if (a == "--every" || a == "-e") && i+1 < len(os.Args) {
			d, err := time.ParseDuration(os.Args[i+1])
			if err != nil || d < 10*time.Second {
				fmt.Fprintln(os.Stderr, "Interval tidak valid (min 10s), mis. --every 30s")
				os.Exit(1)
			}
			every = d
		}
	}

	database := initDB()
	defer database.Close()

	unlock, err := acquireControllerLock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	defer unlock()

	ctrl := initController(ifaceName)
	if !ctrl.IsReady() {
		fmt.Fprintln(os.Stderr, "❌ Root required: jalankan dengan sudo (butuh tc + iptables)")
		os.Exit(1)
	}

	schedules, err := database.GetSchedules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gagal baca jadwal: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("⏰ Scheduler jalan (%d jadwal, cek tiap %s, Ctrl+C = stop + pulihkan)\n", len(schedules), every)
	fmt.Println("   Jadwal baru/revisi otomatis kepakai tanpa restart daemon.")
	fmt.Println()

	applied := make(map[int64]appliedSched)
	unknown := make(map[string]bool)
	selfWarned := make(map[string]bool)

	tick := func() {
		now := time.Now()
		nowMin := now.Hour()*60 + now.Minute()
		myIP, gwIP := getMyIP(ifaceName), getGatewayIP()
		schedules, err := database.GetSchedules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] db error: %v\n", ts(), err)
			return
		}
		present := make(map[int64]bool, len(schedules))
		for _, sc := range schedules {
			present[sc.ID] = true
			want := dayMatches(sc.Days, now) && inWindow(sc.StartMin, sc.EndMin, nowMin)

			resolved := resolveIPByMAC(sc.MAC)
			ip := resolved
			if resolved != "" && resolved != sc.IP {
				if err := database.UpdateScheduleIP(sc.MAC, resolved); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] db error update IP #%d: %v\n", ts(), sc.ID, err)
				}
			}

			cur, ok := applied[sc.ID]

			// Target ternyata IP sendiri/gateway (mis. ganti jaringan):
			// jangan pernah terapkan, bersihkan bila sempat teraplikasi.
			if ip != "" && (ip == myIP || ip == gwIP) {
				if ok {
					if err := revertSched(ctrl, database, cur); err != nil {
						fmt.Fprintf(os.Stderr, "[%s] gagal mencabut jadwal #%d: %v\n", ts(), sc.ID, err)
						continue
					}
					delete(applied, sc.ID)
				}
				if !selfWarned[sc.MAC] {
					fmt.Printf("[%s] ⏭️  Jadwal #%d menunjuk %s (perangkat sendiri/gateway) — dilewati\n",
						ts(), sc.ID, ip)
					selfWarned[sc.MAC] = true
				}
				continue
			}
			delete(selfWarned, sc.MAC)

			if want && ip == "" {
				// Perangkat hilang dari jaringan — bersihkan aturan basi.
				// Jangan pernah memakai sc.IP: IP itu bisa sudah dipakai
				// perangkat lain setelah DHCP lease berakhir.
				if ok {
					if err := revertSched(ctrl, database, cur); err != nil {
						fmt.Fprintf(os.Stderr, "[%s] gagal mencabut aturan basi #%d: %v\n", ts(), sc.ID, err)
						continue
					}
					delete(applied, sc.ID)
				}
				if !unknown[sc.MAC] {
					fmt.Printf("[%s] ⏳ %s belum terlihat di jaringan — menunggu...\n", ts(), sc.MAC)
					unknown[sc.MAC] = true
				}
				continue
			}
			delete(unknown, sc.MAC)

			if want {
				if !ok || cur.action != sc.Action || cur.speed != sc.SpeedKbps || cur.ip != ip {
					if ok {
						if err := revertSched(ctrl, database, cur); err != nil {
							fmt.Fprintf(os.Stderr, "[%s] gagal mencabut aturan lama #%d: %v\n", ts(), sc.ID, err)
							continue
						}
						delete(applied, sc.ID)
					}
					if err := applySched(ctrl, database, sc, ip); err != nil {
						fmt.Fprintf(os.Stderr, "[%s] ⚠️  Gagal terapkan jadwal #%d ke %s: %v (coba lagi tick berikut)\n",
							ts(), sc.ID, ip, err)
						continue
					}
					applied[sc.ID] = appliedSched{action: sc.Action, speed: sc.SpeedKbps, ip: ip, mac: sc.MAC}
					fmt.Printf("[%s] #%d %s → %s (%s)\n", ts(), sc.ID, describeSched(sc), ip, sc.MAC)
				}
				continue
			}

			if ok {
				if err := revertSched(ctrl, database, cur); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] gagal memulihkan jadwal #%d: %v\n", ts(), sc.ID, err)
					continue
				}
				delete(applied, sc.ID)
				fmt.Printf("[%s] #%d window selesai — %s (%s) dipulihkan\n", ts(), sc.ID, cur.ip, cur.mac)
			}
		}

		// Jadwal yang dihapus saat daemon berjalan tidak akan dikunjungi lagi
		// oleh loop di atas; cabut aturannya di sini.
		for id, cur := range applied {
			if present[id] {
				continue
			}
			if err := revertSched(ctrl, database, cur); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] gagal mencabut jadwal #%d yang dihapus: %v\n", ts(), id, err)
				continue
			}
			delete(applied, id)
			fmt.Printf("[%s] Jadwal #%d dihapus — %s (%s) dipulihkan\n", ts(), id, cur.ip, cur.mac)
		}
	}

	tick()

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-ticker.C:
			tick()
		case <-sig:
			fmt.Println("\n🔄 Memulihkan semua perangkat terjadwal...")
			for id, cur := range applied {
				if err := revertSched(ctrl, database, cur); err != nil {
					fmt.Fprintf(os.Stderr, "Gagal memulihkan jadwal #%d (%s): %v\n", id, cur.ip, err)
				}
			}
			fmt.Println("✅ Scheduler berhenti")
			return
		}
	}
}

func applySched(ctrl *controller.Controller, database *db.Database, sc *db.Schedule, ip string) error {
	dev := &db.Device{MAC: sc.MAC, IP: ip}
	if sc.Action == "block" {
		if err := ctrl.BlockDevice(dev); err != nil {
			return err
		}
		return database.UpdateDeviceBlock(sc.MAC, true)
	}
	if err := ctrl.ThrottleDevice(dev, sc.SpeedKbps); err != nil {
		return err
	}
	return database.UpdateDeviceSpeed(sc.MAC, sc.SpeedKbps)
}

func revertSched(ctrl *controller.Controller, database *db.Database, cur appliedSched) error {
	dev := &db.Device{MAC: cur.mac, IP: cur.ip}
	if cur.action == "block" {
		if err := ctrl.UnblockDevice(dev); err != nil {
			return err
		}
		return database.UpdateDeviceBlock(cur.mac, false)
	}
	if err := ctrl.ThrottleDevice(dev, 0); err != nil {
		return err
	}
	return database.UpdateDeviceSpeed(cur.mac, 0)
}

func describeSched(sc *db.Schedule) string {
	if sc.Action == "block" {
		return "BLOCK"
	}
	return fmt.Sprintf("throttle %d Kbps", sc.SpeedKbps)
}

// --- parsing & time helpers (pure, unit-tested) ---

// parseWindow parses "HH:MM-HH:MM" into minutes since midnight.
// Overnight windows like "22:00-06:00" are allowed.
func parseWindow(s string) (startMin, endMin int, err error) {
	invalid := func() (int, int, error) {
		return 0, 0, fmt.Errorf("format harus HH:MM-HH:MM, contoh 22:00-06:00")
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return invalid()
	}
	parse := func(t string) (int, error) {
		hm := strings.Split(strings.TrimSpace(t), ":")
		if len(hm) != 2 {
			return 0, fmt.Errorf("jam %q tidak valid", t)
		}
		h, err1 := strconv.Atoi(strings.TrimSpace(hm[0]))
		m, err2 := strconv.Atoi(strings.TrimSpace(hm[1]))
		if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, fmt.Errorf("jam %q tidak valid (00:00-23:59)", t)
		}
		return h*60 + m, nil
	}
	startMin, err = parse(parts[0])
	if err != nil {
		return 0, 0, err
	}
	endMin, err = parse(parts[1])
	if err != nil {
		return 0, 0, err
	}
	if startMin == endMin {
		return 0, 0, fmt.Errorf("awal dan akhir sama — window kosong")
	}
	return startMin, endMin, nil
}

var schedDayNames = map[string]string{
	"mon": "mon", "monday": "mon",
	"tue": "tue", "tues": "tue", "tuesday": "tue",
	"wed": "wed", "wednesday": "wed",
	"thu": "thu", "thur": "thu", "thurs": "thu", "thursday": "thu",
	"fri": "fri", "friday": "fri",
	"sat": "sat", "saturday": "sat",
	"sun": "sun", "sunday": "sun",
}

// parseDays normalizes day specs to "*" or a comma list like "mon,tue".
func parseDays(s string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "", "*", "daily", "everyday", "all":
		return "*", nil
	case "weekdays":
		return "mon,tue,wed,thu,fri", nil
	case "weekend":
		return "sat,sun", nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, d := range strings.Split(t, ",") {
		d = strings.TrimSpace(d)
		n, ok := schedDayNames[d]
		if !ok {
			return "", fmt.Errorf("hari %q tidak valid (mon,tue,wed,thu,fri,sat,sun)", d)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("daftar hari kosong")
	}
	return strings.Join(out, ","), nil
}

func dayMatches(days string, now time.Time) bool {
	if days == "" || days == "*" {
		return true
	}
	wd := strings.ToLower(now.Weekday().String())
	if len(wd) > 3 {
		wd = wd[:3]
	}
	for _, d := range strings.Split(days, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if n, ok := schedDayNames[d]; ok {
			d = n
		}
		if d == wd {
			return true
		}
	}
	return false
}

// inWindow reports whether nowMin (minutes since midnight) falls in
// [startMin, endMin), correctly handling overnight windows.
func inWindow(startMin, endMin, nowMin int) bool {
	if startMin <= endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	return nowMin >= startMin || nowMin < endMin
}

// windowsOverlap reports whether two (possibly overnight) windows share any minute.
func windowsOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return inWindow(aStart, aEnd, bStart) || inWindow(bStart, bEnd, aStart)
}

func daysIntersect(a, b string) bool {
	if a == "*" || a == "" || b == "*" || b == "" {
		return true
	}
	set := make(map[string]bool)
	for _, d := range strings.Split(a, ",") {
		set[strings.TrimSpace(d)] = true
	}
	for _, d := range strings.Split(b, ",") {
		if set[strings.TrimSpace(d)] {
			return true
		}
	}
	return false
}

func fmtWindow(startMin, endMin int) string {
	return fmt.Sprintf("%s-%s", fmtMins(startMin), fmtMins(endMin))
}

func fmtMins(m int) string {
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

func fmtDays(days string) string {
	if days == "" || days == "*" {
		return "daily"
	}
	return days
}

func ipOrDash(ip string) string {
	if ip == "" {
		return "-"
	}
	return ip
}

func ts() string {
	return time.Now().Format("15:04:05")
}

// resolveIPByMAC finds the current IP for a MAC from the kernel ARP table.
func resolveIPByMAC(mac string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	mac = strings.ToUpper(mac)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.ToUpper(f[3]) == mac {
			return f[0]
		}
	}
	return ""
}
