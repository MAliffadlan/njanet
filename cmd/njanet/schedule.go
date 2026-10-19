package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	unlockSched, lockErr := acquireScheduleLock()
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "Gagal lock jadwal: %v\n", lockErr)
		os.Exit(1)
	}
	defer unlockSched()
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
	unlockSched, lockErr := acquireScheduleLock()
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "Gagal lock jadwal: %v\n", lockErr)
		os.Exit(1)
	}
	defer unlockSched()

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

	if isValidIP(arg) {
		// Match the stored schedule IP exactly. Resolving the IP to its
		// current owner would delete the wrong device's schedules after DHCP
		// reassignment.
		ok, err := database.RemoveSchedulesByIP(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Gagal hapus jadwal: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("✅ Jadwal dengan IP %s dihapus\n", arg)
		} else {
			fmt.Printf("Tidak ada jadwal dengan IP %s.\n", arg)
		}
		return
	}
	if !isValidMAC(arg) {
		fmt.Fprintf(os.Stderr, "Argumen tidak valid: %s (pakai id, IP, atau MAC)\n", arg)
		os.Exit(1)
	}
	mac := strings.ToUpper(arg)
	if ok, err := database.RemoveScheduleByMAC(mac); err != nil {
		fmt.Fprintf(os.Stderr, "Gagal hapus jadwal: %v\n", err)
		os.Exit(1)
	} else if ok {
		fmt.Printf("✅ Jadwal untuk %s dihapus\n", mac)
	} else {
		fmt.Printf("Tidak ada jadwal untuk %s.\n", arg)
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
	id     int64
}

type desiredSched struct {
	mac    string
	ip     string
	action string
	speed  int
	id     int64
}

type scheduleController interface {
	BlockDeviceScheduled(*db.Device) error
	ThrottleDevice(*db.Device, int) error
	UnblockScheduled(*db.Device) error
	ScheduledBlockActive(mac, ip string) bool
	ManualBlockRulesExist(ip string) bool
}

type storedApplied struct {
	Action     string `json:"action"`
	Speed      int    `json:"speed"`
	IP         string `json:"ip"`
	ScheduleID int64  `json:"schedule_id"`
}

func selectDesired(candidates []desiredSched) (map[string]desiredSched, map[string][]int64) {
	selected := make(map[string]desiredSched, len(candidates))
	ids := make(map[string][]int64)
	for _, d := range candidates {
		ids[d.mac] = append(ids[d.mac], d.id)
		if cur, ok := selected[d.mac]; !ok || d.id > cur.id {
			selected[d.mac] = d
		}
	}
	overlaps := make(map[string][]int64)
	for mac, list := range ids {
		if len(list) < 2 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		overlaps[mac] = list
	}
	return selected, overlaps
}

// planSchedule compares desired state per MAC with what this daemon owns.
// Reverts always run before applies, so removing and re-adding a schedule (or
// adjacent windows changing IDs) cannot undo the still-desired rule.
func planSchedule(applied map[string]appliedSched, desired map[string]desiredSched) (reverts []appliedSched, applies []desiredSched) {
	for mac, cur := range applied {
		d, want := desired[mac]
		if !want {
			reverts = append(reverts, cur)
			continue
		}
		if cur.action == d.action && cur.speed == d.speed && cur.ip == d.ip {
			continue
		}
		reverts = append(reverts, cur)
		applies = append(applies, d)
	}
	for mac, d := range desired {
		if _, ok := applied[mac]; !ok {
			applies = append(applies, d)
		}
	}
	sort.Slice(reverts, func(i, j int) bool { return reverts[i].mac < reverts[j].mac })
	sort.Slice(applies, func(i, j int) bool {
		if applies[i].mac != applies[j].mac {
			return applies[i].mac < applies[j].mac
		}
		return applies[i].id < applies[j].id
	})
	return reverts, applies
}

func reconcileScheduleState(ctrl scheduleController, database *db.Database, applied map[string]appliedSched, desired map[string]desiredSched, persist func() error) {
	for mac, cur := range applied {
		if cur.action == "block" && !ctrl.ScheduledBlockActive(mac, cur.ip) {
			if err := ctrl.UnblockScheduled(&db.Device{MAC: mac, IP: cur.ip}); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] block #%d tidak aktif dan gagal dibersihkan: %v\n", ts(), cur.id, err)
				if _, want := desired[mac]; want {
					// The device is still scheduled: let the idempotent apply
					// path repair the rules instead of keeping a broken entry.
					delete(applied, mac)
					if perr := persist(); perr != nil {
						fmt.Fprintf(os.Stderr, "[%s] state jadwal tidak bisa disimpan: %v\n", ts(), perr)
					}
				}
				continue
			}
			if !ctrl.ManualBlockRulesExist(cur.ip) {
				if err := database.UpdateDeviceBlock(mac, false); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] db error clear block %s: %v\n", ts(), mac, err)
				}
			}
			delete(applied, mac)
			if err := persist(); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] state jadwal tidak bisa disimpan: %v\n", ts(), err)
			}
			fmt.Printf("[%s] block #%d tidak aktif — menerapkan ulang\n", ts(), cur.id)
			continue
		}
		if d, ok := desired[mac]; ok &&
			cur.action == d.action && cur.speed == d.speed && cur.ip == d.ip && cur.id != d.id {
			cur.id = d.id
			applied[mac] = cur
		}
	}

	if err := persist(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] state jadwal tidak bisa disimpan; tick dilewati: %v\n", ts(), err)
		return
	}
	reverts, applies := planSchedule(applied, desired)
	for _, cur := range reverts {
		delete(applied, cur.mac)
		if err := revertSched(ctrl, database, cur); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] gagal mencabut aturan #%d (%s): %v\n", ts(), cur.id, cur.ip, err)
			applied[cur.mac] = cur
			continue
		}
		if err := persist(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] gagal simpan state setelah mencabut #%d: %v\n", ts(), cur.id, err)
			applied[cur.mac] = cur
			continue
		}
		fmt.Printf("[%s] #%d aturan dicabut — %s (%s)\n", ts(), cur.id, cur.ip, cur.mac)
	}
	for _, d := range applies {
		if _, ok := applied[d.mac]; ok {
			// A previous revert failed; don't stack a new rule on top.
			continue
		}
		// Write-ahead intent before touching the kernel: a crash from here on
		// leaves a record that startup reconciliation can verify or clean.
		applied[d.mac] = appliedSched{
			action: d.action, speed: d.speed, ip: d.ip, mac: d.mac, id: d.id,
		}
		if err := persist(); err != nil {
			delete(applied, d.mac)
			fmt.Fprintf(os.Stderr, "[%s] state jadwal tidak bisa disimpan; jadwal #%d tidak diterapkan: %v\n", ts(), d.id, err)
			continue
		}
		sc := &db.Schedule{ID: d.id, MAC: d.mac, IP: d.ip, Action: d.action, SpeedKbps: d.speed}
		if err := applySched(ctrl, database, sc, d.ip); err != nil {
			delete(applied, d.mac)
			_ = persist()
			fmt.Fprintf(os.Stderr, "[%s] ⚠️  Gagal terapkan jadwal #%d ke %s: %v (coba lagi tick berikut)\n",
				ts(), d.id, d.ip, err)
			continue
		}
		if err := persist(); err != nil {
			// Never leave a kernel rule this process cannot track.
			delete(applied, d.mac)
			rev := appliedSched{action: d.action, speed: d.speed, ip: d.ip, mac: d.mac, id: d.id}
			_ = revertSched(ctrl, database, rev)
			fmt.Fprintf(os.Stderr, "[%s] gagal simpan state setelah menerapkan #%d; aturan dikembalikan: %v\n", ts(), d.id, err)
			continue
		}
		fmt.Printf("[%s] #%d %s → %s (%s)\n", ts(), d.id, describeSched(sc), d.ip, d.mac)
	}
}

func saveAppliedState(path string, applied map[string]appliedSched) error {
	stored := make(map[string]storedApplied)
	for mac, cur := range applied {
		stored[mac] = storedApplied{
			Action:     cur.action,
			Speed:      cur.speed,
			IP:         cur.ip,
			ScheduleID: cur.id,
		}
	}
	if len(stored) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sched-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func schedStatePath() string {
	return filepath.Join(mustRuntimeStateDir(), "sched-state.json")
}

func loadAppliedState(path string) map[string]appliedSched {
	out := make(map[string]appliedSched)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[%s] gagal baca state jadwal: %v\n", ts(), err)
		}
		return out
	}
	var stored map[string]storedApplied
	if err := json.Unmarshal(data, &stored); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] state jadwal korup: %v\n", ts(), err)
		return out
	}
	for mac, cur := range stored {
		if cur.IP == "" || (cur.Action != "block" && cur.Action != "throttle") {
			continue
		}
		out[mac] = appliedSched{
			action: cur.Action,
			speed:  cur.Speed,
			ip:     cur.IP,
			mac:    mac,
			id:     cur.ScheduleID,
		}
	}
	return out
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

	statePath := schedStatePath()
	applied := loadAppliedState(statePath)
	ctrl := initSchedulerController(ifaceName, len(applied) > 0)
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

	staleThrottleMACs := make(map[string]bool)
	for mac, cur := range applied {
		if cur.action == "block" {
			if !ctrl.ScheduledBlockActive(mac, cur.ip) {
				// The scheduler-owned rule or spoof is gone (manual unblock,
				// crashed spoof, external cleanup); remove only scheduler
				// ownership and let the first tick reapply if still wanted.
				if err := ctrl.UnblockScheduled(&db.Device{MAC: mac, IP: cur.ip}); err != nil {
					fmt.Fprintf(os.Stderr, "Gagal membersihkan block lama %s: %v\n", cur.ip, err)
					continue
				}
				if !ctrl.ManualBlockRulesExist(cur.ip) {
					if err := database.UpdateDeviceBlock(mac, false); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: gagal update status DB: %v\n", err)
					}
				}
				delete(applied, mac)
			}
			continue
		}
		// Controller.New already removed stale throttle qdisc/spoof state, so
		// a persisted throttle must be reapplied from scratch.
		staleThrottleMACs[mac] = true
		delete(applied, mac)
	}
	if err := saveAppliedState(statePath, applied); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: gagal simpan state awal: %v\n", err)
	}
	persist := func() error {
		return saveAppliedState(statePath, applied)
	}
	unknown := make(map[string]bool)
	selfWarned := make(map[string]bool)
	overlapWarned := make(map[string]string)

	tick := func() {
		now := time.Now()
		nowMin := now.Hour()*60 + now.Minute()
		myIP, gwIP := getMyIP(ifaceName), getGatewayIP()
		schedules, err := database.GetSchedules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] db error: %v\n", ts(), err)
			return
		}

		candidates := make([]desiredSched, 0, len(schedules))
		for _, sc := range schedules {
			want := dayMatches(sc.Days, now) && inWindow(sc.StartMin, sc.EndMin, nowMin)

			resolved := resolveIPByMAC(sc.MAC)
			if resolved != "" && resolved != sc.IP {
				if err := database.UpdateScheduleIP(sc.MAC, resolved); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] db error update IP #%d: %v\n", ts(), sc.ID, err)
				}
			}
			if !want {
				continue
			}
			if resolved == "" {
				if !unknown[sc.MAC] {
					fmt.Printf("[%s] ⏳ %s belum terlihat di jaringan — menunggu...\n", ts(), sc.MAC)
					unknown[sc.MAC] = true
				}
				continue
			}
			delete(unknown, sc.MAC)
			if resolved == myIP || resolved == gwIP {
				if !selfWarned[sc.MAC] {
					fmt.Printf("[%s] ⏭️  Jadwal #%d menunjuk %s (perangkat sendiri/gateway) — dilewati\n",
						ts(), sc.ID, resolved)
					selfWarned[sc.MAC] = true
				}
				continue
			}
			delete(selfWarned, sc.MAC)
			candidates = append(candidates, desiredSched{
				mac: sc.MAC, ip: resolved, action: sc.Action, speed: sc.SpeedKbps, id: sc.ID,
			})
		}

		desired, overlaps := selectDesired(candidates)
		for mac, ids := range overlaps {
			key := fmt.Sprint(ids)
			if overlapWarned[mac] != key {
				fmt.Printf("[%s] ⚠️  Beberapa jadwal aktif untuk %s: %v — memakai #%d\n",
					ts(), mac, ids, desired[mac].id)
				overlapWarned[mac] = key
			}
		}
		for mac := range overlapWarned {
			if _, ok := overlaps[mac]; !ok {
				delete(overlapWarned, mac)
			}
		}

		reconcileScheduleState(ctrl, database, applied, desired, persist)

		for mac := range staleThrottleMACs {
			if _, want := desired[mac]; !want {
				if err := database.UpdateDeviceSpeed(mac, 0); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] db error clear speed %s: %v\n", ts(), mac, err)
				}
			}
			delete(staleThrottleMACs, mac)
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
			for mac, cur := range applied {
				if err := revertSched(ctrl, database, cur); err != nil {
					fmt.Fprintf(os.Stderr, "Gagal memulihkan jadwal #%d (%s): %v\n", cur.id, cur.ip, err)
					continue
				}
				delete(applied, mac)
			}
			if err := saveAppliedState(statePath, applied); err != nil {
				fmt.Fprintf(os.Stderr, "Gagal simpan state jadwal: %v\n", err)
			}
			fmt.Println("✅ Scheduler berhenti")
			return
		}
	}
}

func applySched(ctrl scheduleController, database *db.Database, sc *db.Schedule, ip string) error {
	dev := &db.Device{MAC: sc.MAC, IP: ip}
	if sc.Action == "block" {
		if err := ctrl.BlockDeviceScheduled(dev); err != nil {
			return err
		}
		if err := database.UpdateDeviceBlock(sc.MAC, true); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] db error update block #%d: %v\n", ts(), sc.ID, err)
		}
		return nil
	}
	if err := ctrl.ThrottleDevice(dev, sc.SpeedKbps); err != nil {
		return err
	}
	if err := database.UpdateDeviceSpeed(sc.MAC, sc.SpeedKbps); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] db error update speed #%d: %v\n", ts(), sc.ID, err)
	}
	return nil
}

func revertSched(ctrl scheduleController, database *db.Database, cur appliedSched) error {
	dev := &db.Device{MAC: cur.mac, IP: cur.ip}
	if cur.action == "block" {
		if err := ctrl.UnblockScheduled(dev); err != nil {
			return err
		}
		if ctrl.ManualBlockRulesExist(cur.ip) {
			return nil
		}
		if err := database.UpdateDeviceBlock(cur.mac, false); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] db error clear block %s: %v\n", ts(), cur.mac, err)
		}
		return nil
	}
	if err := ctrl.ThrottleDevice(dev, 0); err != nil {
		return err
	}
	if err := database.UpdateDeviceSpeed(cur.mac, 0); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] db error clear speed %s: %v\n", ts(), cur.mac, err)
	}
	return nil
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
	mac = strings.ToUpper(mac)
	for _, e := range readARPEntries() {
		if strings.EqualFold(e.MAC, mac) {
			return e.IP
		}
	}
	return ""
}
