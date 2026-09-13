package main

import (
	"fmt"
	"os"
	"path/filepath"
)

var dbPath string

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	ifaceName := os.Getenv("NJANET_IFACE")
	if ifaceName == "" {
		ifaceName = autoDetectInterface()
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan", "s", "sc":
		cmdScan(ifaceName)
	case "list", "ls", "l":
		cmdList(ifaceName)
	case "protect", "p":
		cmdProtect(ifaceName)
	case "rename", "name", "rn":
		cmdRename(ifaceName)
	case "block", "b":
		cmdBlock(ifaceName)
	case "unblock", "ub":
		cmdUnblock(ifaceName)
	case "throttle", "t":
		cmdThrottle(ifaceName)
	case "hog", "monopoly", "prioritize", "h":
		cmdHog(ifaceName)
	case "reset", "rs":
		cmdReset(ifaceName)
	case "router", "rt":
		cmdRouter(ifaceName)
	case "stats", "st":
		cmdStats(ifaceName)
	case "defend", "d":
		cmdDefend(ifaceName)
	case "schedule", "sched":
		cmdSchedule(ifaceName)
	case "monitor", "m", "mon":
		cmdMonitor(ifaceName)
	case "help", "-h", "--help":
		if len(os.Args) >= 3 && !printHelpDetail(os.Args[2]) {
			fmt.Printf("Perintah tidak dikenal: %s\n\n", os.Args[2])
			printUsage()
		} else if len(os.Args) < 3 {
			printUsage()
		}
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`NjaNet v0.1 — kontrol jaringan WiFi via terminal
  Pindai perangkat, batasi kecepatan, blokir koneksi, jadwal otomatis.

PENGGUNAAN
  njanet <perintah> [argumen]
  Perintah bertanda (*) wajib sudo. Detail per perintah: njanet help <perintah>

PINDAI & PANTAU
  s, scan                   Pindai jaringan, deteksi perangkat (*)
  l, list                   Daftar perangkat yang tersimpan
  m, monitor                Pantau live tiap 5 detik (lebih akurat sudo)
  st, stats                 Statistik jaringan
  rt, router                Pindai web interface router

BATASI & BLOKIR (*)
  t, throttle IP KBPS [-w]  Batasi kecepatan (KBPS 0 = normal lagi)
  b, block IP               Putuskan koneksi perangkat
  ub, unblock IP            Pulihkan koneksi perangkat
  h, hog KBPS               Batasi SEMUA perangkat kecuali laptop ini
  d, defend                 Jaga jaringan dari serangan ARP spoof
  rs, reset                 Hapus semua aturan NjaNet

JADWAL OTOMATIS
  sched add IP AKSI JAM [hari]  Tambah jadwal (block | KBPS, JAM 22:00-06:00)
  sched list                    Lihat semua jadwal
  sched remove ID|IP            Hapus jadwal
  sched run (*)                 Jalankan penjadwal (daemon, Ctrl+C = stop)

LAINNYA
  p, protect ...            Kecualikan perangkat dari hog (add|remove|list)
  rn, rename IP NAMA        Beri nama perangkat
  help [perintah]           Bantuan ini / detail satu perintah

CONTOH
  sudo njanet s
  sudo njanet t 192.168.1.8 64
  sudo njanet b 192.168.1.8
  njanet sched add 192.168.1.8 block 00:00-06:00
  sudo njanet sched run

  NJANET_IFACE=wlan0  ganti interface (otomatis jika dikosongkan)`)
}

func init() {
	home := os.Getenv("HOME")
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// When running with sudo, use the original user's home
		home = "/home/" + sudoUser
	}
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot get home dir: %v, using /tmp\n", err)
			home = "/tmp"
		}
	}
	dbPath = filepath.Join(home, ".njanet", "njanet.db")
}
