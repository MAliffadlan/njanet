package main

import (
	"fmt"
	"strings"
)

// Alias tiap perintah ke nama kanonis untuk help detail.
var helpAliases = map[string]string{
	"s": "scan", "sc": "scan", "scan": "scan",
	"l": "list", "ls": "list", "list": "list",
	"b": "block", "block": "block",
	"ub": "unblock", "unblock": "unblock",
	"t": "throttle", "throttle": "throttle",
	"h": "hog", "hog": "hog", "monopoly": "hog", "prioritize": "hog",
	"p": "protect", "protect": "protect",
	"d": "defend", "defend": "defend",
	"m": "monitor", "mon": "monitor", "monitor": "monitor",
	"rn": "rename", "name": "rename", "rename": "rename",
	"rt": "router", "router": "router",
	"st": "stats", "stats": "stats",
	"rs": "reset", "reset": "reset",
	"sched": "schedule", "schedule": "schedule",
}

var helpDetails = map[string]string{
	"scan": `NAMA
  njanet scan (alias: s) — pindai jaringan, deteksi perangkat. (*) 

PENGGUNAAN
  sudo njanet s

KETERANGAN
  Mendeteksi IP, MAC, vendor, dan hostname semua perangkat di subnet.
  Hasilnya disimpan ke database, dipakai oleh list/throttle/block.

CONTOH
  sudo njanet s`,
	"list": `NAMA
  njanet list (alias: l) — daftar perangkat yang tersimpan.

PENGGUNAAN
  njanet l

KETERANGAN
  Membaca database hasil scan. Kolom status: FULL, N Kbps, atau BLOCKED.
  Jalankan scan dulu kalau daftar kosong.`,
	"throttle": `NAMA
  njanet throttle (alias: t) — batasi kecepatan satu perangkat. (*)

PENGGUNAAN
  sudo njanet t IP KBPS [--watch | -w]

KETERANGAN
  KBPS 0 = kembali normal. Contoh KBPS: 16 (hampir mati), 64 (WA saja),
  256 (browsing), 1024 (hampir normal). --watch mengikuti perangkat
  kalau IP-nya berubah (DHCP). Tekan Ctrl+C untuk berhenti & memulihkan.
  IP laptop sendiri dan gateway otomatis ditolak.

CONTOH
  sudo njanet t 192.168.1.8 64
  sudo njanet t 192.168.1.8 64 --watch
  sudo njanet t 192.168.1.8 0`,
	"block": `NAMA
  njanet block (alias: b) — putuskan koneksi satu perangkat. (*)

PENGGUNAAN
  sudo njanet b IP

KETERANGAN
  Perangkat tidak bisa akses internet/router sampai di-unblock.
  Target bisa IP atau MAC. IP laptop sendiri dan gateway otomatis
  ditolak.

CONTOH
  sudo njanet b 192.168.1.8`,
	"unblock": `NAMA
  njanet unblock (alias: ub) — pulihkan koneksi perangkat. (*)

PENGGUNAAN
  sudo njanet ub IP

CONTOH
  sudo njanet ub 192.168.1.8`,
	"hog": `NAMA
  njanet hog (alias: h) — batasi SEMUA perangkat kecuali laptop ini. (*)

PENGGUNAAN
  sudo njanet h [KBPS]

KETERANGAN
  KBPS default 64 kalau tidak diisi. Perangkat di daftar protect
  dilewati. Tekan Ctrl+C untuk berhenti & memulihkan semua.

CONTOH
  sudo njanet h 64`,
	"protect": `NAMA
  njanet protect (alias: p) — kecualikan perangkat dari hog.

PENGGUNAAN
  njanet p add IP [label]     (alias: p a ...)
  njanet p list               (alias: p l)
  njanet p remove IP          (alias: p r ...)

KETERANGAN
  Disimpan by MAC, jadi tetap berlaku walau IP perangkat berubah.

CONTOH
  njanet p a 192.168.1.9 Server
  njanet p l`,
	"defend": `NAMA
  njanet defend (alias: d) — jaga jaringan dari serangan ARP spoof. (*)

PENGGUNAAN
  sudo njanet d

KETERANGAN
  Memantau tabel ARP tiap 2 detik. Kalau gateway dipalsukan, entri
  yang benar dipulihkan otomatis dan pelaku ditampilkan beserta
  saran perintah block/throttle. Ctrl+C untuk berhenti.`,
	"monitor": `NAMA
  njanet monitor (alias: m) — pantau jaringan live tiap 5 detik.

PENGGUNAAN
  njanet m            (sudo = hasil lebih akurat)

KETERANGAN
  Scan ringan berulang, tampilkan IP, hostname, vendor, status.
  Ctrl+C untuk berhenti.`,
	"rename": `NAMA
  njanet rename (alias: rn) — beri nama sendiri pada perangkat.

PENGGUNAAN
  njanet rn IP NAMA

CONTOH
  njanet rn 192.168.1.8 HP-Andi`,
	"router": `NAMA
  njanet router (alias: rt) — pindai web interface router.

PENGGUNAAN
  njanet rt

KETERANGAN
  Cek port web umum (80, 443, 8080, ...) di IP gateway dan
  tampilkan judul halamannya kalau ada.`,
	"stats": `NAMA
  njanet stats (alias: st) — statistik jaringan dari database.

PENGGUNAAN
  njanet st`,
	"reset": `NAMA
  njanet reset (alias: rs) — hapus semua aturan NjaNet. (*)

PENGGUNAAN
  sudo njanet rs

KETERANGAN
  Membersihkan aturan tc/iptables buatan NjaNet dan menghentikan
  ARP spoof. Aturan firewall lain (ufw/dll) tidak disentuh.`,
	"schedule": `NAMA
  njanet schedule (alias: sched) — blokir/batasi otomatis per jam & hari.

PENGGUNAAN
  njanet sched add IP {block|KBPS} HH:MM-HH:MM [hari]
  njanet sched list
  njanet sched remove ID|IP
  sudo njanet sched run [--every 30s]

KETERANGAN
  hari: daily (default), weekdays, weekend, atau mon,tue,wed,...
  Window boleh lewat tengah malam (22:00-06:00). Di luar window
  perangkat dipulihkan otomatis. Daemon wajib jalan agar aturan
  ditegakkan; jadwal baru otomatis kepakai tanpa restart.

CONTOH
  njanet sched add 192.168.1.8 block 00:00-06:00
  njanet sched add 192.168.1.8 64 22:00-06:00 weekdays
  sudo njanet sched run`,
}

// printHelpDetail menampilkan bantuan satu perintah (gaya man-page).
// Mengembalikan false kalau nama perintah tidak dikenal.
func printHelpDetail(name string) bool {
	canon, ok := helpAliases[strings.ToLower(name)]
	if !ok {
		return false
	}
	fmt.Println(helpDetails[canon])
	fmt.Println()
	fmt.Println("  (*) wajib sudo. Lihat semua: njanet help")
	return true
}
