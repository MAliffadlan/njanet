<div align="center">
  <img src="Pictures/njanet.png" alt="NjaNet logo" />

  **NjaNet Mectov for Network Control**

</div>

<br />

> [!NOTE]
> Alat ini hanya untuk pembelajaran dan penggunaan pada jaringan milik sendiri. Penggunaan pada jaringan orang lain tanpa izin melanggar hukum.

## **1. Overview**

**NjaNet** adalah tool CLI berbasis Go untuk kontrol jaringan WiFi — scan perangkat, batasi kecepatan, blokir koneksi, dan lindungi jaringan dari ARP spoofing. Dikemas dalam satu binary Go siap pakai. ARP spoof memakai tool `dsniff` (`arpspoof`), dengan fallback Python bawaan otomatis jika `arpspoof` belum terpasang.

## **2. Persiapan**

Diperlukan:
- Sistem operasi **Linux**
- **Go 1.22+** (untuk build dari source)
- **iproute2** (`tc`) dan **iptables** — untuk throttle/block
- Tool **dsniff** (`sudo apt install dsniff`) — untuk ARP spoof
- **python3** (fallback ARP spoof jika `arpspoof` tidak ada)
- **net-tools** (`arp`) — untuk memulihkan cache ARP
- Hak akses **root** (sudo) — untuk throttle, block, hog

State runtime (lock, PID spoof, state scheduler) disimpan di `/run/njanet`; database perangkat disimpan di `~/.njanet`.

## **3. Fitur**

- Scan & deteksi perangkat (IP, MAC, vendor, hostname)
- Throttle — batasi kecepatan internet per perangkat
- Block — putuskan koneksi perangkat
- Hog — batasi semua perangkat kecuali laptop sendiri
- Protect — lindungi perangkat dari Hog (by MAC, cross-network)
- Watch — auto-track perangkat saat IP berubah (`--watch`)
- Schedule — blokir/batasi otomatis per jam & hari (`sched`)
- ARP Spoof Defense — deteksi & counter serangan ARP spoof
- Monitor — live scan otomatis tiap 5 detik
- Rename — beri nama sendiri pada perangkat
- Auto-detect interface (WiFi / LAN)
- Vendor lookup online (macvendors.com)

## **4. Instalasi**

**Option A**: Build dari source (**Direkomendasikan**)

```bash
git clone https://github.com/MAliffadlan/njanet
cd njanet
go build -o njanet ./cmd/njanet
sudo cp njanet /usr/local/bin/
```

**Option B**: Install dependency ARP spoof

```bash
sudo apt install dsniff -y
```

## **5. Penggunaan**

NjaNet memiliki CLI sendiri. Ketik `njanet` atau `njanet help` untuk bantuan.

```bash
njanet help
```

```
NjaNet v0.1 — kontrol jaringan WiFi via terminal

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
  t, throttle IP|MAC KBPS [-w]  Batasi kecepatan (KBPS 0 = normal lagi)
  b, block IP|MAC               Putuskan koneksi perangkat
  ub, unblock IP|MAC            Pulihkan koneksi perangkat
  h, hog KBPS                   Batasi SEMUA perangkat kecuali laptop ini
  d, defend                     Jaga jaringan dari serangan ARP spoof
  rs, reset                     Hapus semua aturan NjaNet

JADWAL OTOMATIS
  sched add IP|MAC AKSI JAM [hari]  Tambah jadwal (block | KBPS, JAM 22:00-06:00)
  sched list                        Lihat semua jadwal
  sched remove ID|IP|MAC            Hapus jadwal
  sched run (*)                     Jalankan penjadwal (daemon, Ctrl+C = stop)

LAINNYA
  p, protect ...            Kecualikan perangkat dari hog (add|remove|list)
  rn, rename IP NAMA        Beri nama perangkat
  help [perintah]           Bantuan ini / detail satu perintah
```

**Contoh:**

```bash
# Bantuan lengkap / detail per perintah
njanet help
njanet help throttle

# Scan jaringan
sudo njanet s

# Batasi kecepatan (64 Kbps — WhatsApp saja cukup)
sudo njanet t 192.168.1.8 64

# Batasi + auto-track jika IP berubah
sudo njanet t 192.168.1.8 64 --watch

# Block/unblock memakai IP atau MAC; unblock MAC membersihkan semua IP
# yang pernah tercatat untuk perangkat itu
sudo njanet b AA:BB:CC:DD:EE:FF
sudo njanet ub AA:BB:CC:DD:EE:FF

# Kembalikan throttle tanpa harus menunggu Ctrl+C
sudo njanet t 192.168.1.8 0

# Hog semua perangkat kecuali Anda
sudo njanet h 64

# Lindungi server dari Hog
njanet p a 192.168.1.9 "Server"
njanet p l

# Aktifkan ARP defense
sudo njanet d

# Monitor live
njanet m

# Jadwal: blokir HP tiap jam 12 malam – 6 pagi
njanet sched add 192.168.1.8 block 00:00-06:00

# Jadwal: lemotkan tiap malam hari kerja, daemon yang menjalankan
njanet sched add 192.168.1.8 64 22:00-06:00 weekdays
sudo njanet sched run
```

<details>
<summary><strong>Klik untuk detail speed (Kbps)</strong></summary>
<br />

| Speed | Efek |
|-------|------|
| `16`  | Hampir tidak bisa apa-apa |
| `64`  | WhatsApp bisa, video tidak |
| `128` | WhatsApp + browsing teks |
| `256` | Browsing, streaming rendah |
| `512` | Hampir normal |
| `1024`| Tidak terasa bedanya |
| `0`   | Unlimited (kembali normal) |

</details>

## **6. Cara Kerja**

```
Normal:
  Perangkat → Router → Internet

Throttle / Block:
  Perangkat → Laptop Anda (ARP Spoof) → Router → Internet
                  ↓
          Traffic dibatasi (tc) atau diblokir (iptables)
```

1. **ARP Spoof** — Laptop berpura-pura menjadi gateway
2. **IP Forwarding** — Traffic diteruskan ke router asli
3. **tc / iptables** — Bandwidth dibatasi sesuai aturan
4. **Ctrl+C** — Semua kembali normal

### State dan ownership

- Rule **manual** (block/throttle dari terminal) dan rule **jadwal** memiliki owner terpisah. Mencabut jadwal tidak akan meng-unblock block manual, dan sebaliknya.
- Hanya ada satu proses pengubah aturan pada satu waktu. Saat `sched run` aktif, perintah `throttle`/`block`/`hog`/`reset` ditolak sampai daemon dihentikan.
- Database perangkat: `~/.njanet/njanet.db`. State runtime (lock, PID spoof, state scheduler): `/run/njanet` dengan permission root.
- `block`/`throttle` membutuhkan target yang terlihat di ARP saat perintah dijalankan. `unblock` dan `throttle ... 0` tetap bisa memakai IP tersimpan.
- `sched remove <IP>` mencocokkan IP yang tersimpan di jadwal. Kalau IP perangkat sudah berubah, gunakan ID atau MAC.
- Daemon menyimpan state jadwal sebelum menerapkan aturan. Setelah crash, jalankan ulang `sudo njanet sched run` agar state direkonsiliasi. Kalau daemon tidak akan dijalankan lagi, gunakan `sudo njanet reset`.
- `reset` menghapus rule NjaNet, state scheduler, dan mengembalikan perangkat. State lama dari versi sebelumnya di `~/.njanet` dimigrasikan otomatis saat perintah root pertama.

## **7. Keterbatasan**

| Situasi | Keterangan |
|---------|------------|
| HP Android, laptop Windows/Linux | Berfungsi |
| iPhone (beberapa versi iOS) | Tergantung proteksi ARP |
| VPN | Tidak berfungsi |
| Laptop mati / suspend | Throttle ikut mati |
| Perangkat restart | Tanpa `--watch`, aturan hilang |
| Target tidak terlihat di ARP | Block/throttle ditolak; scan dulu atau targetkan saat online |
| Daemon scheduler crash/mati | State ada di `/run/njanet`; jalankan ulang `sched run` untuk rekonsiliasi, atau `reset` |
| IP perangkat berubah saat offline | Hapus jadwal lewat ID/MAC; IP lama tidak dipakai untuk enforcement |
| Dua perintah pengubah aturan bersamaan | Ditolak; hentikan proses aktif dulu (Ctrl+C) |

## **8. Troubleshooting**

```bash
# ARP spoof tidak berjalan (arpspoof tidak ada)
sudo apt install dsniff -y
# Fallback membutuhkan python3 jika arpspoof tidak tersedia
python3 --version

# Error "root required"
Gunakan sudo: sudo njanet throttle ...

# Error tc / state nyangkut setelah crash
sudo njanet reset
sudo iptables -S NJANET_FWD
sudo tc qdisc show dev <interface>
pgrep -a arpspoof
pgrep -af NJANET_SPOOF

# ARP spoof nyangkut dari session lama yang tidak punya state
sudo pkill -9 arpspoof
sudo njanet reset

# sched remove <IP> tidak menemukan jadwal
# IP perangkat mungkin sudah berubah; gunakan ID atau MAC:
njanet sched list
njanet sched remove <ID>
```

## **9. Testing**

```bash
go build ./...
go vet ./...
go test -race ./...
```

Test berjalan tanpa root dan memakai fake `iptables`/ARP. Pengujian `tc`, `iptables`, dan ARP spoof nyata tetap memerlukan sudo dan interface jaringan sungguhan.

## **10. Struktur Project**

```
njanet/
├── cmd/njanet/                   # CLI (main, commands, schedule, lock, runtime, helpers, setup, help)
├── internal/
│   ├── scanner/                 # Scanner (ARP, nmap, ping, defense)
│   ├── controller/              # Block, throttle, ARP spoof, ownership state
│   └── db/                      # SQLite database + ownership/permissions
├── go.mod
└── README.md
```

State runtime: `/run/njanet`. Database: `~/.njanet/njanet.db`.

## **Disclaimer**

> [!IMPORTANT]
> Penggunaan alat ini pada jaringan orang lain tanpa izin adalah pelanggaran hukum.
> Penulis tidak bertanggung jawab atas penyalahgunaan.
> Gunakan hanya untuk pembelajaran dan jaringan milik sendiri.

## **License**

MIT — bebas digunakan, dimodifikasi, dan disebarluaskan.

---

*Dibuat karena males beli NetCut tapi butuh fiturnya.*
