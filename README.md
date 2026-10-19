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
- Tool **dsniff** (`sudo apt install dsniff`) — untuk ARP spoof
- Hak akses **root** (sudo) — untuk throttle, block, hog

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

## **7. Keterbatasan**

| Situasi | Keterangan |
|---------|------------|
| HP Android, laptop Windows/Linux | Berfungsi |
| iPhone (beberapa versi iOS) | Tergantung proteksi ARP |
| VPN | Tidak berfungsi |
| Laptop mati / suspend | Throttle ikut mati |
| Perangkat restart | Tanpa `--watch`, aturan hilang |
| Dua perintah pengubah aturan bersamaan | Ditolak; hentikan proses aktif dulu (Ctrl+C) |

## **8. Troubleshooting**

```bash
# ARP spoof tidak berjalan
sudo apt install dsniff -y

# Error "root required"
Gunakan sudo: sudo njanet throttle ...

# Error tc
sudo njanet reset

# ARP spoof nyangkut dari session sebelumnya
sudo pkill -9 arpspoof
sudo njanet reset
```

## **9. Struktur Project**

```
njanet/
├── cmd/njanet/                   # CLI (main, commands, schedule, helpers, setup)
├── internal/
│   ├── scanner/                 # Scanner (ARP, nmap, ping, defense)
│   ├── controller/              # Block, throttle, ARP spoof
│   └── db/                      # SQLite database
├── go.mod
└── README.md
```

## **Disclaimer**

> [!IMPORTANT]
> Penggunaan alat ini pada jaringan orang lain tanpa izin adalah pelanggaran hukum.
> Penulis tidak bertanggung jawab atas penyalahgunaan.
> Gunakan hanya untuk pembelajaran dan jaringan milik sendiri.

## **License**

MIT — bebas digunakan, dimodifikasi, dan disebarluaskan.

---

*Dibuat karena males beli NetCut tapi butuh fiturnya.*
