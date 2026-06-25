<div align="center">
  <img src="Pictures/njanet.png" alt="NjaNet logo" />

  **NjaNet Mectov for Network Control**

</div>

<br />

> [!NOTE]
> Alat ini hanya untuk pembelajaran dan penggunaan pada jaringan milik sendiri. Penggunaan pada jaringan orang lain tanpa izin melanggar hukum.

## **1. Overview**

**NjaNet** adalah tool CLI berbasis Go untuk kontrol jaringan WiFi — scan perangkat, batasi kecepatan, blokir koneksi, dan lindungi jaringan dari ARP spoofing. Dibangun tanpa dependency Python, satu binary siap pakai.

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
go build -o njanet cmd/njanet/main.go
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
Usage:
  njanet scan              Scan jaringan, deteksi perangkat
  njanet list              Lihat daftar perangkat
  njanet throttle <ip> <kbps> [--watch]  Batasi kecepatan
  njanet block <ip>        Putuskan koneksi
  njanet unblock <ip>      Pulihkan koneksi
  njanet hog <kbps>        Batasi SEMUA perangkat kecuali Anda
  njanet protect add <ip> [label]  Lindungi dari Hog
  njanet protect list      Lihat daftar protected
  njanet protect remove <ip>  Hapus dari protected
  njanet defend            ARP spoof defense (deteksi + counter)
  njanet monitor           Live scan tiap 5 detik
  njanet rename <ip> <name>  Beri nama perangkat
  njanet stats             Statistik jaringan
  njanet reset             Reset semua aturan
```

**Contoh:**

```bash
# Scan jaringan
sudo njanet scan

# Batasi kecepatan (64 Kbps — WhatsApp saja cukup)
sudo njanet throttle 192.168.1.8 64

# Batasi + auto-track jika IP berubah
sudo njanet throttle 192.168.1.8 64 --watch

# Hog semua perangkat kecuali Anda
sudo njanet hog 64

# Lindungi server dari Hog
njanet protect add 192.168.1.9 "Server"
njanet protect list

# Aktifkan ARP defense
sudo njanet defend

# Monitor live
njanet monitor
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
sudo iptables -F FORWARD
```

## **9. Struktur Project**

```
njanet/
├── cmd/njanet/main.go           # Entry point CLI
├── internal/
│   ├── scanner/                 # Scanner (ARP, nmap, ping, defense)
│   ├── controller/              # Block, throttle, ARP spoof
│   ├── db/                      # SQLite database
│   └── api/                     # REST API
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
