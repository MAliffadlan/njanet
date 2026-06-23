# NjaNet

Kontrol perangkat dalam jaringan WiFi dari terminal. Lihat siapa saja yang terhubung, batasi kecepatan, atau blokir koneksi mereka.

Mirip NetCut, gratis dan open source.

## Fitur

- Scan jaringan, deteksi perangkat (IP, MAC, vendor, hostname)
- Throttle - batasi kecepatan internet perangkat
- Block - putuskan koneksi perangkat
- Hog - batasi semua perangkat kecuali laptop sendiri
- Dashboard TUI interaktif (mirip htop)
- Rename - beri nama sendiri pada perangkat
- Auto-detect interface (WiFi / LAN)

## Cara Kerja

```
Normal:
  HP -> Router -> Internet

Throttle:
  HP -> Laptop (ARP spoof) -> Router -> Internet
                |
          Bandwidth dibatasi (tc)
```

NjaNet menggunakan ARP spoof untuk mengarahkan traffic perangkat target melewati laptop, kemudian membatasi bandwidth menggunakan tc (traffic control). Saat program dimatikan (Ctrl+C), jaringan kembali normal.

## Instalasi

```bash
# Clone repository
git clone https://github.com/mectov/njanet
cd njanet

# Build
go build -o njanet cmd/njanet/main.go

# Install ke sistem
sudo cp njanet /usr/local/bin/

# Install ARP spoof tool (wajib untuk throttle / block)
sudo apt install dsniff -y
```

## Penggunaan

### Scan

```bash
sudo njanet scan
```

Hasil:
```
IP               MAC                Vendor        Status
192.168.1.10     0C:9D:92:3F:07:D6  ASUS          Online
192.168.1.1      D0:04:92:18:9F:D8  Fiberhome     Online
192.168.1.8      72:86:B5:64:81:6F  -             Online
```

### Throttle

Batasi kecepatan perangkat tertentu.

```bash
sudo njanet throttle 192.168.1.8 64
```

Angka speed dalam Kbps:
- `64` - WA bisa, video tidak
- `128` - WA + browsing teks pelan
- `256` - browsing, streaming tidak HD
- `512` - hampir normal
- `1024` - nyaris tidak terasa

Program berjalan terus sampai di Ctrl+C. Saat dimatikan, kecepatan kembali normal.

### Block

Putuskan koneksi perangkat secara total.

```bash
sudo njanet block 192.168.1.8
sudo njanet unblock 192.168.1.8
```

### Hog

Batasi semua perangkat dalam jaringan, kecuali laptop sendiri.

```bash
sudo njanet hog 64
```

Cocok digunakan saat ingin memonopoli bandwidth, misalnya saat download file besar atau streaming.

### Dashboard

Tampilan interaktif di terminal (mirip htop).

```bash
# Mode lihat (tanpa sudo)
njanet dashboard

# Mode kontrol (dengan sudo)
sudo njanet dashboard
```

Navigasi:
| Tombol | Fungsi |
|--------|--------|
| Arrow Up/Down | Pilih perangkat |
| Enter | Detail perangkat |
| b | Block / unblock |
| 1-9 | Atur speed limit |
| r | Scan ulang |
| ESC / q | Keluar |

### Perintah Lain

```bash
njanet list               # Lihat daftar perangkat
njanet rename 192.168.1.8 "HP Budi"  # Beri nama
njanet stats              # Statistik jaringan
njanet reset              # Reset semua aturan
njanet help               # Bantuan
```

### Rename

Memberi nama pada perangkat agar mudah dikenali.

```bash
njanet rename 192.168.1.8 "HP Budi"
njanet rename 192.168.1.1 "Router"
njanet list
```

Nama hanya disimpan di database lokal dan tidak mempengaruhi perangkat asli.

## Keterbatasan

| Situasi | Keterangan |
|---------|------------|
| HP Android, laptop Windows/Linux | Berfungsi |
| iPhone (beberapa versi iOS) | Tergantung proteksi ARP |
| Perangkat menggunakan VPN | Tidak berfungsi |
| Laptop mati / suspend | Throttle ikut mati |
| Perangkat restart | Koneksi kembali normal |

## Troubleshooting

```bash
# ARP spoof tidak berjalan
sudo apt install dsniff -y

# Error "root required"
Gunakan sudo: sudo njanet throttle ...

# Error tc, reset aturan
sudo njanet reset
```

## Instalasi dari Source

```bash
git clone https://github.com/mectov/njanet
cd njanet
go build -o njanet cmd/njanet/main.go
sudo cp njanet /usr/local/bin/
```

## Struktur Project

```
njanet/
├── cmd/njanet/main.go         # Entry point CLI
├── internal/
│   ├── scanner/               # Scanner jaringan (ARP, nmap, ping)
│   ├── controller/            # Block, throttle, ARP spoof
│   ├── db/                    # SQLite database
│   ├── api/                   # REST API
│   └── ui/tui/                # Terminal UI
├── go.mod
└── README.md
```

## Lisensi

MIT
