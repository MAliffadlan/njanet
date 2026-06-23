# NjaNet — Network Controller

**Kontrol WiFi dari terminal — lihat device, blokir, atau lemotin koneksi mereka.**

Mirip kayak **NetCut**, tapi **gratis, open source, dan buat Linux**.

```
┌─────────────────────────────────────────────┐
│  🟢 192.168.1.10  Laptop lo         FULL   │
│  🔴 192.168.1.8   HP temen          BLOCK  │
│  🐢 192.168.1.5   HP adik           64Kbps │
│  🟢 192.168.1.1   Router            FULL   │
└─────────────────────────────────────────────┘
```

## 📦 Install

```bash
# 1. Download / clone
git clone https://github.com/mectov/netctl
cd netctl

# 2. Build
go build -o netctl cmd/netctl/main.go

# 3. Install ke PATH (biar tinggal ketik "netctl")
sudo cp netctl /usr/local/bin/

# 4. Install ARP spoof tool (WAJIB buat block/throttle)
sudo apt install dsniff -y
```

## 🚀 Cara Pake

### 1. Scan — Lihat siapa aja yang terhubung ke WiFi

```bash
sudo netctl scan
```

Contoh hasil:
```
🔍 Scanning network...

✅ Scan completed in 4.3s
   Devices found: 8 (8 online)

IP               MAC                Hostname       Vendor        Status
192.168.1.10     0C:9D:92:3F:07:D6  netctl-host    ASUS          🟢
192.168.1.1      D0:04:92:18:9F:D8  _gateway       Fiberhome     🟢
192.168.1.8      72:86:B5:64:81:6F  -              Unknown       🟢
192.168.1.200    64:1C:AE:FD:C1:B6  -              Samsung       🟢
...
```

> 💡 Catet IP device yang mau diatur (contoh: `192.168.1.8`)

### 2. Throttle — Bikin koneksi device lemot

```bash
# Lemotin HP 192.168.1.8 ke 64 Kbps (WA doang, YouTube gak jalan)
sudo netctl throttle 192.168.1.8 64

# Program bakal jalan terus. Test dari HP target — harusnya loading lama.
# Kalo mau balikin normal: Ctrl+C
```

**Angka speed (Kbps) biar kebayang:**
| Speed | Kira-kira bisa buat apa |
|-------|------------------------|
| `64` | WA doang, YouTube/TikTok gak muter |
| `128` | WA + browsing teks pelan |
| `256` | Browsing dikit, streaming gak HD |
| `512` | Lumayan normal |
| `1024` | Hampir gak kerasa bedanya |

### 3. Block — Putusin koneksi total

```bash
# Blokir total device 192.168.1.8
sudo netctl block 192.168.1.8

# Buka blokir
sudo netctl unblock 192.168.1.8
```

### 4. Dashboard — TUI interaktif kaya htop

```bash
# Mode liat-liat doang (gak perlu sudo)
netctl dashboard

# Mode kontrol (block/throttle pake sudo)
sudo netctl dashboard
```

Navigasi di dashboard:
| Tombol | Fungsi |
|--------|--------|
| `↑/↓` | Pilih device |
| `Enter` | Detail device |
| `b` | Block/unblock |
| `1-9` | Speed limit (1=1024Kbps, 9=9Mbps) |
| `r` | Scan ulang |
| `ESC/q` | Keluar |

### 5. Lain-lain

```bash
netctl list        # Lihat device yang pernah terdeteksi
netctl stats       # Statistik jaringan
netctl reset       # Reset semua aturan (block/throttle)
netctl help        # Bantuan
```

## 📋 Cara Kerja (simple version)

```
Normal:
  📱 HP → 🖥️ ROUTER → 🌐 Internet

Waktu di-throttle:
  📱 HP → 💻 LAPTOP (ARP spoof) → 🖥️ ROUTER → 🌐 Internet
               ↓
          Traffic dibatesin pake tc (traffic control)
```

1. **ARP Spoof** — Laptop lo "berpura-pura" jadi router. Device target kira laptop lo adalah gateway.
2. **IP Forwarding** — Traffic diterusin ke router beneran.
3. **tc (Traffic Control)** — Bandwidth dibatesin sesuai perintah.
4. **Kalo program dimatiin** (Ctrl+C) — Semua balik normal.

## ⚠️ Keterbatasan

| Situasi | Bisa? |
|---------|-------|
| HP Android, laptop Windows/Linux | ✅ Work |
| iPhone (beberapa versi iOS) | ⚠️ Tergantung proteksi ARP |
| Device pake VPN | ❌ Gak work |
| Laptop lo mati/suspend | ❌ Throttle ikut mati |
| Target restart | ⚠️ Koneksi balik bentar |

## 🔧 Troubleshooting

```
# ARP spoof gak jalan?
sudo apt install dsniff -y

# "root required"?
Jalanin pake sudo: sudo netctl throttle ...

# TC error?
sudo netctl reset  # Reset dulu
```

## 📁 Project Structure

```
netctl/
├── cmd/netctl/main.go         ← CLI entry point
├── internal/
│   ├── scanner/scanner.go     ← Network scanner (ARP, nmap, ping)
│   ├── controller/
│   │   ├── controller.go      ← Block, throttle, ARP spoof
│   ├── db/
│   │   ├── models.go          ← Data structures
│   │   └── database.go        ← SQLite storage
│   ├── api/handlers.go        ← REST API
│   └── ui/tui/dashboard.go    ← Terminal UI (htop-like)
├── go.mod
└── README.md
```

## 📜 License

MIT — bebas dipake, dimodifikasi, disebarluaskan.

---

*Dibuat karena males beli NetCut tapi butuh juga fiturnya.*
