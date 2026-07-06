# Team23 App — Kriptografi Hybrid + Transport mTLS + Chat Aman

Aplikasi enkripsi/dekripsi **hybrid** (simetris + asimetris) yang memenuhi 4 prinsip
keamanan, DITAMBAH **chat + kirim file** yang transportnya diamankan **TLS 1.3 (mTLS)**.
Chat kini menyatu di dalam aplikasi (menu Chat), bisa jadi Server atau Client.

## Lapisan Keamanan (2 lapis)

| Lapisan | Mekanisme | Menjamin |
|---|---|---|
| Transport (kabel) | **TLS 1.3 mutual TLS** — server & client saling verifikasi sertifikat yang ditandatangani CA | Seluruh data di kabel teracak; hanya pihak bersertifikat sah yang boleh terhubung |
| End-to-end (isi) | **Fernet (AES-128) + RSA-OAEP + tanda tangan RSA-PSS** | Kerahasiaan, Integritas, Otentikasi, Non-Repudiasi per pesan/file |

Jadi meski ada yang menyadap kabel, yang terlihat hanya **TLS record terenkripsi** —
nama file / isi JSON tidak lagi terbaca (berbeda dengan versi lama).

## Struktur File

| File | Peran |
|---|---|
| `Team23App.py` | Aplikasi GUI: tab Buat Kunci, Pengirim, Penerima, dan **Chat (mTLS)** |
| `transport_umum.py` | Fungsi bersama: framing TCP, kunci, enkripsi pesan/file, **konteks TLS/mTLS** |
| `buat_sertifikat.py` | Membuat CA + sertifikat server/client (di-sign CA) + penjahat (palsu) |
| `chat_server.py` / `chat_client.py` | Versi terminal dari chat mTLS (untuk demo 2 terminal / VM) |
| `buat_kunci.py`, `tukar_kunci_*.py` | Kunci tanda tangan sendiri (PKI) + tukar public key |
| `sertifikat/` | ca, server, client, penjahat (dibuat otomatis saat pertama chat) |

## Cara Pakai

### Aplikasi lengkap (GUI)
```
pip install cryptography
python Team23App.py
```
Linux butuh tkinter: `sudo dnf install -y python3-tkinter` (Rocky) / `sudo apt install -y python3-tk` (Ubuntu).

Di tab **Chat (mTLS)**: pilih peran (Server/Client), klik **Mulai / Sambungkan**.
Sertifikat mTLS dibuat otomatis kalau belum ada. Lalu ketik pesan, atau tombol **File**
untuk kirim file. File masuk ke folder `diterima_chat/`.

### Versi terminal (opsional, cocok untuk VM)
```
Terminal 1 (server):  python chat_server.py
Terminal 2 (client):  python chat_client.py
# Uji tolak sertifikat palsu:
                       python chat_client.py penjahat   -> DITOLAK server
```

### Antar-mesin (WiFi / VirtualBox)
Di sisi **client**, isi alamat server (di GUI) atau ubah `HOST_DEFAULT` di `transport_umum.py`:
- VM VirtualBox (NAT) ke server Windows: `10.0.2.2`
- 2 laptop 1 WiFi: IP server (mis. `192.168.1.90`, ditampilkan saat server start)

Sertifikat (`sertifikat/`) harus SAMA di kedua mesin (di-sign CA yang sama), jadi salin
folder `sertifikat/` ke mesin lain, atau clone repo yang sudah memuatnya.

## Demo Keamanan (untuk presentasi)
- **Transport terenkripsi**: penyadap kabel hanya melihat TLS record acak (bukan nama file).
- **mTLS**: server & client saling menunjukkan sertifikat CA. TLS 1.3.
- **Sertifikat penjahat ditolak**: centang "uji sertifikat PENJAHAT" (GUI) atau
  `python chat_client.py penjahat` -> koneksi ditolak ("certificate verify failed").

## Catatan Teknis
- **Paket OPAQUE**: seluruh metadata (pengirim, penerima, nama_file, waktu, hash) IKUT
  dienkripsi bersama isi. Paket `.team23` maupun paket chat hanya berisi field acak
  `v` (penanda format), `k`, `s`, `d` — tidak ada lagi metadata yang terbaca.
- Semua transport **TCP** + framing (4 byte panjang + isi), dibungkus **TLS 1.3**.
- Sertifikat & kunci PEM standar — bisa dibuka di XCA/OpenSSL.
- `check_hostname` dimatikan agar bisa lintas-IP (VM/LAN); keamanan tetap dijaga karena
  sertifikat wajib ditandatangani CA tepercaya.
- Untuk kelas ini CA bersifat throwaway; di dunia nyata private key CA tidak dibagikan.

> Team 23 — Kriptografi Dasar
