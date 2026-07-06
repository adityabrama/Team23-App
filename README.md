# Team23 App — Kriptografi Hybrid + Transport mTLS + Chat Aman

Aplikasi enkripsi/dekripsi **hybrid** (simetris + asimetris) yang memenuhi 4 prinsip
keamanan, dilengkapi **chat + kirim file** yang transportnya diamankan **TLS 1.3 (mTLS)**.
Semuanya menyatu dalam satu aplikasi GUI (`Team23App.py`).

## 4 Prinsip Keamanan

| Prinsip | Mekanisme |
|---|---|
| Kerahasiaan | Isi + metadata dienkripsi **Fernet** (AES-128); kunci Fernet dibungkus **RSA-2048 OAEP** |
| Integritas | HMAC bawaan Fernet + pembanding hash **SHA-256** |
| Otentikasi | **Tanda tangan digital RSA-PSS** dengan private key pengirim |
| Non-Repudiasi | Tanda tangan hanya bisa dibuat pemilik private key |

## Dua Lapis Perlindungan

1. **Transport (kabel)** — **TLS 1.3 mutual TLS**: server & client saling verifikasi sertifikat
   yang ditandatangani CA. Penyadap kabel hanya melihat TLS record acak.
2. **End-to-end (isi)** — paket **BINER opaque**: seluruh isi + metadata (pengirim, nama file,
   hash) terenkripsi. Paket hanya berupa 4 byte magic (`T23`) lalu byte acak.

## Struktur File

| File / Folder | Peran |
|---|---|
| `Team23App.py` | Aplikasi GUI utama: tab Buat Kunci, Pengirim, Penerima, Chat (mTLS) |
| `transport_umum.py` | Fungsi bersama: framing TCP, konteks TLS/mTLS, enkripsi pesan/file, Sesi ber-lock |
| `buat_sertifikat.py` | Membuat CA + sertifikat server/client (di-sign CA) + penjahat (palsu) |
| `chat_server.py` / `chat_client.py` | Versi terminal dari chat mTLS (untuk VM/headless) |
| `buat_kunci.py` | Generate kunci tanda tangan sendiri (`saya_private/public.pem`) — mode PKI |
| `tukar_kunci_server.py` / `tukar_kunci_client.py` | Tukar public key antar mesin (PKI) |
| `kunci/` | Kunci tanda tangan demo (ikut di-commit agar clone langsung jalan) |
| `sertifikat/` | CA + sertifikat mTLS demo (ikut di-commit) |

## Cara Pakai

### 1. Install
```
pip install cryptography
```
Linux (untuk GUI): `sudo dnf install -y python3-tkinter` (Rocky) / `sudo apt install -y python3-tk` (Ubuntu).

### 2. Aplikasi GUI
```
python Team23App.py     (Windows)
python3 Team23App.py    (Linux)
```
- **Buat Kunci**: buat pasangan kunci RSA untuk fitur enkripsi file manual.
- **Pengirim**: pilih file + private key kamu + public key penerima → hasil paket `.team23` (biner acak).
- **Penerima**: buka `.team23` → verifikasi 4 prinsip → simpan file asli.
- **Chat (mTLS)**: pilih Server/Client → **Mulai / Sambungkan** → ketik pesan atau tombol **File**.
  File yang diterima masuk ke folder `diterima_chat/`. Ada tombol **Stop** untuk memutus.

### 3. Chat versi terminal (opsional, cocok untuk VM)
```
Server:  python chat_server.py
Client:  python chat_client.py
Uji tolak sertifikat palsu:  python chat_client.py penjahat   -> DITOLAK
```

### Antar-mesin (WiFi / VirtualBox)
Di sisi **client**, isi "Alamat server" (GUI) atau ubah `HOST_DEFAULT` di `transport_umum.py`:
- VM VirtualBox (NAT) → server Windows: `10.0.2.2`
- 2 laptop 1 WiFi: IP server (mis. `192.168.1.90`, ditampilkan saat server start)

Kedua mesin harus punya folder `sertifikat/` & `kunci/` yang SAMA — cukup `git clone` repo ini.

## Demo Keamanan (untuk presentasi)
- **Transport terenkripsi**: penyadap kabel hanya melihat TLS record acak.
- **File terenkripsi**: buka `.team23` di editor teks → byte acak semua (Notepad bahkan menolak, itu normal).
- **mTLS**: server & client saling verifikasi sertifikat CA (TLS 1.3).
- **Sertifikat penjahat ditolak**: centang "uji sertifikat PENJAHAT" (GUI) atau `python chat_client.py penjahat`.
- **Integritas**: ubah 1 byte paket → dekripsi menolak ("integritas gagal").

## Catatan Teknis
- Chat memakai kelas `Sesi` (lock + `select`) agar TLS aman dibaca+ditulis dua thread (chat dua arah lancar).
- Kunci & sertifikat format PEM standar — bisa dibuka di **XCA** / OpenSSL.
- CA di repo ini bersifat throwaway (khusus demo kelas); di dunia nyata private key CA tidak dibagikan.

> Team 23 — Kriptografi Dasar
