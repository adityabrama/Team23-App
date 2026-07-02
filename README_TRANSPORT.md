# Transport TCP Team23 — Pengiriman Paket Terenkripsi

Pengembangan dari aplikasi enkripsi/dekripsi hybrid: sekarang paket dikirim
lewat **jaringan (TCP)** menggunakan transport buatan sendiri, lalu didekripsi
di sisi penerima. Tujuannya membuktikan 2 hal:

1. **Integritas terjamin** — kalau paket diubah di tengah jalan, penerima
   langsung mendeteksi dan menolaknya.
2. **Aman saat di-intercept** — kalau lalu lintas disadap, isi rahasia tetap
   tidak terbaca (hanya ciphertext acak).

## File

| File | Peran |
|---|---|
| `Team23App.py` | Aplikasi GUI enkripsi/dekripsi hybrid (inti kripto dipakai ulang di sini) |
| `transport_umum.py` | Fungsi bersama: framing pesan TCP, setup kunci, hexdump |
| `server_penerima.py` | **Server/penerima**: menerima, dekripsi, verifikasi 4 prinsip |
| `client_pengirim.py` | **Client/pengirim**: enkripsi file lalu kirim lewat TCP |
| `penyadap.py` | **Penyadap (man-in-the-middle)**: mengintip / mengubah data untuk demo |

Kunci demo (`Pengirim`, `Penerima`) dibuat otomatis di folder `kunci/`
dengan password `team23demo`.

## Kenapa TCP + framing?

TCP adalah aliran byte (stream) yang **reliable** — dijamin sampai, urut, dan
tidak korup di level transport (itulah kenapa TCP "tidak perlu memusingkan
integritas" seperti UDP). Tapi TCP tidak tahu batas antar-pesan, jadi kita
tambahkan **framing**: kirim 4 byte panjang dulu, baru isinya. Integritas
**terhadap serangan/modifikasi jahat** tetap dijamin oleh kripto (HMAC Fernet +
hash SHA-256 + tanda tangan RSA), bukan oleh TCP.

## Cara demo (3 terminal)

Buka 3 terminal di folder ini.

**Skenario 1 — Kirim langsung (semua LULUS):**
```
Terminal 1:  python server_penerima.py
Terminal 2:  python client_pengirim.py
```

**Skenario 2 — Disadap tapi tetap aman (isi tak terbaca):**
```
Terminal 1:  python server_penerima.py
Terminal 2:  python penyadap.py
Terminal 3:  python client_pengirim.py pesan_rahasia.txt 5024
```
Angka `5024` = kirim lewat penyadap. Lihat di Terminal 2: yang tertangkap
hanya byte acak, dan kata rahasia TIDAK ditemukan. Server tetap LULUS.

**Skenario 3 — Disadap DAN diubah (integritas mendeteksi serangan):**
```
Terminal 1:  python server_penerima.py
Terminal 2:  python penyadap.py --tamper
Terminal 3:  python client_pengirim.py pesan_rahasia.txt 5024
```
Penyadap mengubah 1 byte. Server LANGSUNG MENOLAK ("integritas gagal").

## Jalan di 2 device dalam 1 WiFi

1. Di komputer **penerima**, cari IP LAN-nya:
   - Windows: `ipconfig` → lihat "IPv4 Address" (mis. `192.168.1.10`)
2. Edit `transport_umum.py` baris `HOST_DEFAULT = "127.0.0.1"` menjadi IP itu,
   di **kedua** komputer. Pastikan firewall mengizinkan port 5023.
3. Jalankan `server_penerima.py` di penerima, `client_pengirim.py` di pengirim.
4. Salin folder `kunci/` (public key lawan) agar pasangan kunci cocok.

> Catatan: `127.0.0.1` = localhost (satu komputer), cocok untuk latihan &
> presentasi. IP `192.168.x.x` untuk antar-device dalam WiFi yang sama.
