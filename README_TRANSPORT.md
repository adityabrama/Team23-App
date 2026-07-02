# Team23 App — Transport & Chat Terenkripsi (TCP)

Pengembangan dari aplikasi enkripsi/dekripsi hybrid (`Team23App.py`) menjadi
komunikasi lewat jaringan: **chat + kirim file terenkripsi** di atas TCP.

## Isi folder (file inti)

| File | Peran |
|---|---|
| `Team23App.py` | Aplikasi GUI enkripsi/dekripsi hybrid (mesin kripto dipakai ulang) |
| `transport_umum.py` | Fungsi bersama: framing TCP, kunci, enkripsi pesan/file |
| `chat_server.py` | **Server chat**: menunggu client, kirim/terima pesan & file |
| `chat_client.py` | **Client chat**: menghubungi server, kirim/terima pesan & file |
| `buat_kunci.py` | Generate kunci sendiri (`saya_private.pem` + `saya_public.pem`) |
| `tukar_kunci_server.py` / `tukar_kunci_client.py` | Tukar public key antar mesin |

Semua koneksi memakai **TCP** (`socket.SOCK_STREAM`). Tiap pesan/file
dienkripsi hybrid (Fernet + RSA-OAEP) dan ditandatangani (RSA-PSS).

## Alur demo (PKI — tiap mesin punya kunci sendiri)

Di TIAP mesin (Windows & Linux) jalankan sekali:
```
python buat_kunci.py          (Windows)   |   python3 buat_kunci.py   (Linux)
```

Tukar public key:
```
Server:  python  tukar_kunci_server.py
Client:  python3 tukar_kunci_client.py
```
Setelah ini tiap mesin punya `lawan_public.pem`.

## Chat + kirim file

```
Terminal 1 (server):  python  chat_server.py
Terminal 2 (client):  python3 chat_client.py
```

Perintah saat chat:
- ketik teks biasa  → kirim pesan
- `/kirim <namafile>` → kirim file (tersimpan di `diterima_chat/` sisi lawan)
- `/keluar` → berhenti

## Antar-mesin (WiFi / VM)

Di sisi **client**, ubah `HOST_DEFAULT` di `transport_umum.py`:
- VM VirtualBox (NAT) → server di Windows: `HOST_DEFAULT = "10.0.2.2"`
- 2 laptop WiFi → `HOST_DEFAULT = "192.168.1.90"` (IP server, lihat saat server start)

Server otomatis mendengar di semua jaringan (`0.0.0.0`) dan menampilkan IP-nya.
Kalau muncul popup Windows Firewall saat pertama kali, klik **Allow access**.

## Catatan

Kalau belum `buat_kunci.py` + tukar kunci, chat tetap jalan memakai kunci demo
bawaan (mode 1 laptop) — cocok untuk uji cepat di satu komputer.
