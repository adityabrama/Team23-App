"""
================================================================
 transport_umum.py — Fungsi bersama untuk TRANSPORT TCP Team23
================================================================
 Berisi:
  - Protokol pembingkaian pesan (message framing) di atas TCP
  - Helper generate kunci demo
  - Import fungsi kripto dari Team23App.py

 KENAPA PERLU FRAMING?
 TCP itu "stream" (aliran byte tanpa batas). Kalau kita kirim
 paket 1300 byte, penerima bisa menerimanya terpotong
 (mis. 500 + 800) atau tergabung dengan pesan berikutnya.
 Solusi standar: kirim dulu 4 byte panjang pesan, lalu isinya.
 Penerima baca 4 byte -> tahu harus baca berapa byte berikutnya.
 (Referensi: Python "Socket Programming HOWTO" — pola
  length-prefixed message.)
================================================================
"""

import socket, struct, importlib.util, json, base64, os
from pathlib import Path

# ---- import fungsi kripto dari Team23App.py (tanpa menjalankan GUI) ----
_DIR = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("Team23App", _DIR / "Team23App.py")
kripto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kripto)   # aman: GUI hanya jalan lewat jalankan_gui()

# ---- konfigurasi demo ----
HOST_DEFAULT = "127.0.0.1"   # DIPAKAI CLIENT sbg alamat tujuan server.
                             # 1 laptop: biarkan "127.0.0.1".
                             # Antar-laptop (WiFi): di laptop CLIENT ganti ke IP server,
                             # contoh HOST_DEFAULT = "192.168.1.90"
HOST_BIND    = "0.0.0.0"     # DIPAKAI SERVER: dengar di semua jaringan (localhost + WiFi).
                             # Tidak perlu diubah.
PORT_SERVER  = 5023          # port server penerima
PORT_PROXY   = 5024          # port penyadap (man-in-the-middle)
PWD_DEMO     = "team23demo"  # password private key untuk demo
FOLDER_KUNCI = Path(os.environ.get("TEAM23_KUNCI") or (_DIR / "kunci"))

# --- Nama file berbasis PERAN (sama di kedua mesin, isi beda) ---
F_PRIV_SAYA = "saya_private.pem"    # kunci privat milikku
F_PUB_SAYA  = "saya_public.pem"     # kunci publik milikku (dibagikan)
F_PUB_LAWAN = "lawan_public.pem"    # kunci publik milik lawan (hasil tukar)

def path_kunci(nama):
    return str(FOLDER_KUNCI / nama)

def punya_identitas_sendiri():
    return (FOLDER_KUNCI / F_PRIV_SAYA).exists() and (FOLDER_KUNCI / F_PUB_SAYA).exists()

def kunci_saya_lawan():
    """(private_saya, public_lawan) kalau sudah generate & tukar kunci sendiri;
    kalau belum, kembalikan None (skrip pakai kunci demo Pengirim/Penerima)."""
    p = FOLDER_KUNCI / F_PRIV_SAYA
    q = FOLDER_KUNCI / F_PUB_LAWAN
    if p.exists() and q.exists():
        return str(p), str(q)
    return None


# ================= FRAMING PESAN DI ATAS TCP =================

def kirim_pesan(sock, data):
    """Kirim: [4 byte panjang][isi]. Menjamin pesan diterima utuh."""
    sock.sendall(struct.pack(">I", len(data)) + data)

def _terima_pasti(sock, n):
    """Baca TEPAT n byte dari socket (loop sampai lengkap)."""
    buf = b""
    while len(buf) < n:
        potongan = sock.recv(n - len(buf))
        if not potongan:
            raise ConnectionError("Koneksi terputus sebelum data lengkap")
        buf += potongan
    return buf

def terima_pesan(sock):
    """Terima satu pesan utuh sesuai framing kirim_pesan()."""
    header = _terima_pasti(sock, 4)
    panjang = struct.unpack(">I", header)[0]
    return _terima_pasti(sock, panjang)


# ================= SETUP KUNCI DEMO =================

def pastikan_kunci_demo():
    """Buat pasangan kunci Pengirim & Penerima kalau belum ada,
    supaya demo langsung jalan tanpa setup manual."""
    FOLDER_KUNCI.mkdir(exist_ok=True)
    dibuat = []
    for nama in ["Pengirim", "Penerima"]:
        fp = FOLDER_KUNCI / (nama + "_private.pem")
        fq = FOLDER_KUNCI / (nama + "_public.pem")
        if not fp.exists() or not fq.exists():
            priv, pub = kripto.buat_kunci_rsa()
            kripto.simpan_kunci_privat(priv, str(fp), PWD_DEMO)
            kripto.simpan_kunci_publik(pub, str(fq))
            dibuat.append(nama)
    return dibuat, FOLDER_KUNCI


# ================= DEMO PENYADAPAN =================

def ambil_ciphertext_isi(paket_bytes):
    """Ambil BAGIAN ISI FILE yang terenkripsi dari paket, sebagai byte
    acak mentah. Dipakai demo penyadapan agar terlihat benar-benar acak
    (bukan sekadar nama field JSON yang memang tidak rahasia)."""
    try:
        p = json.loads(paket_bytes)
        token = base64.b64decode(p["data"])          # token Fernet
        return base64.urlsafe_b64decode(token)        # -> byte acak mentah
    except Exception:
        return paket_bytes


def hexdump(data, baris_maks=8):
    """Tampilkan sebagian data sebagai hex + ASCII (untuk membuktikan
    yang lewat kabel hanyalah ciphertext acak, bukan teks asli)."""
    keluaran = []
    for i in range(0, min(len(data), baris_maks * 16), 16):
        blok = data[i:i + 16]
        hexs = " ".join("{:02x}".format(b) for b in blok)
        teks = "".join(chr(b) if 32 <= b < 127 else "." for b in blok)
        keluaran.append("  {:04x}  {:<48}  {}".format(i, hexs, teks))
    if len(data) > baris_maks * 16:
        keluaran.append("  ... ({} byte total)".format(len(data)))
    return "\n".join(keluaran)


def lan_ip():
    """Deteksi IP LAN (WiFi) komputer ini, untuk ditampilkan ke presenter."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


# ================= ENKRIPSI PESAN & FILE CHAT (in-memory) =================

def _b64e(b): return base64.b64encode(b).decode()
def _b64d(s): return base64.b64decode(s)

def muat_pasangan_kunci(peran):
    """Kembalikan (priv_saya_obj, pub_lawan_obj, mode).
    peran = 'server' atau 'client' (menentukan kunci demo bila belum PKI)."""
    sl = kunci_saya_lawan()
    if sl:
        priv = kripto.muat_kunci_privat(sl[0], PWD_DEMO)
        pub  = kripto.muat_kunci_publik(sl[1])
        return priv, pub, "PKI (saya_private + lawan_public)"
    pastikan_kunci_demo()
    if peran == "server":
        priv = kripto.muat_kunci_privat(path_kunci("Penerima_private.pem"), PWD_DEMO)
        pub  = kripto.muat_kunci_publik(path_kunci("Pengirim_public.pem"))
    else:
        priv = kripto.muat_kunci_privat(path_kunci("Pengirim_private.pem"), PWD_DEMO)
        pub  = kripto.muat_kunci_publik(path_kunci("Penerima_public.pem"))
    return priv, pub, "DEMO (kunci bawaan)"

MAGIC_CHAT = b"T23\x01"   # penanda paket chat (biner)

def _enkripsi_paket(data_bytes, jenis, nama_file, priv_saya, pub_lawan, nama):
    """Bungkus data jadi paket BINER opaque (byte acak semua)."""
    h = kripto.sha256_hex(data_bytes)
    meta = {"jenis": jenis, "nama_file": nama_file, "pengirim": nama, "sha256": h}
    meta_json = json.dumps(meta).encode()
    inner = len(meta_json).to_bytes(4, "big") + meta_json + data_bytes
    fk = kripto.Fernet.generate_key()
    blob = base64.urlsafe_b64decode(kripto.Fernet(fk).encrypt(inner))   # byte mentah
    k = pub_lawan.encrypt(fk, kripto._oaep())
    sig = priv_saya.sign((h + nama).encode(), kripto._pss(), kripto.hashes.SHA256())
    return kripto._pack_biner(MAGIC_CHAT, [k, sig, blob])

def enkripsi_pesan(teks, priv_saya, pub_lawan, nama):
    """Enkripsi satu PESAN teks -> paket JSON (bytes)."""
    return _enkripsi_paket(teks.encode("utf-8"), "pesan", "", priv_saya, pub_lawan, nama)

def enkripsi_berkas(path_file, priv_saya, pub_lawan, nama):
    """Enkripsi satu FILE -> paket JSON (bytes)."""
    from pathlib import Path as _P
    data = _P(path_file).read_bytes()
    return _enkripsi_paket(data, "file", _P(path_file).name, priv_saya, pub_lawan, nama)

def dekripsi_pesan(paket_bytes, priv_saya, pub_lawan):
    """Buka paket BINER -> dict {jenis, nama_file, data, pengirim, valid}."""
    k, sig, blob = kripto._unpack_biner(paket_bytes, MAGIC_CHAT)
    fk = priv_saya.decrypt(k, kripto._oaep())
    inner = kripto.Fernet(fk).decrypt(base64.urlsafe_b64encode(blob))
    mlen = int.from_bytes(inner[:4], "big")
    meta = json.loads(inner[4:4 + mlen]); data = inner[4 + mlen:]
    ok = False
    try:
        pub_lawan.verify(sig, (meta["sha256"] + meta["pengirim"]).encode(),
                         kripto._pss(), kripto.hashes.SHA256())
        ok = True
    except Exception:
        pass
    return {"jenis": meta.get("jenis", "pesan"), "nama_file": meta.get("nama_file", ""),
            "data": data, "pengirim": meta["pengirim"], "valid": ok}

# ================= LAPISAN TLS / mTLS (transport terenkripsi) =================
# Membungkus socket TCP dengan TLS 1.3 supaya SELURUH data di kabel teracak
# (termasuk paket JSON kita). mTLS = server & client saling menunjukkan
# sertifikat yang ditandatangani CA; sertifikat asing (penjahat) ditolak.

import ssl as _ssl

FOLDER_SERT = _DIR / "sertifikat"

def sert_ada():
    """Cek apakah sertifikat mTLS sudah dibuat."""
    perlu = ["ca.crt", "server.crt", "server.key", "client.crt", "client.key"]
    return all((FOLDER_SERT / f).exists() for f in perlu)

def _p(nama):
    return str(FOLDER_SERT / nama)

def konteks_tls_server():
    """Konteks TLS untuk SERVER (mTLS): tunjukkan server.crt, WAJIBKAN &
    verifikasi sertifikat client terhadap CA."""
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=_p("server.crt"), keyfile=_p("server.key"))
    ctx.verify_mode = _ssl.CERT_REQUIRED          # client WAJIB bersertifikat
    ctx.load_verify_locations(cafile=_p("ca.crt"))# hanya percaya yg di-sign CA
    try:
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx

def konteks_tls_client(pakai_penjahat=False):
    """Konteks TLS untuk CLIENT (mTLS): verifikasi server terhadap CA, dan
    tunjukkan client.crt (atau penjahat.crt untuk demo penolakan).
    check_hostname dimatikan supaya bisa jalan lintas-IP (VM/LAN); keamanan
    tetap dijaga karena sertifikat wajib ditandatangani CA tepercaya."""
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=_p("ca.crt"))
    if pakai_penjahat:
        ctx.load_cert_chain(certfile=_p("penjahat.crt"), keyfile=_p("penjahat.key"))
    else:
        ctx.load_cert_chain(certfile=_p("client.crt"), keyfile=_p("client.key"))
    try:
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx



# ================= SESI CHAT AMAN (serialisasi baca/tulis TLS) =================
# SSL socket TIDAK aman dibaca & ditulis dua thread bersamaan. "Sesi"
# menserialisasi operasi dengan lock. Pembaca memakai select() untuk MENUNGGU
# data TANPA memegang lock dan TANPA timeout pada recv (timeout saat recv bisa
# merusak state TLS). Jadi thread pengirim tidak pernah terkunci lama, dan
# tidak ada korupsi TLS akibat timeout.
import threading as _threading
import select as _select

class Sesi:
    def __init__(self, sock):
        self.sock = sock
        self._lock = _threading.Lock()
        self._buf = b""
        try: sock.setblocking(True)     # blocking; kesiapan dicek pakai select
        except Exception: pass

    def kirim(self, data):
        pesan = struct.pack(">I", len(data)) + data
        with self._lock:
            self.sock.sendall(pesan)

    def terima(self):
        """Ambil satu pesan berbingkai utuh. Raise bila koneksi ditutup."""
        while True:
            if len(self._buf) >= 4:
                n = struct.unpack(">I", self._buf[:4])[0]
                if len(self._buf) >= 4 + n:
                    m = self._buf[4:4+n]; self._buf = self._buf[4+n:]; return m
            # tunggu data TANPA memegang lock (biar pengirim tak terkunci)
            try:
                pending = self.sock.pending() > 0
            except Exception:
                pending = False
            if not pending:
                r, _, _ = _select.select([self.sock], [], [], 0.3)
                if not r:
                    continue                # belum ada data, coba lagi
            with self._lock:
                try:
                    d = self.sock.recv(65536)
                except _ssl.SSLWantReadError:
                    continue
            if d == b"":
                raise ConnectionError("Koneksi ditutup")
            self._buf += d

    def tutup(self):
        try: self.sock.close()
        except Exception: pass
