"""
================================================================
 chat_server.py — CHAT mTLS (sisi SERVER) versi terminal
================================================================
 Sama seperti tab Chat di Team23App.py, tapi versi terminal.
 Transport dibungkus TLS 1.3 (mTLS) sehingga SELURUH data di kabel
 teracak. Server & client saling verifikasi sertifikat CA.

 Perintah: teks = pesan | /kirim <file> = kirim file | /keluar
 Jalankan buat_sertifikat.py dulu (otomatis dibuat kalau belum ada).
================================================================
"""
import socket, ssl, threading
from pathlib import Path
import transport_umum as T

NAMA = "SERVER"
FOLDER_MASUK = Path(__file__).parent / "diterima_chat"


def penerima(sesi, priv, pub):
    while True:
        try:
            paket = sesi.terima()
        except Exception:
            print("\n[i] Koneksi ditutup."); break
        try:
            info = T.dekripsi_pesan(paket, priv, pub)
            catatan = "" if info["valid"] else "  (tanda tangan TIDAK valid!)"
            if info["jenis"] == "file":
                FOLDER_MASUK.mkdir(exist_ok=True)
                (FOLDER_MASUK / info["nama_file"]).write_bytes(info["data"])
                print("\r{} > [FILE: {} ({} B)] -> diterima_chat/{}".format(
                    info["pengirim"], info["nama_file"], len(info["data"]), catatan))
            else:
                print("\r{} > {}{}".format(info["pengirim"], info["data"].decode("utf-8"), catatan))
            print("{} > ".format(NAMA), end="", flush=True)
        except Exception as e:
            print("\n[!] Gagal buka paket: {}".format(e))


def main():
    if not T.sert_ada():
        import buat_sertifikat; buat_sertifikat.main()
    priv, pub, mode = T.muat_pasangan_kunci("server")
    ctx = T.konteks_tls_server()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((T.HOST_BIND, T.PORT_SERVER)); s.listen(1)
    print("=== CHAT SERVER mTLS (kunci ttd: {}) ===".format(mode))
    print("Menunggu client di port {} ...  IP: {}".format(T.PORT_SERVER, T.lan_ip()))
    ss = ctx.wrap_socket(s, server_side=True)
    try:
        conn, addr = ss.accept()
    except ssl.SSLError as e:
        print("[!] Handshake DITOLAK (sertifikat tak tepercaya):", str(e).split('] ')[-1][:60]); return
    cn = dict(x[0] for x in conn.getpeercert()["subject"]).get("commonName", "?")
    print("[v] Client {} (CN={}) terhubung via {}. Mulai chat!".format(addr[0], cn, conn.version()))
    print("    (teks=pesan | /kirim <file> | /keluar)\n")
    with conn:
        sesi = T.Sesi(conn)
        threading.Thread(target=penerima, args=(sesi, priv, pub), daemon=True).start()
        while True:
            try:
                teks = input("{} > ".format(NAMA))
            except (EOFError, KeyboardInterrupt):
                break
            if teks.strip() == "/keluar": break
            if not teks: continue
            if teks.startswith("/kirim "):
                path = teks[7:].strip().strip('"').strip("'")
                if not Path(path).exists():
                    print("[!] File tidak ada: {}".format(path)); continue
                paket = T.enkripsi_berkas(path, priv, pub, NAMA)
                print("[i] Kirim file {} (terenkripsi)...".format(Path(path).name))
            else:
                paket = T.enkripsi_pesan(teks, priv, pub, NAMA)
            try:
                sesi.kirim(paket)
            except Exception:
                print("[i] Koneksi terputus."); break
    print("\n[i] Chat selesai.")


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[i] Server dihentikan.")
