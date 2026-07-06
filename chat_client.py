"""
================================================================
 chat_client.py — CHAT mTLS (sisi CLIENT) versi terminal
================================================================
 Perintah: teks = pesan | /kirim <file> = kirim file | /keluar
 Jalankan SETELAH chat_server.py hidup.

 Untuk MENGUJI penolakan sertifikat palsu, jalankan:
     python chat_client.py penjahat
 (client akan memakai penjahat.crt dan DITOLAK server).
================================================================
"""
import socket, ssl, threading, sys
from pathlib import Path
import transport_umum as T

NAMA = "CLIENT"
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
    penjahat = (len(sys.argv) > 1 and sys.argv[1].lower() == "penjahat")
    if not T.sert_ada():
        import buat_sertifikat; buat_sertifikat.main()
    priv, pub, mode = T.muat_pasangan_kunci("client")
    ctx = T.konteks_tls_client(pakai_penjahat=penjahat)
    print("=== CHAT CLIENT mTLS (kunci ttd: {}) ===".format(mode))
    if penjahat: print("!! MODE PENJAHAT: memakai sertifikat palsu — seharusnya DITOLAK.")
    print("Menghubungi server {}:{} ...".format(T.HOST_DEFAULT, T.PORT_SERVER))
    try:
        raw = socket.create_connection((T.HOST_DEFAULT, T.PORT_SERVER), timeout=8)
        conn = ctx.wrap_socket(raw, server_hostname="localhost")
        # paksa komunikasi supaya penolakan penjahat langsung terdeteksi
        cn = dict(x[0] for x in conn.getpeercert()["subject"]).get("commonName", "?")
    except ssl.SSLError as e:
        print("[!] DITOLAK saat handshake:", str(e).split('] ')[-1][:60]); return
    except Exception as e:
        print("[!] Gagal konek:", type(e).__name__, str(e)[:60]); return
    print("[v] Terhubung ke server (CN={}) via {}. Mulai chat!".format(cn, conn.version()))
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
    main()
