"""
================================================================
 chat_server.py — CHAT TERENKRIPSI + KIRIM FILE (sisi SERVER)
================================================================
 Server & client saling kirim pesan/file, semua lewat TCP.
 Tiap pesan/file dienkripsi hybrid (Fernet + RSA) + ditandatangani.

 Perintah saat chat:
   (ketik teks biasa)   -> kirim pesan
   /kirim <namafile>    -> kirim FILE (tersimpan di diterima_chat/ lawan)
   /keluar              -> berhenti

 Cara pakai:
   1) python chat_server.py   (jalankan DULU)
   2) python chat_client.py   (di terminal/mesin lain)
================================================================
"""
import socket, threading
from pathlib import Path
import transport_umum as T

NAMA = "SERVER"
FOLDER_MASUK = Path(__file__).parent / "diterima_chat"


def penerima(conn, priv, pub):
    while True:
        try:
            paket = T.terima_pesan(conn)
        except Exception:
            print("\n[i] Koneksi ditutup."); break
        try:
            info = T.dekripsi_pesan(paket, priv, pub)
            catatan = "" if info["valid"] else "  (tanda tangan TIDAK valid!)"
            if info["jenis"] == "file":
                FOLDER_MASUK.mkdir(exist_ok=True)
                out = FOLDER_MASUK / info["nama_file"]
                out.write_bytes(info["data"])
                print("\r{} > [FILE diterima: {} ({} byte)] -> disimpan di diterima_chat/{}".format(
                    info["pengirim"], info["nama_file"], len(info["data"]), catatan))
            else:
                print("\r{} > {}{}".format(info["pengirim"], info["data"].decode("utf-8"), catatan))
            print("{} > ".format(NAMA), end="", flush=True)
        except Exception as e:
            print("\n[!] Gagal buka paket: {}".format(e))


def main():
    priv, pub, mode = T.muat_pasangan_kunci("server")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((T.HOST_BIND, T.PORT_SERVER))
        srv.listen()
        print("=== CHAT SERVER (mode kunci: {}) ===".format(mode))
        print("Menunggu client di port {} ...".format(T.PORT_SERVER))
        print("IP untuk client (WiFi): {}".format(T.lan_ip()))
        conn, addr = srv.accept()
        print("[+] {} terhubung. Mulai chat!".format(addr[0]))
        print("    (ketik teks=pesan | /kirim <file>=kirim file | /keluar=stop)\n")
        with conn:
            threading.Thread(target=penerima, args=(conn, priv, pub), daemon=True).start()
            while True:
                try:
                    teks = input("{} > ".format(NAMA))
                except (EOFError, KeyboardInterrupt):
                    break
                if teks.strip() == "/keluar":
                    break
                if not teks:
                    continue
                if teks.startswith("/kirim "):
                    path = teks[7:].strip().strip('"').strip("'")
                    if not Path(path).exists():
                        print("[!] File tidak ada: {}".format(path)); continue
                    paket = T.enkripsi_berkas(path, priv, pub, NAMA)
                    print("[i] Mengirim file {} ({} byte, terenkripsi)...".format(Path(path).name, Path(path).stat().st_size))
                else:
                    paket = T.enkripsi_pesan(teks, priv, pub, NAMA)
                try:
                    T.kirim_pesan(conn, paket)
                except Exception:
                    print("[i] Koneksi terputus."); break
    print("\n[i] Chat selesai.")


if __name__ == "__main__":
    main()
