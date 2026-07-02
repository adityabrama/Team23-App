"""
================================================================
 chat_server.py — CHAT TERENKRIPSI (sisi SERVER)
================================================================
 Server & client bisa saling kirim pesan. Tiap pesan dienkripsi
 hybrid (Fernet + RSA) dan ditandatangani, lalu didekripsi di
 sisi lawan. Ketik pesan lalu Enter untuk mengirim. Ketik /keluar
 untuk berhenti.

 Cara pakai:
   1) python chat_server.py         (jalankan DULU)
   2) python chat_client.py         (di terminal/mesin lain)
================================================================
"""
import socket, threading, sys
import transport_umum as T

NAMA = "SERVER"


def penerima(conn, priv, pub):
    """Thread: terus menerima & menampilkan pesan masuk."""
    while True:
        try:
            paket = T.terima_pesan(conn)
        except Exception:
            print("\n[i] Koneksi ditutup."); break
        try:
            teks, dari, valid = T.dekripsi_pesan(paket, priv, pub)
            tanda = "" if valid else "  (tanda tangan TIDAK valid!)"
            print("\r{} > {}{}".format(dari, teks, tanda))
            print("{} > ".format(NAMA), end="", flush=True)
        except Exception as e:
            print("\n[!] Gagal buka pesan: {}".format(e))


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
        print("[+] {} terhubung. Mulai chat! (ketik /keluar untuk stop)\n".format(addr[0]))
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
                paket = T.enkripsi_pesan(teks, priv, pub, NAMA)
                try:
                    T.kirim_pesan(conn, paket)
                except Exception:
                    print("[i] Koneksi terputus."); break
    print("\n[i] Chat selesai.")


if __name__ == "__main__":
    main()
