"""
================================================================
 chat_client.py — CHAT TERENKRIPSI (sisi CLIENT)
================================================================
 Sama seperti chat_server.py, tapi menghubungi server.
 Ketik pesan + Enter untuk kirim. Ketik /keluar untuk berhenti.

 Jalankan SETELAH chat_server.py hidup.
================================================================
"""
import socket, threading
import transport_umum as T

NAMA = "CLIENT"


def penerima(sock, priv, pub):
    while True:
        try:
            paket = T.terima_pesan(sock)
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
    priv, pub, mode = T.muat_pasangan_kunci("client")
    print("=== CHAT CLIENT (mode kunci: {}) ===".format(mode))
    print("Menghubungi server {}:{} ...".format(T.HOST_DEFAULT, T.PORT_SERVER))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((T.HOST_DEFAULT, T.PORT_SERVER))
        print("[+] Terhubung. Mulai chat! (ketik /keluar untuk stop)\n")
        threading.Thread(target=penerima, args=(sock, priv, pub), daemon=True).start()
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
                T.kirim_pesan(sock, paket)
            except Exception:
                print("[i] Koneksi terputus."); break
    print("\n[i] Chat selesai.")


if __name__ == "__main__":
    main()
