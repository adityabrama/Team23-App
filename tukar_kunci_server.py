"""
================================================================
 tukar_kunci_server.py — DEMO TUKAR PUBLIC KEY (sisi SERVER)
================================================================
 Membuktikan koneksi TCP itu DUA ARAH:
   1. Server MENERIMA public key dari client.
   2. Server MEMBALAS dengan public key miliknya sendiri.
 Jalankan server ini DULU, baru client.
================================================================
"""
import socket
from pathlib import Path
import transport_umum as T

KUNCI = T.FOLDER_KUNCI


def main():
    T.pastikan_kunci_demo()
    # public key milik SERVER yang akan dikirim balik ke client
    pub_server = (KUNCI / "Penerima_public.pem").read_bytes()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((T.HOST_BIND, T.PORT_SERVER))
        srv.listen()
        print("=== SERVER TUKAR KUNCI ===")
        print("Menunggu client di port {} ...".format(T.PORT_SERVER))
        print("IP untuk client (WiFi): {}".format(T.lan_ip()))
        while True:
            conn, addr = srv.accept()
            with conn:
                print("\n[+] Client terhubung: {}".format(addr[0]))
                # 1. TERIMA public key client
                pub_client = T.terima_pesan(conn)
                simpan = KUNCI / "Client_public_diterima.pem"
                simpan.write_bytes(pub_client)
                print("[+] Public key client DITERIMA & disimpan: {}".format(simpan.name))
                # 2. BALAS dengan public key server (arah sebaliknya)
                T.kirim_pesan(conn, pub_server)
                print("[+] Public key server DIKIRIM balik ke client. Selesai.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Server dihentikan.")
