"""
================================================================
 tukar_kunci_client.py — DEMO TUKAR PUBLIC KEY (sisi CLIENT)
================================================================
   1. Client MENGIRIM public key miliknya ke server.
   2. Client MENERIMA balasan berupa public key server, lalu simpan.
 Jalankan SETELAH server tukar kunci hidup.
================================================================
"""
import socket
from pathlib import Path
import transport_umum as T

KUNCI = T.FOLDER_KUNCI


def main():
    T.pastikan_kunci_demo()
    # public key milik CLIENT yang akan dikirim ke server
    pub_client = (KUNCI / "Pengirim_public.pem").read_bytes()

    print("=== CLIENT TUKAR KUNCI ===")
    print("Menghubungi server {}:{} ...".format(T.HOST_DEFAULT, T.PORT_SERVER))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((T.HOST_DEFAULT, T.PORT_SERVER))
        # 1. KIRIM public key client
        T.kirim_pesan(s, pub_client)
        print("[>] Public key client dikirim.")
        # 2. TERIMA public key server (balasan)
        pub_server = T.terima_pesan(s)
        simpan = KUNCI / "Server_public_diterima.pem"
        simpan.write_bytes(pub_server)
        print("[<] Public key server DITERIMA & disimpan: {}".format(simpan.name))
        print("[v] Tukar kunci dua arah selesai!")


if __name__ == "__main__":
    main()
