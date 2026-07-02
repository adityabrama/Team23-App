"""
================================================================
 tukar_kunci_server.py — TUKAR PUBLIC KEY (sisi SERVER)
================================================================
 Membuktikan koneksi TCP dua arah:
   1. Server MENERIMA public key client  -> simpan sbg lawan_public.pem
   2. Server MEMBALAS public key-nya      -> saya_public.pem
 Jalankan buat_kunci.py DULU, lalu server ini, baru client.
================================================================
"""
import socket
from pathlib import Path
import transport_umum as T


def pub_saya():
    if T.punya_identitas_sendiri():
        return Path(T.path_kunci(T.F_PUB_SAYA)).read_bytes()
    # fallback demo
    T.pastikan_kunci_demo()
    return Path(T.path_kunci("Penerima_public.pem")).read_bytes()


def main():
    data_pub_saya = pub_saya()
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
                pub_client = T.terima_pesan(conn)             # 1. terima
                simpan = Path(T.path_kunci(T.F_PUB_LAWAN))
                simpan.write_bytes(pub_client)
                print("[+] Public key client DITERIMA & disimpan: {}".format(simpan.name))
                T.kirim_pesan(conn, data_pub_saya)            # 2. balas
                print("[+] Public key server DIKIRIM balik. Selesai tukar kunci.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Server dihentikan.")
