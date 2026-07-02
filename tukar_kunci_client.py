"""
================================================================
 tukar_kunci_client.py — TUKAR PUBLIC KEY (sisi CLIENT)
================================================================
   1. Client MENGIRIM public key-nya (saya_public.pem)
   2. Client MENERIMA public key server -> simpan sbg lawan_public.pem
 Jalankan buat_kunci.py DULU, lalu SETELAH server tukar kunci hidup.
================================================================
"""
import socket
from pathlib import Path
import transport_umum as T


def pub_saya():
    if T.punya_identitas_sendiri():
        return Path(T.path_kunci(T.F_PUB_SAYA)).read_bytes()
    T.pastikan_kunci_demo()
    return Path(T.path_kunci("Pengirim_public.pem")).read_bytes()


def main():
    data_pub_saya = pub_saya()
    print("=== CLIENT TUKAR KUNCI ===")
    print("Menghubungi server {}:{} ...".format(T.HOST_DEFAULT, T.PORT_SERVER))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((T.HOST_DEFAULT, T.PORT_SERVER))
        T.kirim_pesan(s, data_pub_saya)                  # 1. kirim
        print("[>] Public key client dikirim.")
        pub_server = T.terima_pesan(s)                   # 2. terima
        simpan = Path(T.path_kunci(T.F_PUB_LAWAN))
        simpan.write_bytes(pub_server)
        print("[<] Public key server DITERIMA & disimpan: {}".format(simpan.name))
        print("[v] Tukar kunci dua arah selesai! Sekarang bisa saling kirim file.")


if __name__ == "__main__":
    main()
