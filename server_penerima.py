"""
================================================================
 server_penerima.py — SERVER (PENERIMA) transport TCP Team23
================================================================
 Tugas server:
   1. Menunggu koneksi dari client (pengirim) di port TCP.
   2. Menerima paket terenkripsi (hybrid) lewat transport buatan sendiri.
   3. Mendekripsi + memverifikasi 4 prinsip keamanan.
   4. Menyimpan file hasil ke folder "diterima/".

 Cara pakai:
   python server_penerima.py
 (jalankan DULU sebelum client)
================================================================
"""

import socket
from pathlib import Path
import transport_umum as T

FOLDER_HASIL = Path(__file__).parent / "diterima"


def tangani_client(conn, addr):
    print("\n[+] Koneksi masuk dari {}:{}".format(addr[0], addr[1]))

    # 1. Terima paket lewat transport (framing menjamin utuh)
    paket = T.terima_pesan(conn)
    print("[+] Menerima {} byte paket terenkripsi.".format(len(paket)))

    # Tampilkan ISI FILE terenkripsi yang lewat kabel -> byte acak
    print("[i] Cuplikan ISI FILE terenkripsi yang lewat jaringan:")
    print(T.hexdump(T.ambil_ciphertext_isi(paket), baris_maks=3))

    # 2. Simpan paket sementara lalu dekripsi + verifikasi
    FOLDER_HASIL.mkdir(exist_ok=True)
    tmp = FOLDER_HASIL / "_paket_masuk.team23"
    tmp.write_bytes(paket)

    priv_penerima = str(T.FOLDER_KUNCI / "Penerima_private.pem")
    pub_pengirim  = str(T.FOLDER_KUNCI / "Pengirim_public.pem")

    try:
        hasil = T.kripto.dekripsi_hybrid(str(tmp), priv_penerima,
                                         T.PWD_DEMO, pub_pengirim)
    except Exception as e:
        print("[!] GAGAL dekripsi: {}".format(e))
        print("[!] => Integritas TIDAK terjamin (paket kemungkinan disadap & diubah).")
        T.kirim_pesan(conn, b"TOLAK: paket rusak / integritas gagal")
        return

    meta = hasil["meta"]
    print("\n=========== HASIL VERIFIKASI 4 PRINSIP ===========")
    print("  Pengirim   : {}".format(meta["pengirim"]))
    print("  Nama file  : {} ({} byte)".format(meta["nama_file"], meta["ukuran"]))
    def tanda(ok): return "LULUS OK" if ok else "GAGAL X"
    print("  Kerahasiaan   : {}  (isi hanya bisa dibuka kunci privat penerima)".format(tanda(hasil["kerahasiaan"])))
    print("  Integritas    : {}  (hash SHA-256 cocok)".format(tanda(hasil["integritas"])))
    print("  Otentikasi    : {}  (tanda tangan valid dari {})".format(tanda(hasil["otentikasi"]), meta["pengirim"]))
    print("  Non-Repudiasi : {}  (pengirim tak bisa menyangkal)".format(tanda(hasil["non_repudiasi"])))
    print("==================================================")

    if hasil["integritas"] and hasil["otentikasi"]:
        keluar = FOLDER_HASIL / meta["nama_file"]
        keluar.write_bytes(hasil["data"])
        print("[v] File asli berhasil dipulihkan & disimpan: {}".format(keluar))
        T.kirim_pesan(conn, b"OK: file diterima, 4 prinsip LULUS")
    else:
        print("[!] Verifikasi gagal - file TIDAK disimpan.")
        T.kirim_pesan(conn, b"TOLAK: verifikasi gagal (integritas/otentikasi)")


def main():
    dibuat, folder = T.pastikan_kunci_demo()
    if dibuat:
        print("[i] Kunci demo dibuat untuk: {} (di {})".format(", ".join(dibuat), folder))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((T.HOST_BIND, T.PORT_SERVER))
        srv.listen()
        print("====================================================")
        print(" SERVER PENERIMA - Team23 Transport TCP")
        print(" Mendengarkan di semua jaringan, port {}".format(T.PORT_SERVER))
        print(" -> Di 1 laptop, client pakai : 127.0.0.1")
        print(" -> Di laptop lain (WiFi), client pakai IP ini : {}".format(T.lan_ip()))
        print(" (tekan Ctrl+C untuk berhenti)")
        print("====================================================")
        try:
            while True:
                conn, addr = srv.accept()
                with conn:
                    tangani_client(conn, addr)
        except KeyboardInterrupt:
            print("\n[i] Server dihentikan.")


if __name__ == "__main__":
    main()
