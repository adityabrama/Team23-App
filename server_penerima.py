"""
================================================================
 server_penerima.py — SERVER (PENERIMA) transport TCP Team23
================================================================
 Menerima paket terenkripsi, mendekripsi, memverifikasi 4 prinsip,
 lalu menyimpan file hasil ke folder "diterima/".

 Kunci yang dipakai:
   - Kalau sudah generate kunci sendiri + tukar kunci: otomatis
     pakai saya_private.pem (dekripsi) + lawan_public.pem (verifikasi).
   - Kalau belum: pakai kunci demo Penerima/Pengirim (mode 1 laptop).
================================================================
"""
import socket
from pathlib import Path
import transport_umum as T

FOLDER_HASIL = Path(__file__).parent / "diterima"


def pilih_kunci():
    """Tentukan (private_saya, public_lawan, mode)."""
    sl = T.kunci_saya_lawan()
    if sl:
        return sl[0], sl[1], "PKI (kunci sendiri: saya_private + lawan_public)"
    T.pastikan_kunci_demo()
    return (T.path_kunci("Penerima_private.pem"),
            T.path_kunci("Pengirim_public.pem"),
            "DEMO (Penerima/Pengirim bawaan)")


def tangani_client(conn, addr, priv_saya, pub_lawan):
    print("\n[+] Koneksi masuk dari {}:{}".format(addr[0], addr[1]))
    paket = T.terima_pesan(conn)
    print("[+] Menerima {} byte paket terenkripsi.".format(len(paket)))
    print("[i] Cuplikan ISI FILE terenkripsi yang lewat jaringan:")
    print(T.hexdump(T.ambil_ciphertext_isi(paket), baris_maks=3))

    FOLDER_HASIL.mkdir(exist_ok=True)
    tmp = FOLDER_HASIL / "_paket_masuk.team23"
    tmp.write_bytes(paket)
    try:
        hasil = T.kripto.dekripsi_hybrid(str(tmp), priv_saya, T.PWD_DEMO, pub_lawan)
    except Exception as e:
        print("[!] GAGAL dekripsi: {}".format(e))
        print("[!] => Integritas TIDAK terjamin (paket mungkin disadap & diubah).")
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
    priv_saya, pub_lawan, mode = pilih_kunci()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((T.HOST_BIND, T.PORT_SERVER))
        srv.listen()
        print("====================================================")
        print(" SERVER PENERIMA - Team23 Transport TCP")
        print(" Mode kunci: {}".format(mode))
        print(" Mendengarkan di semua jaringan, port {}".format(T.PORT_SERVER))
        print(" -> Di 1 laptop, client pakai : 127.0.0.1")
        print(" -> Di laptop lain (WiFi), client pakai IP ini : {}".format(T.lan_ip()))
        print(" (tekan Ctrl+C untuk berhenti)")
        print("====================================================")
        try:
            while True:
                conn, addr = srv.accept()
                with conn:
                    tangani_client(conn, addr, priv_saya, pub_lawan)
        except KeyboardInterrupt:
            print("\n[i] Server dihentikan.")


if __name__ == "__main__":
    main()
