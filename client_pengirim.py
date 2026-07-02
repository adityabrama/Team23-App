"""
================================================================
 client_pengirim.py — CLIENT (PENGIRIM) transport TCP Team23
================================================================
 Mengenkripsi sebuah file (hybrid + tanda tangan) lalu mengirimnya
 ke server lewat TCP.

 Kunci yang dipakai:
   - Kalau sudah generate kunci sendiri (buat_kunci.py) DAN sudah
     tukar kunci: otomatis pakai saya_private.pem + lawan_public.pem.
   - Kalau belum: pakai kunci demo Pengirim/Penerima (mode 1 laptop).

 Cara pakai:
   python client_pengirim.py                    -> kirim file contoh
   python client_pengirim.py rahasia.pdf        -> kirim file tertentu
   python client_pengirim.py rahasia.pdf 5024   -> lewat penyadap (port proxy)
================================================================
"""
import socket, sys
from pathlib import Path
import transport_umum as T

DIR = Path(__file__).parent


def siapkan_file_contoh():
    f = DIR / "pesan_rahasia.txt"
    if not f.exists():
        f.write_text(
            "RAHASIA TEAM 23\n"
            "Nomor rekening: 1234-5678-9012\n"
            "Password brankas: merdeka45\n"
            "Pesan ini harusnya TIDAK terbaca kalau disadap di tengah jalan.\n",
            encoding="utf-8")
    return f


def pilih_kunci():
    """Tentukan (private_saya, public_lawan, mode)."""
    sl = T.kunci_saya_lawan()
    if sl:
        return sl[0], sl[1], "PKI (kunci sendiri: saya_private + lawan_public)"
    T.pastikan_kunci_demo()
    return (T.path_kunci("Pengirim_private.pem"),
            T.path_kunci("Penerima_public.pem"),
            "DEMO (Pengirim/Penerima bawaan)")


def main():
    file_kirim = Path(sys.argv[1]) if len(sys.argv) > 1 else siapkan_file_contoh()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else T.PORT_SERVER
    if not file_kirim.exists():
        print("[!] File tidak ditemukan: {}".format(file_kirim)); return

    priv_saya, pub_lawan, mode = pilih_kunci()
    paket, h = T.kripto.enkripsi_hybrid(
        str(file_kirim), priv_saya, T.PWD_DEMO, pub_lawan, "Pengirim", "Penerima")

    print("====================================================")
    print(" CLIENT PENGIRIM - Team23 Transport TCP")
    print("====================================================")
    print("[+] Mode kunci : {}".format(mode))
    print("[+] File       : {} ({} byte)".format(file_kirim.name, file_kirim.stat().st_size))
    print("[+] SHA-256    : {}...".format(h[:48]))
    print("[+] Paket      : {} byte (terenkripsi + ditandatangani)".format(len(paket)))
    tujuan = "PENYADAP (proxy)" if port == T.PORT_PROXY else "SERVER langsung"
    print("[+] Tujuan     : {}:{}  -> {}".format(T.HOST_DEFAULT, port, tujuan))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((T.HOST_DEFAULT, port))
        T.kirim_pesan(sock, paket)
        print("[+] Paket terkirim. Menunggu balasan server...")
        try:
            balasan = T.terima_pesan(sock)
            print("[<] Balasan server: {}".format(balasan.decode(errors="replace")))
        except Exception:
            print("[i] Tidak ada balasan.")


if __name__ == "__main__":
    main()
