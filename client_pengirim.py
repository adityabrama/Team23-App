"""
================================================================
 client_pengirim.py — CLIENT (PENGIRIM) transport TCP Team23
================================================================
 Tugas client:
   1. Membaca sebuah file.
   2. Mengenkripsi hybrid + menandatanganinya (pakai fungsi Team23App).
   3. Mengirim paket terenkripsi ke server lewat transport TCP.

 Cara pakai:
   python client_pengirim.py                 -> kirim file contoh, langsung ke server
   python client_pengirim.py rahasia.txt     -> kirim file tertentu
   python client_pengirim.py rahasia.txt 5024 -> kirim lewat PENYADAP (port proxy)

 Argumen ke-2 (port) berguna untuk demo: arahkan ke port penyadap
 agar terlihat lalu lintas bisa disadap tapi tetap aman/terenkripsi.
================================================================
"""

import socket, sys
from pathlib import Path
import transport_umum as T

DIR = Path(__file__).parent


def siapkan_file_contoh():
    """Buat file contoh kalau user tidak memberi file."""
    f = DIR / "pesan_rahasia.txt"
    if not f.exists():
        f.write_text(
            "RAHASIA TEAM 23\n"
            "Nomor rekening: 1234-5678-9012\n"
            "Password brankas: merdeka45\n"
            "Pesan ini harusnya TIDAK terbaca kalau disadap di tengah jalan.\n",
            encoding="utf-8")
    return f


def main():
    # argumen: [file] [port]
    file_kirim = Path(sys.argv[1]) if len(sys.argv) > 1 else siapkan_file_contoh()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else T.PORT_SERVER

    if not file_kirim.exists():
        print(f"[!] File tidak ditemukan: {file_kirim}")
        return

    dibuat, folder = T.pastikan_kunci_demo()
    if dibuat:
        print(f"[i] Kunci demo dibuat untuk: {', '.join(dibuat)}")

    # 1+2. Enkripsi hybrid + tanda tangan
    priv_pengirim = str(T.FOLDER_KUNCI / "Pengirim_private.pem")
    pub_penerima  = str(T.FOLDER_KUNCI / "Penerima_public.pem")
    paket, h = T.kripto.enkripsi_hybrid(
        str(file_kirim), priv_pengirim, T.PWD_DEMO,
        pub_penerima, "Pengirim", "Penerima")

    print("=" * 52)
    print(" CLIENT PENGIRIM — Team23 Transport TCP")
    print("=" * 52)
    print(f"[+] File     : {file_kirim.name} ({file_kirim.stat().st_size} byte)")
    print(f"[+] SHA-256  : {h[:48]}…")
    print(f"[+] Paket    : {len(paket)} byte (sudah terenkripsi + ditandatangani)")
    tujuan = "PENYADAP (proxy)" if port == T.PORT_PROXY else "SERVER langsung"
    print(f"[+] Tujuan   : {T.HOST_DEFAULT}:{port}  -> {tujuan}")

    # 3. Kirim lewat transport TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((T.HOST_DEFAULT, port))
        T.kirim_pesan(sock, paket)
        print("[+] Paket terkirim. Menunggu balasan server…")
        try:
            balasan = T.terima_pesan(sock)
            print(f"[<] Balasan server: {balasan.decode(errors='replace')}")
        except Exception:
            print("[i] Tidak ada balasan (mungkin koneksi ditutup penyadap).")


if __name__ == "__main__":
    main()
