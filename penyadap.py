"""
================================================================
 penyadap.py — DEMO PENYADAP (Man-in-the-Middle) Team23
================================================================
 Program ini berpura-pura menjadi "penyadap" di tengah jalan.
 Ia duduk di antara CLIENT dan SERVER: client mengira ini server,
 padahal ia hanya meneruskan (relay) data ke server asli — sambil
 MENGINTIP semua byte yang lewat.

 Ini membuktikan 2 hal untuk presentasi:
   1. AMAN SAAT DISADAP  : yang tertangkap penyadap hanyalah ciphertext
                           acak — isi rahasia file TIDAK terbaca.
   2. INTEGRITAS TERJAGA : kalau penyadap iseng mengubah 1 byte saja
                           (mode --tamper), server LANGSUNG menolak
                           karena verifikasi hash/tanda tangan gagal.

 Cara pakai:
   python penyadap.py            -> hanya mengintip (relay apa adanya)
   python penyadap.py --tamper   -> mengintip + mengubah 1 byte (serangan)

 Urutan demo:
   Terminal 1: python server_penerima.py
   Terminal 2: python penyadap.py            (atau --tamper)
   Terminal 3: python client_pengirim.py pesan_rahasia.txt 5024
                (angka 5024 = kirim lewat penyadap, bukan langsung)
================================================================
"""

import socket, sys, struct
import transport_umum as T

TAMPER = "--tamper" in sys.argv


def baca_frame(sock):
    """Baca satu frame [4 byte panjang][isi] dari sock."""
    head = b""
    while len(head) < 4:
        p = sock.recv(4 - len(head))
        if not p: return None
        head += p
    n = struct.unpack(">I", head)[0]
    isi = b""
    while len(isi) < n:
        p = sock.recv(n - len(isi))
        if not p: return None
        isi += p
    return isi


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((T.HOST_DEFAULT, T.PORT_PROXY))
        proxy.listen()
        print("=" * 52)
        print(" PENYADAP (Man-in-the-Middle) — Team23")
        print(f" Menyamar sebagai server di {T.HOST_DEFAULT}:{T.PORT_PROXY}")
        print(f" Mode : {'MENGUBAH DATA (serangan)' if TAMPER else 'hanya mengintip'}")
        print(f" Meneruskan ke server asli {T.HOST_DEFAULT}:{T.PORT_SERVER}")
        print("=" * 52)

        while True:
            client, addr = proxy.accept()
            print(f"\n[*] Korban terhubung dari {addr[0]}:{addr[1]}")

            # 1. Tangkap paket dari client
            paket = baca_frame(client)
            if paket is None:
                client.close(); continue
            print(f"[*] TERTANGKAP {len(paket)} byte. ISI FILE terenkripsi (mentah):")
            print(T.hexdump(T.ambil_ciphertext_isi(paket), baris_maks=4))
            # Bukti: cari kata rahasia di seluruh byte tangkapan -> tidak ada
            bocor = [k for k in [b"merdeka45", b"1234-5678", b"Password", b"rekening"]
                     if k in paket]
            if bocor:
                print(f"[*] BOCOR: {bocor}")
            else:
                print("[*] => Dicari kata rahasia ('merdeka45', 'rekening', dst) di tangkapan:")
                print("[*]    TIDAK DITEMUKAN. Isi rahasia aman meski disadap. ✅")

            kirim = paket
            if TAMPER:
                b = bytearray(paket)
                b[len(b) // 2] ^= 0xFF      # balik 1 byte di tengah
                kirim = bytes(b)
                print("[!] MODE SERANGAN: 1 byte diubah sebelum diteruskan!")

            # 2. Teruskan ke server asli
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ke_server:
                ke_server.connect((T.HOST_DEFAULT, T.PORT_SERVER))
                ke_server.sendall(struct.pack(">I", len(kirim)) + kirim)
                balasan = baca_frame(ke_server)

            # 3. Teruskan balasan server ke client
            if balasan is not None:
                print(f"[*] Balasan server: {balasan.decode(errors='replace')}")
                if TAMPER:
                    print("[*] => Server MENOLAK karena integritas gagal. Serangan digagalkan! ✅")
                client.sendall(struct.pack(">I", len(balasan)) + balasan)
            client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Penyadap dihentikan.")
