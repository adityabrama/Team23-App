"""
================================================================
 buat_kunci.py — GENERATE kunci milik SENDIRI (untuk PKI)
================================================================
 Tiap mesin menjalankan ini SEKALI untuk membuat kuncinya sendiri:
   kunci/saya_private.pem   (rahasia, jangan dibagikan)
   kunci/saya_public.pem    (boleh dibagikan ke lawan)

 Nama file SENGAJA sama di kedua mesin ("saya"), tapi ISI kuncinya
 beda karena digenerate terpisah. Jadi tidak ada yang perlu diedit
 di kode. Setelah ini, jalankan tukar_kunci_* untuk saling berbagi.
================================================================
"""
import sys, hashlib
import transport_umum as T

def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "saya"   # sekadar untuk ditampilkan
    T.FOLDER_KUNCI.mkdir(parents=True, exist_ok=True)
    priv, pub = T.kripto.buat_kunci_rsa()
    T.kripto.simpan_kunci_privat(priv, T.path_kunci(T.F_PRIV_SAYA), T.PWD_DEMO)
    T.kripto.simpan_kunci_publik(pub, T.path_kunci(T.F_PUB_SAYA))
    sidik = hashlib.sha256(open(T.path_kunci(T.F_PUB_SAYA), "rb").read()).hexdigest()[:16]
    print("=== KUNCI SAYA DIBUAT ({}) ===".format(label))
    print("  privat : {}".format(T.path_kunci(T.F_PRIV_SAYA)))
    print("  publik : {}".format(T.path_kunci(T.F_PUB_SAYA)))
    print("  sidik jari public key : {}".format(sidik))
    print("  password private key  : {}".format(T.PWD_DEMO))
    print("Langkah berikutnya: tukar kunci (tukar_kunci_server.py / _client.py)")
    print("supaya public key lawan tersimpan sebagai lawan_public.pem.")

if __name__ == "__main__":
    main()
