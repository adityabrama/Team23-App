

import json, base64, hashlib, datetime
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

FORMAT_PAKET = "TEAM23-HYBRID-V1"
EKSTENSI     = ".team23"

# ================= BAGIAN 1 : FUNGSI KRIPTOGRAFI =================

def _oaep():
    return padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)

def _pss():
    return padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def buat_kunci_rsa():
    """Membuat sepasang kunci RSA-2048."""
    privat = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return privat, privat.public_key()

def simpan_kunci_privat(kunci, path, password):
    """Simpan private key sebagai PEM PKCS#8 terenkripsi password
    (format standar -> bisa dibuka di XCA / OpenSSL)."""
    Path(path).write_bytes(kunci.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode())))

def simpan_kunci_publik(kunci, path):
    """Simpan public key sebagai PEM SubjectPublicKeyInfo (standar)."""
    Path(path).write_bytes(kunci.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))

def muat_kunci_privat(path, password):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(), password.encode())

def muat_kunci_publik(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())

def enkripsi_hybrid(path_file, path_priv_pengirim, pwd_pengirim,
                    path_pub_penerima, nama_pengirim, nama_penerima):
    """Enkripsi hybrid + tanda tangan digital. Menghasilkan paket JSON."""
    data = Path(path_file).read_bytes()
    hash_asli = sha256_hex(data)

    # [KERAHASIAAN + INTEGRITAS] enkripsi simetris Fernet
    kunci_fernet = Fernet.generate_key()
    data_enkripsi = Fernet(kunci_fernet).encrypt(data)

    # [HYBRID] bungkus kunci Fernet dengan public key penerima (RSA-OAEP)
    pub_penerima = muat_kunci_publik(path_pub_penerima)
    kunci_terbungkus = pub_penerima.encrypt(kunci_fernet, _oaep())

    # [OTENTIKASI + NON-REPUDIASI] tanda tangani hash + identitas pengirim
    priv_pengirim = muat_kunci_privat(path_priv_pengirim, pwd_pengirim)
    tanda_tangan = priv_pengirim.sign(
        (hash_asli + nama_pengirim).encode(), _pss(), hashes.SHA256())

    paket = {
        "format":        FORMAT_PAKET,
        "pengirim":      nama_pengirim,
        "penerima":      nama_penerima,
        "nama_file":     Path(path_file).name,
        "ukuran":        len(data),
        "waktu":         datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sha256":        hash_asli,
        "kunci_fernet":  base64.b64encode(kunci_terbungkus).decode(),
        "tanda_tangan":  base64.b64encode(tanda_tangan).decode(),
        "data":          base64.b64encode(data_enkripsi).decode(),
    }
    return json.dumps(paket, indent=1).encode(), hash_asli

def dekripsi_hybrid(path_paket, path_priv_penerima, pwd_penerima,
                    path_pub_pengirim):
    """Dekripsi + verifikasi 4 prinsip. Mengembalikan dict hasil."""
    paket = json.loads(Path(path_paket).read_bytes())
    if paket.get("format") != FORMAT_PAKET:
        raise ValueError("Bukan paket Team23 yang valid!")

    # buka bungkus kunci Fernet dengan private key penerima
    priv_penerima = muat_kunci_privat(path_priv_penerima, pwd_penerima)
    kunci_fernet = priv_penerima.decrypt(
        base64.b64decode(paket["kunci_fernet"]), _oaep())

    # dekripsi Fernet (HMAC bawaan otomatis memverifikasi integritas token)
    try:
        data = Fernet(kunci_fernet).decrypt(base64.b64decode(paket["data"]))
        ok_kerahasiaan = True
    except InvalidToken:
        raise ValueError("Token Fernet rusak / dimodifikasi (integritas gagal)!")

    # cek integritas: bandingkan hash
    hash_hitung = sha256_hex(data)
    ok_integritas = (hash_hitung == paket["sha256"])

    # verifikasi tanda tangan dengan public key pengirim
    ok_ttd = False
    try:
        muat_kunci_publik(path_pub_pengirim).verify(
            base64.b64decode(paket["tanda_tangan"]),
            (paket["sha256"] + paket["pengirim"]).encode(),
            _pss(), hashes.SHA256())
        ok_ttd = True
    except Exception:
        pass

    return {"data": data, "meta": paket, "hash_hitung": hash_hitung,
            "kerahasiaan": ok_kerahasiaan, "integritas": ok_integritas,
            "otentikasi": ok_ttd, "non_repudiasi": ok_ttd}

# ================= BAGIAN 2 : GUI (tkinter, tema terang) =================

WARNA_BG      = "#f2f5fa"
WARNA_SIDEBAR = "#12395e"
WARNA_AKSEN   = "#1f6fb2"
WARNA_KARTU   = "#ffffff"
WARNA_OK      = "#1a8a4a"
WARNA_GAGAL   = "#c0392b"
FONT          = ("Segoe UI", 10)
FONT_TEBAL    = ("Segoe UI", 10, "bold")

def jalankan_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("Team23 App — Enkripsi & Dekripsi Hybrid")
    root.geometry("840x720")
    root.configure(bg=WARNA_BG)

    # ---------- kerangka: sidebar kiri + area konten ----------
    sidebar = tk.Frame(root, bg=WARNA_SIDEBAR, width=170)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    konten = tk.Frame(root, bg=WARNA_BG)
    konten.pack(side="right", fill="both", expand=True)

    tk.Label(sidebar, text="TEAM 23", bg=WARNA_SIDEBAR, fg="white",
             font=("Segoe UI", 16, "bold")).pack(pady=(24, 2))
    tk.Label(sidebar, text="Hybrid Crypto App", bg=WARNA_SIDEBAR,
             fg="#9fc3e8", font=("Segoe UI", 9)).pack(pady=(0, 24))

    halaman = {}
    tombol_nav = {}

    def tampilkan(nama):
        for h in halaman.values():
            h.pack_forget()
        halaman[nama].pack(fill="both", expand=True, padx=16, pady=14)
        for n, b in tombol_nav.items():
            b.configure(bg=WARNA_AKSEN if n == nama else WARNA_SIDEBAR)

    for nama, teks in [("kunci", "  🔑  Buat Kunci"),
                       ("kirim", "  📤  Pengirim"),
                       ("terima", "  📥  Penerima"),
                       ("chat", "  💬  Chat (mTLS)")]:
        b = tk.Button(sidebar, text=teks, anchor="w", relief="flat",
                      bg=WARNA_SIDEBAR, fg="white", font=FONT_TEBAL,
                      activebackground=WARNA_AKSEN, activeforeground="white",
                      cursor="hand2", command=lambda n=nama: tampilkan(n))
        b.pack(fill="x", padx=10, pady=3, ipady=7)
        tombol_nav[nama] = b

    tk.Label(sidebar, text="Kunci PEM standar\n(bisa dibuka di XCA)",
             bg=WARNA_SIDEBAR, fg="#7da9d4",
             font=("Segoe UI", 8)).pack(side="bottom", pady=14)

    # ---------- widget pembantu ----------
    def kartu(induk, judul):
        f = tk.Frame(induk, bg=WARNA_KARTU, highlightbackground="#d7dfe9",
                     highlightthickness=1)
        f.pack(fill="x", pady=(0, 10))
        tk.Label(f, text=judul, bg=WARNA_KARTU, fg=WARNA_SIDEBAR,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        return f

    def baris_input(induk, label, show=None):
        tk.Label(induk, text=label, bg=WARNA_KARTU, font=FONT).pack(
            anchor="w", padx=14)
        e = tk.Entry(induk, font=FONT, show=show or "")
        e.pack(fill="x", padx=14, pady=(1, 7))
        return e

    def baris_file(induk, label, tipe, simpan_ke, kunci):
        tk.Label(induk, text=label, bg=WARNA_KARTU, font=FONT).pack(
            anchor="w", padx=14)
        r = tk.Frame(induk, bg=WARNA_KARTU)
        r.pack(fill="x", padx=14, pady=(1, 7))
        lb = tk.Label(r, text="(belum dipilih)", bg="#eef2f7", fg="#666",
                      font=FONT, anchor="w")
        lb.pack(side="left", fill="x", expand=True, ipady=3)
        def pilih():
            p = filedialog.askopenfilename(filetypes=[(tipe, tipe), ("Semua", "*.*")])
            if p:
                simpan_ke[kunci] = p
                lb.configure(text=Path(p).name, fg="#111")
        tk.Button(r, text="Pilih…", command=pilih, bg=WARNA_AKSEN, fg="white",
                  relief="flat", font=FONT, cursor="hand2").pack(side="right", padx=(6, 0))
        return lb

    def area_log(induk):
        t = tk.Text(induk, height=9, font=("Consolas", 9), bg="#0e2233",
                    fg="#cfe3f5", relief="flat", state="disabled")
        t.pack(fill="both", expand=True)
        return t

    def tulis_log(t, pesan):
        t.configure(state="normal")
        t.insert("end", pesan + "\n")
        t.see("end")
        t.configure(state="disabled")

    def bersihkan_log(t):
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.configure(state="disabled")

    # ---------- HALAMAN 1 : BUAT KUNCI ----------
    hal = tk.Frame(konten, bg=WARNA_BG); halaman["kunci"] = hal
    k = kartu(hal, "Buat Pasangan Kunci RSA-2048")
    e_nama  = baris_input(k, "Nama identitas")
    e_pwd1  = baris_input(k, "Password private key (min. 8 karakter)", show="•")
    e_pwd2  = baris_input(k, "Konfirmasi password", show="•")
    tk.Label(k, text="Folder penyimpanan", bg=WARNA_KARTU, font=FONT).pack(
        anchor="w", padx=14)
    rk = tk.Frame(k, bg=WARNA_KARTU); rk.pack(fill="x", padx=14, pady=(1, 10))
    e_dir = tk.Entry(rk, font=FONT); e_dir.pack(side="left", fill="x", expand=True)
    tk.Button(rk, text="Pilih…", bg=WARNA_AKSEN, fg="white", relief="flat",
              font=FONT, cursor="hand2",
              command=lambda: (e_dir.delete(0, "end"),
                               e_dir.insert(0, filedialog.askdirectory() or ""))
              ).pack(side="right", padx=(6, 0))
    log_k = tk.Text(hal, height=8, font=("Consolas", 9), bg="#0e2233",
                    fg="#cfe3f5", relief="flat", state="disabled")

    def aksi_buat_kunci():
        nama = e_nama.get().strip() or "user"
        pwd, pwd2 = e_pwd1.get(), e_pwd2.get()
        folder = e_dir.get().strip() or "."
        if len(pwd) < 8:
            messagebox.showwarning("Peringatan", "Password minimal 8 karakter!"); return
        if pwd != pwd2:
            messagebox.showerror("Error", "Password tidak cocok!"); return
        try:
            priv, pub = buat_kunci_rsa()
            Path(folder).mkdir(parents=True, exist_ok=True)
            fp = str(Path(folder) / f"{nama}_private.pem")
            fq = str(Path(folder) / f"{nama}_public.pem")
            simpan_kunci_privat(priv, fp, pwd)
            simpan_kunci_publik(pub, fq)
            bersihkan_log(log_k)
            tulis_log(log_k, f"✅ Kunci RSA-2048 berhasil dibuat untuk '{nama}'")
            tulis_log(log_k, f"   Private : {fp}")
            tulis_log(log_k, f"   Public  : {fq}")
            tulis_log(log_k, "   Format PEM standar — bisa diimpor & dilihat di XCA")
            messagebox.showinfo("Sukses", "Kunci berhasil dibuat!")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    tk.Button(hal, text="⚙  Generate Kunci RSA-2048", command=aksi_buat_kunci,
              bg=WARNA_AKSEN, fg="white", relief="flat", font=FONT_TEBAL,
              cursor="hand2").pack(fill="x", ipady=8, pady=(2, 8))
    log_k.pack(fill="both", expand=True)

    # ---------- HALAMAN 2 : PENGIRIM ----------
    hal = tk.Frame(konten, bg=WARNA_BG); halaman["kirim"] = hal
    st_kirim = {"file": None, "priv": None, "pub": None, "paket": None}
    k = kartu(hal, "Enkripsi Hybrid + Tanda Tangan Digital")
    baris_file(k, "File yang akan dikirim", "*.*", st_kirim, "file")
    baris_file(k, "Private key PENGIRIM (.pem)", "*.pem", st_kirim, "priv")
    e_pwd_kirim = baris_input(k, "Password private key pengirim", show="•")
    baris_file(k, "Public key PENERIMA (.pem)", "*.pem", st_kirim, "pub")
    rn = tk.Frame(k, bg=WARNA_KARTU); rn.pack(fill="x", padx=14, pady=(0, 10))
    rn.columnconfigure((0, 1), weight=1)
    tk.Label(rn, text="Nama pengirim", bg=WARNA_KARTU, font=FONT).grid(
        row=0, column=0, sticky="w")
    tk.Label(rn, text="Nama penerima", bg=WARNA_KARTU, font=FONT).grid(
        row=0, column=1, sticky="w", padx=(8, 0))
    e_pengirim = tk.Entry(rn, font=FONT); e_pengirim.grid(row=1, column=0, sticky="ew")
    e_penerima = tk.Entry(rn, font=FONT); e_penerima.grid(
        row=1, column=1, sticky="ew", padx=(8, 0))

    log_e = None
    def aksi_enkripsi():
        if not all([st_kirim["file"], st_kirim["priv"], st_kirim["pub"],
                    e_pwd_kirim.get()]):
            messagebox.showwarning("Peringatan", "Lengkapi semua field!"); return
        try:
            paket, h = enkripsi_hybrid(
                st_kirim["file"], st_kirim["priv"], e_pwd_kirim.get(),
                st_kirim["pub"], e_pengirim.get() or "Pengirim",
                e_penerima.get() or "Penerima")
            st_kirim["paket"] = paket
            bersihkan_log(log_e)
            tulis_log(log_e, "✅ Enkripsi hybrid berhasil!")
            tulis_log(log_e, f"   File     : {Path(st_kirim['file']).name}")
            tulis_log(log_e, f"   Paket    : {len(paket)} byte")
            tulis_log(log_e, f"   SHA-256  : {h[:48]}…")
            tulis_log(log_e, "   Kunci Fernet dibungkus RSA-OAEP ✔  |  Ditandatangani RSA-PSS ✔")
            btn_simpan_paket.configure(state="normal")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def aksi_simpan_paket():
        if not st_kirim["paket"]: return
        out = filedialog.asksaveasfilename(
            defaultextension=EKSTENSI, filetypes=[("Paket Team23", "*" + EKSTENSI)],
            initialfile=Path(st_kirim["file"]).name + EKSTENSI)
        if out:
            Path(out).write_bytes(st_kirim["paket"])
            tulis_log(log_e, f"💾 Paket disimpan: {out}")

    tk.Button(hal, text="🔒  Enkripsi & Tanda Tangani", command=aksi_enkripsi,
              bg=WARNA_OK, fg="white", relief="flat", font=FONT_TEBAL,
              cursor="hand2").pack(fill="x", ipady=8, pady=(2, 3))
    btn_simpan_paket = tk.Button(hal, text="💾  Simpan Paket " + EKSTENSI,
              command=aksi_simpan_paket, state="disabled", bg="#5a6b7d",
              fg="white", relief="flat", font=FONT, cursor="hand2")
    btn_simpan_paket.pack(fill="x", ipady=6, pady=(0, 8))
    log_e = area_log(hal)

    # ---------- HALAMAN 3 : PENERIMA ----------
    hal = tk.Frame(konten, bg=WARNA_BG); halaman["terima"] = hal
    st_terima = {"paket": None, "priv": None, "pub": None,
                 "data": None, "nama": None}
    k = kartu(hal, "Dekripsi & Verifikasi 4 Prinsip")
    baris_file(k, f"File paket ({EKSTENSI})", "*" + EKSTENSI, st_terima, "paket")
    baris_file(k, "Private key PENERIMA (.pem)", "*.pem", st_terima, "priv")
    e_pwd_terima = baris_input(k, "Password private key penerima", show="•")
    baris_file(k, "Public key PENGIRIM (.pem)", "*.pem", st_terima, "pub")

    # panel status 4 prinsip
    panel = tk.Frame(hal, bg=WARNA_BG); panel.pack(fill="x", pady=(0, 6))
    panel.columnconfigure((0, 1, 2, 3), weight=1)
    status = {}
    for i, (kk, tt) in enumerate([("kerahasiaan", "Kerahasiaan"),
                                  ("integritas", "Integritas"),
                                  ("otentikasi", "Otentikasi"),
                                  ("non_repudiasi", "Non-Repudiasi")]):
        c = tk.Frame(panel, bg=WARNA_KARTU, highlightbackground="#d7dfe9",
                     highlightthickness=1)
        c.grid(row=0, column=i, padx=3, sticky="nsew")
        tk.Label(c, text=tt, bg=WARNA_KARTU, font=("Segoe UI", 9, "bold"),
                 fg=WARNA_SIDEBAR).pack(pady=(6, 1))
        status[kk] = tk.Label(c, text="—", bg=WARNA_KARTU, fg="#999",
                              font=("Segoe UI", 9))
        status[kk].pack(pady=(0, 6))

    def set_status(kunci, ok, teks):
        status[kunci].configure(text=("✅ " if ok else "❌ ") + teks,
                                fg=WARNA_OK if ok else WARNA_GAGAL)

    log_d = None
    def aksi_dekripsi():
        if not all([st_terima["paket"], st_terima["priv"], st_terima["pub"],
                    e_pwd_terima.get()]):
            messagebox.showwarning("Peringatan", "Lengkapi semua field!"); return
        for s in status.values():
            s.configure(text="—", fg="#999")
        bersihkan_log(log_d)
        try:
            hasil = dekripsi_hybrid(st_terima["paket"], st_terima["priv"],
                                    e_pwd_terima.get(), st_terima["pub"])
            meta = hasil["meta"]
            st_terima["data"] = hasil["data"]
            st_terima["nama"] = meta["nama_file"]
            tulis_log(log_d, f"Pengirim  : {meta['pengirim']}")
            tulis_log(log_d, f"Penerima  : {meta['penerima']}")
            tulis_log(log_d, f"File asli : {meta['nama_file']} ({meta['ukuran']} byte)")
            tulis_log(log_d, f"Waktu     : {meta['waktu']}")
            set_status("kerahasiaan", True, "Terbuka")
            tulis_log(log_d, f"Hash paket    : {meta['sha256'][:48]}…")
            tulis_log(log_d, f"Hash dihitung : {hasil['hash_hitung'][:48]}…")
            set_status("integritas", hasil["integritas"],
                       "Cocok" if hasil["integritas"] else "Berbeda!")
            set_status("otentikasi", hasil["otentikasi"],
                       meta["pengirim"] if hasil["otentikasi"] else "Tidak valid")
            set_status("non_repudiasi", hasil["non_repudiasi"],
                       "Terbukti" if hasil["non_repudiasi"] else "Gagal")
            if hasil["integritas"] and hasil["otentikasi"]:
                tulis_log(log_d, "─" * 52)
                tulis_log(log_d, "🎉 SEMUA VERIFIKASI BERHASIL — FILE AMAN!")
                btn_simpan_hasil.configure(state="normal")
            else:
                tulis_log(log_d, "⚠ VERIFIKASI GAGAL — file tidak disimpan.")
        except Exception as ex:
            set_status("kerahasiaan", False, "Gagal")
            tulis_log(log_d, f"❌ {ex}")
            messagebox.showerror("Error", str(ex))

    def aksi_simpan_hasil():
        if st_terima["data"] is None: return
        out = filedialog.asksaveasfilename(initialfile=st_terima["nama"] or "hasil")
        if out:
            Path(out).write_bytes(st_terima["data"])
            tulis_log(log_d, f"💾 File hasil disimpan: {out}")

    tk.Button(hal, text="🔓  Dekripsi & Verifikasi", command=aksi_dekripsi,
              bg=WARNA_AKSEN, fg="white", relief="flat", font=FONT_TEBAL,
              cursor="hand2").pack(fill="x", ipady=8, pady=(2, 3))
    btn_simpan_hasil = tk.Button(hal, text="💾  Simpan File Hasil",
              command=aksi_simpan_hasil, state="disabled", bg="#5a6b7d",
              fg="white", relief="flat", font=FONT, cursor="hand2")
    btn_simpan_hasil.pack(fill="x", ipady=6, pady=(0, 8))
    log_d = area_log(hal)

    # ---------- HALAMAN 4 : CHAT (mTLS) ----------
    import socket as _sock, threading as _thr, queue as _q
    import transport_umum as T

    hal = tk.Frame(konten, bg=WARNA_BG); halaman["chat"] = hal
    chat = {"sesi": None, "listen": None, "priv": None, "pub": None, "mode": None,
            "antre": _q.Queue(), "jalan": False, "server_on": False}
    FOLDER_MASUK = Path(__file__).parent / "diterima_chat"

    kc = kartu(hal, "Chat Terenkripsi mTLS (TLS 1.3 + tanda tangan)")
    baris_mode = tk.Frame(kc, bg=WARNA_KARTU); baris_mode.pack(fill="x", padx=14, pady=(0, 6))
    mode_var = tk.StringVar(value="server")
    tk.Label(baris_mode, text="Peran:", bg=WARNA_KARTU, font=FONT).pack(side="left")
    tk.Radiobutton(baris_mode, text="Server (penerima)", variable=mode_var, value="server",
                   bg=WARNA_KARTU, font=FONT, selectcolor="#dbe7f3").pack(side="left", padx=6)
    tk.Radiobutton(baris_mode, text="Client (pengirim)", variable=mode_var, value="client",
                   bg=WARNA_KARTU, font=FONT, selectcolor="#dbe7f3").pack(side="left", padx=6)

    baris_ip = tk.Frame(kc, bg=WARNA_KARTU); baris_ip.pack(fill="x", padx=14, pady=(0, 6))
    tk.Label(baris_ip, text="Alamat server (khusus client):", bg=WARNA_KARTU, font=FONT).pack(side="left")
    e_alamat = tk.Entry(baris_ip, font=FONT, width=16); e_alamat.insert(0, T.HOST_DEFAULT)
    e_alamat.pack(side="left", padx=6)
    penjahat_var = tk.BooleanVar(value=False)
    tk.Checkbutton(baris_ip, text="uji sertifikat PENJAHAT (harus ditolak)",
                   variable=penjahat_var, bg=WARNA_KARTU, font=("Segoe UI", 9),
                   selectcolor="#f3dada").pack(side="left", padx=6)

    lbl_status = tk.Label(kc, text="Status: belum tersambung", bg=WARNA_KARTU,
                          font=("Segoe UI", 9, "bold"), fg="#5a6b7d")
    lbl_status.pack(anchor="w", padx=14, pady=(0, 8))

    log_c = tk.Text(hal, height=11, font=("Consolas", 9), bg="#0e2233",
                    fg="#cfe3f5", relief="flat", state="disabled", padx=10, pady=8, wrap="word")
    log_c.pack(fill="both", expand=True, pady=(0, 6))
    def log_chat(msg):
        log_c.configure(state="normal"); log_c.insert("end", msg + "\n")
        log_c.see("end"); log_c.configure(state="disabled")
    for _b in ["Selamat datang di Chat mTLS Team 23.",
               "1) Pilih peran Server/Client, lalu klik 'Mulai / Sambungkan'.",
               "2) Ketik pesan + Enter, atau tombol File untuk kirim berkas.",
               "3) File yang diterima masuk ke folder diterima_chat/.",
               "Transport diamankan TLS 1.3 (mTLS); tiap pesan juga ditandatangani.", ""]:
        log_chat(_b)

    tk.Label(hal, text="Ketik pesan lalu tekan Enter  •  tombol File untuk kirim berkas",
             bg=WARNA_BG, fg="#5a6b7d", font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 2))
    baris_kirim = tk.Frame(hal, bg=WARNA_BG); baris_kirim.pack(fill="x")
    e_pesan = tk.Entry(baris_kirim, font=FONT); e_pesan.pack(side="left", fill="x", expand=True, ipady=4)

    def _pump():
        try:
            while True:
                jenis, teks = chat["antre"].get_nowait()
                if jenis == "status":
                    lbl_status.configure(text=teks)
                elif jenis == "reset":
                    btn_mulai.configure(state="normal"); btn_stop.configure(state="disabled")
                else:
                    log_chat(teks)
        except _q.Empty:
            pass
        root.after(120, _pump)

    def _terima_loop(sesi):
        """Baca pesan dari SATU sesi (Sesi = TLS ber-lock) sampai putus."""
        while chat["jalan"]:
            try:
                paket = sesi.terima()
            except Exception:
                break
            try:
                info = T.dekripsi_pesan(paket, chat["priv"], chat["pub"])
                catatan = "" if info["valid"] else "  (tanda tangan TIDAK valid!)"
                if info["jenis"] == "file":
                    FOLDER_MASUK.mkdir(exist_ok=True)
                    (FOLDER_MASUK / info["nama_file"]).write_bytes(info["data"])
                    chat["antre"].put(("log", "{} > [FILE: {} ({} B)] -> diterima_chat/{}".format(
                        info["pengirim"], info["nama_file"], len(info["data"]), catatan)))
                else:
                    chat["antre"].put(("log", "{} > {}{}".format(
                        info["pengirim"], info["data"].decode("utf-8"), catatan)))
            except Exception as e:
                chat["antre"].put(("log", "[!] Gagal buka paket: {}".format(e)))

    def _server_thread():
        try:
            ctx = T.konteks_tls_server()
            ls = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            ls.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            ls.bind((T.HOST_BIND, T.PORT_SERVER)); ls.listen(1)
            ls.settimeout(1.0)
            chat["listen"] = ls
            chat["antre"].put(("status", "Status: SERVER menunggu di port {} (IP {}) - TLS mTLS".format(
                T.PORT_SERVER, T.lan_ip())))
            while chat["server_on"]:
                try:
                    raw, addr = ls.accept()
                except _sock.timeout:
                    continue
                except OSError:
                    break
                try:
                    conn = ctx.wrap_socket(raw, server_side=True)
                    cn = dict(x[0] for x in conn.getpeercert()["subject"]).get("commonName", "?")
                except Exception:
                    chat["antre"].put(("log", "[!] Koneksi masuk DITOLAK (sertifikat tak tepercaya)."))
                    try: raw.close()
                    except Exception: pass
                    continue
                sesi = T.Sesi(conn); chat["sesi"] = sesi; chat["jalan"] = True
                chat["antre"].put(("status", "Status: TERSAMBUNG dgn {} | client CN={} | {}".format(
                    addr[0], cn, conn.version())))
                chat["antre"].put(("log", "[v] Client terhubung ({}) via {}. Silakan chat!".format(cn, conn.version())))
                _terima_loop(sesi)
                chat["jalan"] = False
                sesi.tutup(); chat["sesi"] = None
                if chat["server_on"]:
                    chat["antre"].put(("log", "[i] Client terputus. Menunggu koneksi berikutnya..."))
                    chat["antre"].put(("status", "Status: SERVER menunggu di port {} ...".format(T.PORT_SERVER)))
        except Exception as e:
            chat["antre"].put(("log", "[!] Server error: {}".format(e)))
        finally:
            try:
                if chat["listen"]: chat["listen"].close()
            except Exception: pass
            chat["listen"] = None; chat["server_on"] = False; chat["jalan"] = False
            chat["antre"].put(("status", "Status: server berhenti"))
            chat["antre"].put(("reset", ""))

    def _client_thread(alamat, penjahat):
        try:
            ctx = T.konteks_tls_client(pakai_penjahat=penjahat)
            raw = _sock.create_connection((alamat, T.PORT_SERVER), timeout=8)
            conn = ctx.wrap_socket(raw, server_hostname="localhost")
            cn = dict(x[0] for x in conn.getpeercert()["subject"]).get("commonName", "?")
            sesi = T.Sesi(conn); chat["sesi"] = sesi; chat["jalan"] = True
            chat["antre"].put(("status", "Status: TERSAMBUNG ke server (CN={}) | {}".format(cn, conn.version())))
            chat["antre"].put(("log", "[v] Terhubung ke server via {}. Silakan chat!".format(conn.version())))
            _terima_loop(sesi)
        except Exception as e:
            tip = " (sertifikat penjahat memang DITOLAK - itu benar!)" if penjahat else ""
            chat["antre"].put(("log", "[!] Gagal/terputus: {}{}".format(type(e).__name__, tip)))
        finally:
            chat["jalan"] = False
            try:
                if chat["sesi"]: chat["sesi"].tutup()
            except Exception: pass
            chat["sesi"] = None
            chat["antre"].put(("status", "Status: terputus"))
            chat["antre"].put(("reset", ""))

    def aksi_mulai():
        if chat["jalan"] or chat["server_on"]:
            messagebox.showinfo("Info", "Sesi masih berjalan. Klik 'Stop' dulu."); return
        if not T.sert_ada():
            log_chat("[i] Membuat sertifikat mTLS otomatis...")
            try:
                import buat_sertifikat; buat_sertifikat.main()
                log_chat("[i] Sertifikat dibuat di folder sertifikat/.")
            except Exception as e:
                messagebox.showerror("Error", "Gagal buat sertifikat: {}".format(e)); return
        peran = mode_var.get()
        chat["priv"], chat["pub"], km = T.muat_pasangan_kunci(peran)
        chat["mode"] = peran
        log_chat("[i] Mode kunci tanda tangan: {}".format(km))
        btn_mulai.configure(state="disabled"); btn_stop.configure(state="normal")
        if peran == "server":
            chat["server_on"] = True
            _thr.Thread(target=_server_thread, daemon=True).start()
        else:
            _thr.Thread(target=_client_thread,
                        args=(e_alamat.get().strip() or "127.0.0.1", penjahat_var.get()),
                        daemon=True).start()

    def aksi_stop():
        chat["server_on"] = False; chat["jalan"] = False
        try:
            if chat["sesi"]: chat["sesi"].tutup()
        except Exception: pass
        try:
            if chat["listen"]: chat["listen"].close()
        except Exception: pass
        chat["sesi"] = None; chat["listen"] = None
        log_chat("[i] Sesi dihentikan.")
        btn_mulai.configure(state="normal"); btn_stop.configure(state="disabled")

    def aksi_kirim_pesan(_=None):
        teks = e_pesan.get()
        if not teks or not chat["sesi"] or not chat["jalan"]: return
        try:
            nama = chat["mode"].upper()
            chat["sesi"].kirim(T.enkripsi_pesan(teks, chat["priv"], chat["pub"], nama))
            log_chat("{} (saya) > {}".format(nama, teks)); e_pesan.delete(0, "end")
        except Exception as e:
            log_chat("[!] Gagal kirim: {}".format(e))

    def aksi_kirim_file():
        if not chat["sesi"] or not chat["jalan"]:
            messagebox.showwarning("Peringatan", "Belum tersambung."); return
        p = filedialog.askopenfilename()
        if not p: return
        try:
            nama = chat["mode"].upper()
            chat["sesi"].kirim(T.enkripsi_berkas(p, chat["priv"], chat["pub"], nama))
            log_chat("{} (saya) > [FILE terkirim: {} ({} B)]".format(nama, Path(p).name, Path(p).stat().st_size))
        except Exception as e:
            log_chat("[!] Gagal kirim file: {}".format(e))

    e_pesan.bind("<Return>", aksi_kirim_pesan)
    tk.Button(baris_kirim, text="Kirim", command=aksi_kirim_pesan, bg=WARNA_AKSEN,
              fg="white", relief="flat", font=FONT, cursor="hand2").pack(side="left", padx=(6, 0), ipadx=6)
    tk.Button(baris_kirim, text="File", command=aksi_kirim_file, bg="#5a6b7d",
              fg="white", relief="flat", font=FONT, cursor="hand2").pack(side="left", padx=(6, 0), ipadx=4)
    baris_tombol = tk.Frame(kc, bg=WARNA_KARTU); baris_tombol.pack(fill="x", padx=14, pady=(0, 10))
    btn_mulai = tk.Button(baris_tombol, text="Mulai / Sambungkan", command=aksi_mulai, bg=WARNA_OK,
              fg="white", relief="flat", font=FONT_TEBAL, cursor="hand2")
    btn_mulai.pack(side="left", fill="x", expand=True, ipady=6)
    btn_stop = tk.Button(baris_tombol, text="Stop", command=aksi_stop, bg=WARNA_GAGAL,
              fg="white", relief="flat", font=FONT_TEBAL, cursor="hand2", state="disabled")
    btn_stop.pack(side="left", padx=(8, 0), ipady=6, ipadx=10)

    root.after(200, _pump)

    tampilkan("kunci")
    root.mainloop()


if __name__ == "__main__":
    jalankan_gui()
