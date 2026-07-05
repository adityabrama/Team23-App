"""
================================================================
 buat_sertifikat.py — Membuat sertifikat untuk mTLS (Team23)
================================================================
 Membuat struktur Certificate Authority (CA) lalu menandatangani
 sertifikat server & client dengan CA itu:

              CA (My Test CA)
               |
       +-------+--------+
       |                |
   server.crt       client.crt      <- keduanya DITANDATANGANI CA

 Plus sertifikat "penjahat" yang TIDAK ditandatangani CA (untuk
 membuktikan bahwa koneksi dari pihak tak tepercaya akan DITOLAK).

 Semua disimpan di folder sertifikat/. Pakai library cryptography
 (murni Python) supaya jalan di Windows/Linux tanpa install OpenSSL.
================================================================
"""
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DIR = Path(__file__).parent / "sertifikat"


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def _simpan_key(key, path):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

def _simpan_crt(cert, path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

def _nama(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def buat_ca():
    key = _rsa()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(_nama("Team23 Test CA"))
        .issuer_name(_nama("Team23 Test CA"))        # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    return key, cert

def sign_oleh_ca(cn, ca_key, ca_cert, san_list=None):
    """Buat kunci + sertifikat untuk cn, DITANDATANGANI oleh CA."""
    key = _rsa()
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
        .subject_name(_nama(cn))
        .issuer_name(ca_cert.subject)                # penerbit = CA
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if san_list:
        b = b.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
    cert = b.sign(ca_key, hashes.SHA256())           # DITANDATANGANI kunci CA
    return key, cert

def buat_self_signed(cn):
    """Sertifikat self-signed (mis. 'penjahat') — TIDAK dikenal CA kita."""
    key = _rsa()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(_nama(cn)).issuer_name(_nama(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256()))
    return key, cert


def main():
    DIR.mkdir(parents=True, exist_ok=True)
    # SAN: supaya cocok untuk localhost & IP umum (walau app juga tetap
    # bisa jalan lintas-IP karena verifikasi utama = ditandatangani CA)
    import ipaddress
    san = [x509.DNSName("localhost"),
           x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
           x509.IPAddress(ipaddress.ip_address("10.0.2.2"))]

    ca_key, ca_cert = buat_ca()
    _simpan_key(ca_key, DIR/"ca.key"); _simpan_crt(ca_cert, DIR/"ca.crt")

    s_key, s_cert = sign_oleh_ca("localhost", ca_key, ca_cert, san)
    _simpan_key(s_key, DIR/"server.key"); _simpan_crt(s_cert, DIR/"server.crt")

    c_key, c_cert = sign_oleh_ca("team23-client", ca_key, ca_cert)
    _simpan_key(c_key, DIR/"client.key"); _simpan_crt(c_cert, DIR/"client.crt")

    p_key, p_cert = buat_self_signed("Penjahat")
    _simpan_key(p_key, DIR/"penjahat.key"); _simpan_crt(p_cert, DIR/"penjahat.crt")

    print("=== SERTIFIKAT DIBUAT (folder sertifikat/) ===")
    print("  ca.crt / ca.key            : Certificate Authority (penanda tangan)")
    print("  server.crt / server.key    : sertifikat SERVER  (ditandatangani CA)")
    print("  client.crt / client.key    : sertifikat CLIENT  (ditandatangani CA)")
    print("  penjahat.crt / penjahat.key: sertifikat PALSU   (TIDAK dikenal CA)")

if __name__ == "__main__":
    main()
