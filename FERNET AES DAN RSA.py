from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import time

# =====================================================
# INPUT PLAINTEXT
# =====================================================
print("=" * 80)
print("PERBANDINGAN KRIPTOGRAFI SIMETRIS (FERNET/AES) DAN ASIMETRIS (RSA)")
print("=" * 80)

pesan = input("\nMasukkan plaintext: ")
plaintext = pesan.encode()

# =====================================================
# FERNET (AES) - SIMETRIS
# =====================================================
print("\n[1] FERNET (AES) - SIMETRIS")

# Generate Key
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

# Enkripsi
start = time.perf_counter()
fernet_ciphertext = fernet.encrypt(plaintext)
fernet_encrypt_time = time.perf_counter() - start

# Dekripsi
start = time.perf_counter()
fernet_plaintext = fernet.decrypt(fernet_ciphertext)
fernet_decrypt_time = time.perf_counter() - start

print("\nPlaintext:")
print(pesan)

print("\nCiphertext:")
print(fernet_ciphertext.decode())

print("\nHasil Dekripsi:")
print(fernet_plaintext.decode())

print("\nWaktu Enkripsi :", format(fernet_encrypt_time, ".8f"), "detik")
print("Waktu Dekripsi :", format(fernet_decrypt_time, ".8f"), "detik")
print("Ukuran Ciphertext :", len(fernet_ciphertext), "byte")

# =====================================================
# RSA - ASIMETRIS
# =====================================================
print("\n\n[2] RSA - ASIMETRIS")

# Generate Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Public Key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Private Key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print("\nPUBLIC KEY:")
print(public_pem.decode())

print("PRIVATE KEY:")
print(private_pem.decode())

# Enkripsi RSA
start = time.perf_counter()

rsa_ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_encrypt_time = time.perf_counter() - start

# Dekripsi RSA
start = time.perf_counter()

rsa_plaintext = private_key.decrypt(
    rsa_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_decrypt_time = time.perf_counter() - start

print("\nPlaintext:")
print(pesan)

print("\nCiphertext (Hex):")
print(rsa_ciphertext.hex())

print("\nHasil Dekripsi:")
print(rsa_plaintext.decode())

print("\nWaktu Enkripsi :", format(rsa_encrypt_time, ".8f"), "detik")
print("Waktu Dekripsi :", format(rsa_decrypt_time, ".8f"), "detik")
print("Ukuran Ciphertext :", len(rsa_ciphertext), "byte")

# =====================================================
# TABEL PERBANDINGAN
# =====================================================
print("\n")
print("=" * 80)
print("TABEL PERBANDINGAN")
print("=" * 80)

print(f"{'Parameter':<25}{'Fernet (AES)':<20}{'RSA':<20}")
print("-" * 80)

print(f"{'Waktu Enkripsi':<25}{fernet_encrypt_time:<20.8f}{rsa_encrypt_time:<20.8f}")
print(f"{'Waktu Dekripsi':<25}{fernet_decrypt_time:<20.8f}{rsa_decrypt_time:<20.8f}")
print(f"{'Ukuran Ciphertext':<25}{len(fernet_ciphertext):<20}{len(rsa_ciphertext):<20}")

# =====================================================
# TINGKAT KEAMANAN DASAR
# =====================================================
print("\n")
print("=" * 80)
print("TINGKAT KEAMANAN DASAR")
print("=" * 80)

print(f"{'Aspek':<25}{'Fernet (AES)':<20}{'RSA':<20}")
print("-" * 80)

print(f"{'Jenis Kunci':<25}{'1 Kunci':<20}{'Public & Private':<20}")
print(f"{'Distribusi Kunci':<25}{'Lebih Sulit':<20}{'Lebih Mudah':<20}")
print(f"{'Kecepatan':<25}{'Sangat Cepat':<20}{'Lebih Lambat':<20}")
print(f"{'Data Besar':<25}{'Sangat Cocok':<20}{'Kurang Cocok':<20}")
print(f"{'Digital Signature':<25}{'Tidak':<20}{'Ya':<20}")
print(f"{'Keamanan Dasar':<25}{'Tinggi':<20}{'Tinggi':<20}")

# =====================================================
# KESIMPULAN
# =====================================================
print("\n")
print("=" * 80)
print("KESIMPULAN")
print("=" * 80)

if fernet_encrypt_time < rsa_encrypt_time:
    print("✓ Fernet (AES) lebih cepat dalam proses enkripsi.")

if fernet_decrypt_time < rsa_decrypt_time:
    print("✓ Fernet (AES) lebih cepat dalam proses dekripsi.")

if len(fernet_ciphertext) < len(rsa_ciphertext):
    print("✓ Fernet menghasilkan ciphertext yang lebih kecil.")

print("✓ RSA menggunakan Public Key dan Private Key.")
print("✓ RSA lebih aman untuk distribusi kunci.")
print("✓ AES/Fernet lebih cocok untuk enkripsi data berukuran besar.")
print("✓ Pada sistem modern, AES dan RSA biasanya digunakan secara bersamaan.")