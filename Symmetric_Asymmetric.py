import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Pesan yang akan dienkripsi
pesan = b"Universitas Muhammadiyah - Praktikum Keamanan Informasi"

# ==========================
# SIMETRIS (FERNET)
# ==========================

key = Fernet.generate_key()
fernet = Fernet(key)

start = time.time()
ciphertext_fernet = fernet.encrypt(pesan)
decrypted_fernet = fernet.decrypt(ciphertext_fernet)
end = time.time()

waktu_fernet = end - start

# ==========================
# ASIMETRIS (RSA)
# ==========================

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

start = time.time()
ciphertext_rsa = public_key.encrypt(
    pesan,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

decrypted_rsa = private_key.decrypt(
    ciphertext_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

end = time.time()

waktu_rsa = end - start

# ==========================
# HASIL
# ==========================

print("=== FERNET (SIMETRIS) ===")
print("Ciphertext :", ciphertext_fernet)
print("Ukuran Ciphertext :", len(ciphertext_fernet), "byte")
print("Waktu :", waktu_fernet, "detik")
print("Dekripsi :", decrypted_fernet.decode())

print("\n=== RSA (ASIMETRIS) ===")
print("Ciphertext :", ciphertext_rsa)
print("Ukuran Ciphertext :", len(ciphertext_rsa), "byte")
print("Waktu :", waktu_rsa, "detik")
print("Dekripsi :", decrypted_rsa.decode())