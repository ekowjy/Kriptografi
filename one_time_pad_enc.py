# =====================================
# File: otp_encrypt.py
# Program Enkripsi One-Time Pad (OTP)
# =====================================

import random
import string

def generate_key(length):
    """Generate kunci acak sepanjang plaintext"""
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def encrypt_otp(plaintext, key):
    """Enkripsi menggunakan One-Time Pad"""
    ciphertext = ''
    for p, k in zip(plaintext, key):
        c = (ord(p) - 65 + ord(k) - 65) % 26
        ciphertext += chr(c + 65)
    return ciphertext

# ============ MAIN PROGRAM ============
print("=== ENKRIPSI ONE-TIME PAD ===")
print("Gunakan huruf A-Z (tanpa spasi, tanpa angka)")
print("------------------------------------")

# Input plaintext
plain = input("Masukkan plaintext : ").upper().replace(" ", "")

# Generate key acak sepanjang plaintext
key = generate_key(len(plain))

# Enkripsi
cipher = encrypt_otp(plain, key)

# Tampilkan hasil
print("\n=== HASIL ENKRIPSI ===")
print(f"Plaintext : {plain}")
print(f"Key       : {key}")
print(f"Ciphertext: {cipher}")
print("------------------------------------")

# Simpan hasil ke file (opsional)
with open("otp_encrypted.txt", "w") as f:
    f.write(f"Ciphertext: {cipher}\nKey: {key}\n")

print("Hasil enkripsi telah disimpan ke file 'otp_encrypted.txt'")
