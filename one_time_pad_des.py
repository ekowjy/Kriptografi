# =====================================
# File: otp_decrypt.py
# Program Dekripsi One-Time Pad (OTP)
# =====================================

def decrypt_otp(ciphertext, key):
    """Dekripsi menggunakan One-Time Pad"""
    plaintext = ''
    for c, k in zip(ciphertext, key):
        p = (ord(c) - 65 - (ord(k) - 65)) % 26
        plaintext += chr(p + 65)
    return plaintext

# ============ MAIN PROGRAM ============
print("=== DEKRIPSI ONE-TIME PAD ===")
print("Gunakan huruf A-Z (tanpa spasi, tanpa angka)")
print("------------------------------------")

# Input ciphertext dan key
cipher = input("Masukkan ciphertext : ").upper().replace(" ", "")
key = input("Masukkan key         : ").upper().replace(" ", "")

# Validasi panjang key dan cipher
if len(cipher) != len(key):
    print("\n❌ Error: Panjang key harus sama dengan panjang ciphertext.")
else:
    # Dekripsi
    plain = decrypt_otp(cipher, key)

    # Tampilkan hasil
    print("\n=== HASIL DEKRIPSI ===")
    print(f"Ciphertext : {cipher}")
    print(f"Key        : {key}")
    print(f"Plaintext  : {plain}")
    print("------------------------------------")

    # Simpan hasil ke file (opsional)
    with open("otp_decrypted.txt", "w") as f:
        f.write(f"Plaintext: {plain}\n")

    print("Hasil dekripsi telah disimpan ke file 'otp_decrypted.txt'")
