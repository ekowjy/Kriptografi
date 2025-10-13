# encript_affine_text.py
import math

def gcd(a, b):
    return math.gcd(a, b)

def affine_encrypt_char(ch, m, b):
    # ubah huruf ke angka (A=0..Z=25)
    p = ord(ch) - 65
    c = (m * p + b) % 26
    return chr(c + 65)

def affine_encrypt_text(plaintext, m, b):
    ciphertext = ""
    for ch in plaintext.upper():
        if ch.isalpha():
            ciphertext += affine_encrypt_char(ch, m, b)
        else:
            ciphertext += ch  # biarkan spasi/tanda baca
    return ciphertext

if __name__ == "__main__":
    print("=== AFFINE ENCRYPTION (TEKS) ===")
    plaintext = input("Masukkan plaintext (huruf): ")
    m = int(input("Masukkan kunci m (relatif prima dengan 26): "))
    b = int(input("Masukkan kunci b (0-25): "))

    if gcd(m, 26) != 1:
        print("❌ Kunci m tidak relatif prima terhadap 26. Pilih nilai m yang lain.")
    else:
        ciphertext = affine_encrypt_text(plaintext, m, b)
        print(f"\nPlaintext : {plaintext.upper()}")
        print(f"Ciphertext: {ciphertext}")
