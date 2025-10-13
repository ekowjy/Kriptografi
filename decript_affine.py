# decript_affine_text.py
import math

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x1, y1, g = egcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def modinv(a, n):
    x, y, g = egcd(a, n)
    if g != 1:
        raise ValueError("Invers tidak ada; m dan n tidak coprime.")
    return x % n

def affine_decrypt_char(ch, m_inv, b):
    c = ord(ch) - 65
    p = (m_inv * (c - b)) % 26
    return chr(p + 65)

def affine_decrypt_text(ciphertext, m, b):
    m_inv = modinv(m, 26)
    plaintext = ""
    for ch in ciphertext.upper():
        if ch.isalpha():
            plaintext += affine_decrypt_char(ch, m_inv, b)
        else:
            plaintext += ch
    return plaintext

if __name__ == "__main__":
    print("=== AFFINE DECRYPTION (TEKS) ===")
    ciphertext = input("Masukkan ciphertext: ")
    m = int(input("Masukkan kunci m (relatif prima dengan 26): "))
    b = int(input("Masukkan kunci b (0-25): "))

    plaintext = affine_decrypt_text(ciphertext, m, b)
    print(f"\nCiphertext: {ciphertext.upper()}")
    print(f"Plaintext : {plaintext}")
