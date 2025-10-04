# ================================================
# File : vigenere_decrypt.py
# Deskripsi : Dekripsi teks menggunakan Vigenère Cipher
# Penulis : Zodi
# ================================================

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""

    for i, char in enumerate(ciphertext):
        if char.isalpha():
            # Konversi huruf ke angka 0-25
            c = ord(char) - 65
            k = ord(key[i % len(key)]) - 65
            # Proses dekripsi
            p = (c - k) % 26
            plaintext += chr(p + 65)
        else:
            # Karakter non-huruf tidak didekripsi
            plaintext += char

    return plaintext


if __name__ == "__main__":
    print("=== Vigenère Cipher Decryption ===")
    ciphertext = input("Masukkan teks sandi (ciphertext): ")
    key = input("Masukkan kunci (key): ")

    decrypted = vigenere_decrypt(ciphertext, key)
    print("\nHasil Dekripsi (plaintext):", decrypted)
