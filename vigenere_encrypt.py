# ================================================
# File : vigenere_encrypt.py
# Deskripsi : Enkripsi teks menggunakan Vigenère Cipher
# Penulis : FT
# ================================================

def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""

    for i, char in enumerate(plaintext):
        if char.isalpha():
            # Konversi huruf ke angka 0-25
            p = ord(char) - 65
            k = ord(key[i % len(key)]) - 65
            # Proses enkripsi
            c = (p + k) % 26
            ciphertext += chr(c + 65)
        else:
            # Karakter non-huruf tidak dienkripsi
            ciphertext += char

    return ciphertext


if __name__ == "__main__":
    print("=== Vigenère Cipher Encryption ===")
    plaintext = input("Masukkan teks asli (plaintext): ")
    key = input("Masukkan kunci (key): ")

    encrypted = vigenere_encrypt(plaintext, key)
    print("\nHasil Enkripsi (ciphertext):", encrypted)
