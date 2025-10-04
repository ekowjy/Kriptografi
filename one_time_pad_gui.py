# =====================================
# File: otp_gui.py
# GUI Program One-Time Pad Cipher
# Dibuat untuk praktikum kriptografi
# =====================================

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

# ====================================================
# ======== Fungsi untuk Enkripsi dan Dekripsi ========
# ====================================================

def generate_key(length):
    """Membuat kunci acak sepanjang plaintext"""
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def encrypt_otp(plaintext, key):
    """Fungsi enkripsi One-Time Pad"""
    ciphertext = ''
    for p, k in zip(plaintext, key):
        c = (ord(p) - 65 + ord(k) - 65) % 26
        ciphertext += chr(c + 65)
    return ciphertext

def decrypt_otp(ciphertext, key):
    """Fungsi dekripsi One-Time Pad"""
    plaintext = ''
    for c, k in zip(ciphertext, key):
        p = (ord(c) - 65 - (ord(k) - 65)) % 26
        plaintext += chr(p + 65)
    return plaintext

# ====================================================
# ============== FUNGSI TOMBOL ENKRIPSI ==============
# ====================================================

def process_encrypt():
    plain = entry_plain.get().upper().replace(" ", "")
    if not plain.isalpha():
        messagebox.showerror("Error", "Plaintext hanya boleh huruf A-Z tanpa spasi.")
        return

    key = generate_key(len(plain))
    cipher = encrypt_otp(plain, key)

    entry_key_enc.delete(0, tk.END)
    entry_cipher.delete(0, tk.END)
    entry_key_enc.insert(0, key)
    entry_cipher.insert(0, cipher)

    with open("otp_encrypted.txt", "w") as f:
        f.write(f"Plaintext : {plain}\nKey : {key}\nCiphertext : {cipher}\n")

    messagebox.showinfo("Sukses", "Hasil enkripsi telah disimpan ke file 'otp_encrypted.txt'")

# ====================================================
# ============== FUNGSI TOMBOL DEKRIPSI ==============
# ====================================================

def process_decrypt():
    cipher = entry_cipher_dec.get().upper().replace(" ", "")
    key = entry_key_dec.get().upper().replace(" ", "")

    if len(cipher) != len(key):
        messagebox.showerror("Error", "Panjang key harus sama dengan panjang ciphertext.")
        return
    if not cipher.isalpha() or not key.isalpha():
        messagebox.showerror("Error", "Ciphertext dan key hanya boleh huruf A-Z.")
        return

    plain = decrypt_otp(cipher, key)
    entry_plain_dec.delete(0, tk.END)
    entry_plain_dec.insert(0, plain)

    with open("otp_decrypted.txt", "w") as f:
        f.write(f"Ciphertext : {cipher}\nKey : {key}\nPlaintext : {plain}\n")

    messagebox.showinfo("Sukses", "Hasil dekripsi telah disimpan ke file 'otp_decrypted.txt'")

# ====================================================
# ============== MEMBANGUN ANTARMUKA GUI =============
# ====================================================

root = tk.Tk()
root.title("🔐 One-Time Pad Cipher GUI")
root.geometry("600x400")
root.resizable(False, False)

notebook = ttk.Notebook(root)
tab_encrypt = ttk.Frame(notebook)
tab_decrypt = ttk.Frame(notebook)
notebook.add(tab_encrypt, text="Enkripsi")
notebook.add(tab_decrypt, text="Dekripsi")
notebook.pack(expand=True, fill="both")

# ---------------- TAB ENKRIPSI ----------------
tk.Label(tab_encrypt, text="ENKRIPSI ONE-TIME PAD", font=("Arial", 14, "bold")).pack(pady=10)

frame_enc = tk.Frame(tab_encrypt)
frame_enc.pack(pady=10)

tk.Label(frame_enc, text="Plaintext :").grid(row=0, column=0, sticky="e", padx=5, pady=5)
entry_plain = tk.Entry(frame_enc, width=40)
entry_plain.grid(row=0, column=1, pady=5)

tk.Label(frame_enc, text="Key (otomatis) :").grid(row=1, column=0, sticky="e", padx=5, pady=5)
entry_key_enc = tk.Entry(frame_enc, width=40)
entry_key_enc.grid(row=1, column=1, pady=5)

tk.Label(frame_enc, text="Ciphertext :").grid(row=2, column=0, sticky="e", padx=5, pady=5)
entry_cipher = tk.Entry(frame_enc, width=40)
entry_cipher.grid(row=2, column=1, pady=5)

btn_encrypt = tk.Button(tab_encrypt, text="🔒 Enkripsi", bg="#2E86C1", fg="white", font=("Arial", 11, "bold"), command=process_encrypt)
btn_encrypt.pack(pady=10)

# ---------------- TAB DEKRIPSI ----------------
tk.Label(tab_decrypt, text="DEKRIPSI ONE-TIME PAD", font=("Arial", 14, "bold")).pack(pady=10)

frame_dec = tk.Frame(tab_decrypt)
frame_dec.pack(pady=10)

tk.Label(frame_dec, text="Ciphertext :").grid(row=0, column=0, sticky="e", padx=5, pady=5)
entry_cipher_dec = tk.Entry(frame_dec, width=40)
entry_cipher_dec.grid(row=0, column=1, pady=5)

tk.Label(frame_dec, text="Key :").grid(row=1, column=0, sticky="e", padx=5, pady=5)
entry_key_dec = tk.Entry(frame_dec, width=40)
entry_key_dec.grid(row=1, column=1, pady=5)

tk.Label(frame_dec, text="Plaintext :").grid(row=2, column=0, sticky="e", padx=5, pady=5)
entry_plain_dec = tk.Entry(frame_dec, width=40)
entry_plain_dec.grid(row=2, column=1, pady=5)

btn_decrypt = tk.Button(tab_decrypt, text="🔓 Dekripsi", bg="#27AE60", fg="white", font=("Arial", 11, "bold"), command=process_decrypt)
btn_decrypt.pack(pady=10)

# ====================================================
# ==================== RUN PROGRAM ===================
# ====================================================
root.mainloop()
