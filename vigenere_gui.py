# ==========================================================
# File    : vigenere_gui.py
# Judul   : Aplikasi GUI Vigenère Cipher (Enkripsi & Dekripsi)
# Penulis : FT
# Versi   : 1.0
# Deskripsi:
#   Aplikasi sederhana berbasis Tkinter untuk melakukan
#   enkripsi dan dekripsi teks dengan algoritma Vigenère Cipher.
# ==========================================================

import tkinter as tk
from tkinter import messagebox

# ---------------------------
# Fungsi Enkripsi
# ---------------------------
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""

    for i, char in enumerate(plaintext):
        if char.isalpha():
            p = ord(char) - 65
            k = ord(key[i % len(key)]) - 65
            c = (p + k) % 26
            ciphertext += chr(c + 65)
        else:
            ciphertext += char
    return ciphertext


# ---------------------------
# Fungsi Dekripsi
# ---------------------------
def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""

    for i, char in enumerate(ciphertext):
        if char.isalpha():
            c = ord(char) - 65
            k = ord(key[i % len(key)]) - 65
            p = (c - k) % 26
            plaintext += chr(p + 65)
        else:
            plaintext += char
    return plaintext


# ---------------------------
# Fungsi Tombol Enkripsi
# ---------------------------
def encrypt_text():
    plaintext = entry_plaintext.get("1.0", tk.END).strip()
    key = entry_key.get().strip()

    if not plaintext:
        messagebox.showwarning("Peringatan", "Teks asli tidak boleh kosong.")
        return
    if not key.isalpha():
        messagebox.showwarning("Peringatan", "Kunci hanya boleh berisi huruf (A-Z).")
        return

    ciphertext = vigenere_encrypt(plaintext, key)
    entry_ciphertext.delete("1.0", tk.END)
    entry_ciphertext.insert(tk.END, ciphertext)


# ---------------------------
# Fungsi Tombol Dekripsi
# ---------------------------
def decrypt_text():
    ciphertext = entry_ciphertext.get("1.0", tk.END).strip()
    key = entry_key.get().strip()

    if not ciphertext:
        messagebox.showwarning("Peringatan", "Teks sandi tidak boleh kosong.")
        return
    if not key.isalpha():
        messagebox.showwarning("Peringatan", "Kunci hanya boleh berisi huruf (A-Z).")
        return

    plaintext = vigenere_decrypt(ciphertext, key)
    entry_plaintext.delete("1.0", tk.END)
    entry_plaintext.insert(tk.END, plaintext)


# ==========================================================
# GUI Setup
# ==========================================================
root = tk.Tk()
root.title("🔐 Vigenère Cipher - Enkripsi & Dekripsi")
root.geometry("600x500")
root.resizable(False, False)
root.config(bg="#f3f4f6")

# Judul
tk.Label(root, text="Vigenère Cipher Encryption & Decryption", 
         font=("Segoe UI", 16, "bold"), bg="#f3f4f6", fg="#333").pack(pady=10)

# Frame input
frame = tk.Frame(root, bg="#f3f4f6")
frame.pack(pady=10)

# Input key
tk.Label(frame, text="Kunci (Key):", font=("Segoe UI", 12), bg="#f3f4f6").grid(row=0, column=0, sticky="w")
entry_key = tk.Entry(frame, font=("Consolas", 12), width=30)
entry_key.grid(row=0, column=1, padx=10, pady=5)

# Input plaintext
tk.Label(frame, text="Teks Asli (Plaintext):", font=("Segoe UI", 12), bg="#f3f4f6").grid(row=1, column=0, sticky="nw")
entry_plaintext = tk.Text(frame, font=("Consolas", 12), height=5, width=40)
entry_plaintext.grid(row=1, column=1, padx=10, pady=5)

# Input ciphertext
tk.Label(frame, text="Teks Sandi (Ciphertext):", font=("Segoe UI", 12), bg="#f3f4f6").grid(row=2, column=0, sticky="nw")
entry_ciphertext = tk.Text(frame, font=("Consolas", 12), height=5, width=40)
entry_ciphertext.grid(row=2, column=1, padx=10, pady=5)

# Tombol
frame_buttons = tk.Frame(root, bg="#f3f4f6")
frame_buttons.pack(pady=10)

btn_encrypt = tk.Button(frame_buttons, text="🔒 Enkripsi", font=("Segoe UI", 12, "bold"), 
                        bg="#2563eb", fg="white", width=15, command=encrypt_text)
btn_encrypt.grid(row=0, column=0, padx=10)

btn_decrypt = tk.Button(frame_buttons, text="🔓 Dekripsi", font=("Segoe UI", 12, "bold"), 
                        bg="#059669", fg="white", width=15, command=decrypt_text)
btn_decrypt.grid(row=0, column=1, padx=10)

# Footer
tk.Label(root, text="© 2025 FT - Vigenère Cipher Educational Tool", 
         font=("Segoe UI", 9), bg="#f3f4f6", fg="#555").pack(side="bottom", pady=10)

root.mainloop()
