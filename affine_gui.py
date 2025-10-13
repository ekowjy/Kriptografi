import tkinter as tk
from tkinter import messagebox
import math

# ---------------------------
# Fungsi bantu matematis
# ---------------------------
def gcd(a, b):
    return math.gcd(a, b)

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x1, y1, g = egcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def modinv(a, n):
    x, y, g = egcd(a, n)
    if g != 1:
        raise ValueError("Invers tidak ada; m dan n tidak relatif prima.")
    return x % n

# ---------------------------
# Fungsi utama Affine Cipher
# ---------------------------
def affine_encrypt_char(ch, m, b):
    p = ord(ch) - 65
    c = (m * p + b) % 26
    return chr(c + 65)

def affine_decrypt_char(ch, m_inv, b):
    c = ord(ch) - 65
    p = (m_inv * (c - b)) % 26
    return chr(p + 65)

def affine_encrypt_text(plaintext, m, b):
    ciphertext = ""
    for ch in plaintext.upper():
        if ch.isalpha():
            ciphertext += affine_encrypt_char(ch, m, b)
        else:
            ciphertext += ch
    return ciphertext

def affine_decrypt_text(ciphertext, m, b):
    m_inv = modinv(m, 26)
    plaintext = ""
    for ch in ciphertext.upper():
        if ch.isalpha():
            plaintext += affine_decrypt_char(ch, m_inv, b)
        else:
            plaintext += ch
    return plaintext

# ---------------------------
# Fungsi untuk tombol GUI
# ---------------------------
def encrypt_action():
    try:
        text = entry_text.get("1.0", tk.END).strip()
        m = int(entry_m.get())
        b = int(entry_b.get())

        if gcd(m, 26) != 1:
            messagebox.showerror("Error", "m tidak relatif prima dengan 26.\nGunakan nilai seperti 1,3,5,7,9,11,15,17,19,21,23,25.")
            return

        result = affine_encrypt_text(text, m, b)
        entry_result.delete("1.0", tk.END)
        entry_result.insert(tk.END, result)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    try:
        text = entry_text.get("1.0", tk.END).strip()
        m = int(entry_m.get())
        b = int(entry_b.get())

        if gcd(m, 26) != 1:
            messagebox.showerror("Error", "m tidak relatif prima dengan 26.")
            return

        result = affine_decrypt_text(text, m, b)
        entry_result.delete("1.0", tk.END)
        entry_result.insert(tk.END, result)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def clear_action():
    entry_text.delete("1.0", tk.END)
    entry_result.delete("1.0", tk.END)
    entry_m.delete(0, tk.END)
    entry_b.delete(0, tk.END)

# ---------------------------
# Desain GUI
# ---------------------------
root = tk.Tk()
root.title("Affine Cipher Encryption & Decryption")
root.geometry("600x450")
root.configure(bg="#EAF3FF")

title = tk.Label(root, text="🔐 Affine Cipher GUI", font=("Segoe UI", 16, "bold"), bg="#EAF3FF", fg="#003366")
title.pack(pady=10)

frame_input = tk.Frame(root, bg="#EAF3FF")
frame_input.pack(pady=5)

lbl_text = tk.Label(frame_input, text="Teks (Plain/Cipher):", bg="#EAF3FF", fg="#003366", font=("Segoe UI", 11))
lbl_text.grid(row=0, column=0, sticky="w", padx=10)

entry_text = tk.Text(frame_input, height=4, width=60, font=("Consolas", 11))
entry_text.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

lbl_m = tk.Label(frame_input, text="m:", bg="#EAF3FF", fg="#003366", font=("Segoe UI", 11))
lbl_m.grid(row=2, column=0, sticky="e", padx=5)
entry_m = tk.Entry(frame_input, width=10, font=("Consolas", 11))
entry_m.grid(row=2, column=1, sticky="w")

lbl_b = tk.Label(frame_input, text="b:", bg="#EAF3FF", fg="#003366", font=("Segoe UI", 11))
lbl_b.grid(row=2, column=2, sticky="e", padx=5)
entry_b = tk.Entry(frame_input, width=10, font=("Consolas", 11))
entry_b.grid(row=2, column=3, sticky="w")

frame_buttons = tk.Frame(root, bg="#EAF3FF")
frame_buttons.pack(pady=10)

btn_encrypt = tk.Button(frame_buttons, text="🔒 Enkripsi", command=encrypt_action, bg="#0078D4", fg="white", font=("Segoe UI", 11, "bold"), width=12)
btn_encrypt.grid(row=0, column=0, padx=10)

btn_decrypt = tk.Button(frame_buttons, text="🔓 Dekripsi", command=decrypt_action, bg="#00A65A", fg="white", font=("Segoe UI", 11, "bold"), width=12)
btn_decrypt.grid(row=0, column=1, padx=10)

btn_clear = tk.Button(frame_buttons, text="🧹 Bersihkan", command=clear_action, bg="#CCCCCC", fg="black", font=("Segoe UI", 11, "bold"), width=12)
btn_clear.grid(row=0, column=2, padx=10)

lbl_result = tk.Label(root, text="Hasil:", bg="#EAF3FF", fg="#003366", font=("Segoe UI", 11))
lbl_result.pack()

entry_result = tk.Text(root, height=4, width=60, font=("Consolas", 11))
entry_result.pack(padx=10, pady=5)

lbl_note = tk.Label(
    root,
    text="Catatan: gunakan m yang relatif prima dengan 26 (1,3,5,7,9,11,15,17,19,21,23,25)",
    bg="#EAF3FF",
    fg="#555555",
    font=("Segoe UI", 9, "italic")
)
lbl_note.pack(pady=5)

root.mainloop()
