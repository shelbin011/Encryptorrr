import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import os

# ---------------- Key Loader ----------------
def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        messagebox.showerror("Error", "secret.key not found! Run main.py first.")
        return None

# ---------------- Encrypt File ----------------
def encrypt_file():
    key = load_key()
    if key is None:
        return

    filename = filedialog.askopenfilename(title="Select file to encrypt")
    if not filename:
        return

    password = password_entry.get()
    if password == "":
        messagebox.showwarning("Password Required", "Enter a password before encrypting.")
        return

    fernet = Fernet(key)
    hashed_pass = hashlib.sha256(password.encode()).hexdigest().encode()

    with open(filename, "rb") as file:
        original = file.read()

    encrypted_data = fernet.encrypt(original)
    final_data = hashed_pass + b"||" + encrypted_data

    with open(filename + ".encrypted", "wb") as enc_file:
        enc_file.write(final_data)

    messagebox.showinfo("Success", f"File encrypted:\n{filename}.encrypted")

# ---------------- Decrypt File ----------------
def decrypt_file():
    key = load_key()
    if key is None:
        return

    filename = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted Files", "*.encrypted")])
    if not filename:
        return

    password = password_entry.get()
    if password == "":
        messagebox.showwarning("Password Required", "Enter a password to decrypt.")
        return

    with open(filename, "rb") as enc_file:
        file_data = enc_file.read()

    stored_hash, encrypted_data = file_data.split(b"||", 1)
    hashed_input = hashlib.sha256(password.encode()).hexdigest().encode()

    if hashed_input != stored_hash:
        messagebox.showerror("Error", "Incorrect password!")
        return

    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)

    original_name = filename.replace(".encrypted", "")
    with open(original_name, "wb") as dec_file:
        dec_file.write(decrypted)

    messagebox.showinfo("Success", f"File decrypted:\n{original_name}")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("File Encryptor & Decryptor")
root.geometry("400x260")
root.resizable(False, False)

tk.Label(root, text="🔐 File Encryptor & Decryptor", font=("Segoe UI", 14, "bold")).pack(pady=10)

tk.Label(root, text="Enter Password:", font=("Segoe UI", 10)).pack()
password_entry = tk.Entry(root, show="*", width=35, font=("Segoe UI", 10))
password_entry.pack(pady=5)

encrypt_btn = tk.Button(root, text="Encrypt File", width=20, font=("Segoe UI", 11), command=encrypt_file)
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt File", width=20, font=("Segoe UI", 11), command=decrypt_file)
decrypt_btn.pack(pady=10)

root.mainloop()
