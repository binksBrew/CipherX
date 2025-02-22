
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import hashlib
import os

# Generate a valid Fernet key from user input
def generate_fernet_key(user_key):
    hashed_key = hashlib.sha256(user_key.encode()).digest()
    return base64.urlsafe_b64encode(hashed_key)

# Generate a valid AES key
def generate_aes_key(user_key):
    return hashlib.sha256(user_key.encode()).digest()[:16]  # AES requires a 16-byte key

# Generate a valid DES key
def generate_des_key(user_key):
    return hashlib.md5(user_key.encode()).digest()[:8]  # DES requires an 8-byte key

# Encrypt text using the selected method
def encrypt_text():
    input_text = entry.get().strip()
    user_key = key_entry.get().strip()
    method = encryption_method.get()

    if not input_text or not user_key:
        messagebox.showwarning("Warning", "Please enter both text and encryption key.")
        return

    try:
        if method == "AES":
            key = generate_aes_key(user_key)
            cipher = AES.new(key, AES.MODE_ECB)
            padded_text = input_text.ljust(16 * ((len(input_text) // 16) + 1))
            encrypted_text = base64.b64encode(cipher.encrypt(padded_text.encode())).decode()
        elif method == "DES":
            key = generate_des_key(user_key)
            cipher = DES.new(key, DES.MODE_ECB)
            padded_text = input_text.ljust(8 * ((len(input_text) // 8) + 1))
            encrypted_text = base64.b64encode(cipher.encrypt(padded_text.encode())).decode()
        elif method == "RSA":
            key = RSA.generate(2048)
            public_key = key.publickey().export_key()
            private_key = key.export_key()
            cipher = PKCS1_OAEP.new(key)
            encrypted_text = base64.b64encode(cipher.encrypt(input_text.encode())).decode()

            with open("private.pem", "wb") as priv_file:
                priv_file.write(private_key)
            with open("public.pem", "wb") as pub_file:
                pub_file.write(public_key)

        else:  # Default to Fernet
            custom_key = generate_fernet_key(user_key)
            cipher_suite = Fernet(custom_key)
            encrypted_text = cipher_suite.encrypt(input_text.encode()).decode()

        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Encrypted ({method}):\n{encrypted_text}")
        output_text.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

# Decrypt text using the selected method
def decrypt_text():
    input_text = entry.get().strip()
    user_key = key_entry.get().strip()
    method = encryption_method.get()

    if not input_text or not user_key:
        messagebox.showwarning("Warning", "Please enter both encrypted text and key.")
        return

    try:
        encrypted_data = base64.b64decode(input_text.encode())

        if method == "AES":
            key = generate_aes_key(user_key)
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_text = cipher.decrypt(encrypted_data).decode().strip()
        elif method == "DES":
            key = generate_des_key(user_key)
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted_text = cipher.decrypt(encrypted_data).decode().strip()
        elif method == "RSA":
            with open("private.pem", "rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())

            cipher = PKCS1_OAEP.new(private_key)
            decrypted_text = cipher.decrypt(encrypted_data).decode()

        else:  # Default to Fernet
            custom_key = generate_fernet_key(user_key)
            cipher_suite = Fernet(custom_key)
            decrypted_text = cipher_suite.decrypt(input_text.encode()).decode()

        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Decrypted ({method}):\n{decrypted_text}")
        output_text.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# GUI setup
window = tk.Tk()
window.title("Text Encryption & Decryption")
window.geometry("500x500")
window.resizable(False, False)
window.configure(bg="black")

# Title Label
title_label = tk.Label(window, text="Text Encryption & Decryption", font=("Arial", 16, "bold"), fg="#45a29e", bg="black")
title_label.pack(pady=10)

# Dropdown for selecting encryption method
encryption_method = tk.StringVar(value="AES")
method_label = tk.Label(window, text="Select Encryption Method:", font=("Arial", 12, "bold"), fg="#45a29e", bg="black")
method_label.pack(pady=(5, 0))
method_menu = ttk.Combobox(window, textvariable=encryption_method, values=["AES", "DES", "RSA", "Fernet"], state="readonly", width=15)
method_menu.pack(pady=5)

# Key Entry
key_label = tk.Label(window, text="Enter Encryption Key:", font=("Arial", 12, "bold"), fg="#45a29e", bg="black")
key_label.pack(pady=(10, 0))
key_entry = tk.Entry(window, font=("Arial", 12), justify="center", width=30, bg="black", fg="#45a29e", relief="solid", highlightthickness=1)
key_entry.pack(pady=5)

# Input Field
entry_label = tk.Label(window, text="Enter Text:", font=("Arial", 12, "bold"), fg="#45a29e", bg="black")
entry_label.pack(pady=(10, 0))
entry = tk.Entry(window, font=("Arial", 12), justify="center", width=30, bg="black", fg="#45a29e", relief="solid", highlightthickness=1)
entry.pack(pady=5)

# Button Frame
button_frame = tk.Frame(window, bg="black")
button_frame.pack(pady=10)

# Encrypt Button
encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_text, font=("Arial", 12, "bold"), bg="#45a29e", fg="black", borderwidth=2, relief="ridge", width=10)
encrypt_button.grid(row=0, column=0, padx=5)

# Decrypt Button
decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_text, font=("Arial", 12, "bold"), bg="#45a29e", fg="black", borderwidth=2, relief="ridge", width=10)
decrypt_button.grid(row=0, column=1, padx=5)

# Output Text Box
output_text = tk.Text(window, wrap=tk.WORD, font=("Arial", 12), height=5, width=50, bg="black", fg="#45a29e", insertbackground="#45a29e", state=tk.DISABLED, relief="solid", highlightthickness=1)
output_text.pack(padx=10, pady=10, fill="both")

# Footer
footer_label = tk.Label(window, text="Created by Binksbrew", font=("Arial", 10, "bold"), fg="#45a29e", bg="black")
footer_label.pack(side="bottom", pady=10)

# Run GUI
window.mainloop()
