# import tkinter as tk
# from tkinter import ttk, messagebox
# from cryptography.fernet import Fernet
# import base64
# import hashlib

# # Function to generate a valid Fernet key from user input
# def generate_key(user_key):
#     """Convert a user-defined key into a valid AES key."""
#     hashed_key = hashlib.sha256(user_key.encode()).digest()  # Hash the user key
#     return base64.urlsafe_b64encode(hashed_key)  # Convert to Fernet-compatible key

# # Encrypt text using a custom key
# def encrypt_text():
#     input_text = entry.get().strip()
#     user_key = key_entry.get().strip()

#     if not input_text or not user_key:
#         messagebox.showwarning("Warning", "Please enter both text and encryption key.")
#         return

#     # Generate Fernet key from user input
#     custom_key = generate_key(user_key)
#     cipher_suite = Fernet(custom_key)

#     encrypted_text = cipher_suite.encrypt(input_text.encode()).decode()

#     # Display encrypted text
#     output_text.config(state=tk.NORMAL)
#     output_text.delete(1.0, tk.END)
#     output_text.insert(tk.END, f"Encrypted: {encrypted_text}")
#     output_text.config(state=tk.DISABLED)

# # Decrypt text using a custom key
# def decrypt_text():
#     input_text = entry.get().strip()
#     user_key = key_entry.get().strip()

#     if not input_text or not user_key:
#         messagebox.showwarning("Warning", "Please enter both encrypted text and key.")
#         return

#     try:
#         # Generate Fernet key from user input
#         custom_key = generate_key(user_key)
#         cipher_suite = Fernet(custom_key)

#         decrypted_text = cipher_suite.decrypt(input_text.encode()).decode()

#         # Display decrypted text
#         output_text.config(state=tk.NORMAL)
#         output_text.delete(1.0, tk.END)
#         output_text.insert(tk.END, f"Decrypted: {decrypted_text}")
#         output_text.config(state=tk.DISABLED)
#     except Exception:
#         messagebox.showerror("Error", "Invalid encryption key or text!")

# # Create main window
# window = tk.Tk()
# window.title("Custom Key Encryption & Decryption")
# window.geometry("400x500")
# window.resizable(False, False)
# window.configure(bg="#f4f4f4")

# # Title Label
# title_label = ttk.Label(window, text="Custom Key Encryption & Decryption", font=("Arial", 14, "bold"), background="#f4f4f4")
# title_label.pack(pady=10)

# # Key Entry Field
# key_label = ttk.Label(window, text="Enter Encryption Key:", font=("Arial", 12), background="#f4f4f4")
# key_label.pack()
# key_entry = ttk.Entry(window, font=("Arial", 12), justify="center", width=35)
# key_entry.pack(pady=5)

# # Input Field
# entry_label = ttk.Label(window, text="Enter Text:", font=("Arial", 12), background="#f4f4f4")
# entry_label.pack()
# entry = ttk.Entry(window, font=("Arial", 12), justify="center", width=35)
# entry.pack(pady=5)

# # Button Frame
# button_frame = ttk.Frame(window)
# button_frame.pack(pady=5)

# # Encrypt Button
# encrypt_button = ttk.Button(button_frame, text="Encrypt", command=encrypt_text)
# encrypt_button.grid(row=0, column=0, padx=10)

# # Decrypt Button
# decrypt_button = ttk.Button(button_frame, text="Decrypt", command=decrypt_text)
# decrypt_button.grid(row=0, column=1, padx=10)

# # Output Text Box
# output_text = tk.Text(window, wrap=tk.WORD, font=("Arial", 12), height=8, bg="#ffffff", state=tk.DISABLED)
# output_text.pack(padx=20, pady=10, fill="both")

# # Footer Label
# footer_label = ttk.Label(window, text="Created by Binksbrew", font=("Arial", 10), foreground="gray", background="#f4f4f4")
# footer_label.pack(side="bottom", pady=10)

# # Run GUI
# window.mainloop()












import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# Function to generate a valid Fernet key from user input
def generate_key(user_key):
    """Convert a user-defined key into a valid AES key."""
    hashed_key = hashlib.sha256(user_key.encode()).digest()  # Hash the user key
    return base64.urlsafe_b64encode(hashed_key)  # Convert to Fernet-compatible key

# Encrypt text using a custom key
def encrypt_text():
    input_text = entry.get().strip()
    user_key = key_entry.get().strip()

    if not input_text or not user_key:
        messagebox.showwarning("Warning", "Please enter both text and encryption key.")
        return

    # Generate Fernet key from user input
    custom_key = generate_key(user_key)
    cipher_suite = Fernet(custom_key)

    encrypted_text = cipher_suite.encrypt(input_text.encode()).decode()

    # Display encrypted text
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Encrypted:\n{encrypted_text}")
    output_text.config(state=tk.DISABLED)

# Decrypt text using a custom key
def decrypt_text():
    input_text = entry.get().strip()
    user_key = key_entry.get().strip()

    if not input_text or not user_key:
        messagebox.showwarning("Warning", "Please enter both encrypted text and key.")
        return

    try:
        # Generate Fernet key from user input
        custom_key = generate_key(user_key)
        cipher_suite = Fernet(custom_key)

        decrypted_text = cipher_suite.decrypt(input_text.encode()).decode()

        # Display decrypted text
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Decrypted:\n{decrypted_text}")
        output_text.config(state=tk.DISABLED)
    except Exception:
        messagebox.showerror("Error", "Invalid encryption key or text!")

# Function to highlight input fields when focused
def on_focus_in(event):
    event.widget.config(highlightbackground="#45a29e", highlightcolor="#45a29e", highlightthickness=2)

def on_focus_out(event):
    event.widget.config(highlightbackground="#ffffff", highlightcolor="#ffffff", highlightthickness=1)

# Function to change button color on hover
def on_enter(event):
    event.widget.config(background="#45a29e", foreground="black")

def on_leave(event):
    event.widget.config(background="black", foreground="#45a29e")

# Create main window
window = tk.Tk()
window.title("Custom Key Encryption & Decryption")
window.geometry("500x600")  # Bigger window
window.resizable(False, False)
window.configure(bg="black")  # Black background

# Title Label
title_label = ttk.Label(window, text="Custom Key Encryption & Decryption", font=("Arial", 16, "bold"), foreground="#45a29e", background="black")
title_label.pack(pady=20)

# Key Entry Field
key_label = ttk.Label(window, text="Enter Encryption Key:", font=("Arial", 12, "bold"), foreground="#45a29e", background="black")
key_label.pack()
key_entry = tk.Entry(window, font=("Arial", 12), justify="center", width=40, bg="black", fg="#45a29e", relief="solid", highlightthickness=1)
key_entry.pack(pady=5)
key_entry.bind("<FocusIn>", on_focus_in)
key_entry.bind("<FocusOut>", on_focus_out)

# Input Field
entry_label = ttk.Label(window, text="Enter Text:", font=("Arial", 12, "bold"), foreground="#45a29e", background="black")
entry_label.pack()
entry = tk.Entry(window, font=("Arial", 12), justify="center", width=40, bg="black", fg="#45a29e", relief="solid", highlightthickness=1)
entry.pack(pady=5)
entry.bind("<FocusIn>", on_focus_in)
entry.bind("<FocusOut>", on_focus_out)

# Button Frame
style = ttk.Style()
style.configure("Black.TFrame", background="black")

button_frame = ttk.Frame(window, style="Black.TFrame")

button_frame.pack(pady=10)

# Encrypt Button
encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_text, font=("Arial", 12, "bold"), bg="black", fg="#45a29e", borderwidth=2, relief="ridge")
encrypt_button.grid(row=0, column=0, padx=20)
encrypt_button.bind("<Enter>", on_enter)
encrypt_button.bind("<Leave>", on_leave)

# Decrypt Button
decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_text, font=("Arial", 12, "bold"), bg="black", fg="#45a29e", borderwidth=2, relief="ridge")
decrypt_button.grid(row=0, column=1, padx=20)
decrypt_button.bind("<Enter>", on_enter)
decrypt_button.bind("<Leave>", on_leave)

# Output Text Box
output_text = tk.Text(window, wrap=tk.WORD, font=("Arial", 12), height=8, bg="black", fg="#45a29e", insertbackground="#45a29e", state=tk.DISABLED, relief="solid", highlightthickness=1)
output_text.pack(padx=30, pady=10, fill="both")
output_text.bind("<FocusIn>", on_focus_in)
output_text.bind("<FocusOut>", on_focus_out)

# Footer Label
footer_label = ttk.Label(window, text="Created by Binksbrew", font=("Arial", 10, "bold"), foreground="#45a29e", background="black")
footer_label.pack(side="bottom", pady=20)

# Run GUI
window.mainloop()
