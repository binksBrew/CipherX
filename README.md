
## Custom Key Encryption & Decryption
A **Python-based GUI application** for text encryption and decryption using a **custom user-defined key**. The application uses the **Fernet (AES-128 CBC with HMAC) encryption algorithm** from the **cryptography** library.

---

## **Installation & Setup**

### **1. Check Python Version**
Ensure you have Python **3.8** installed:
```sh
python3.8 --version
```

### **2. Install Dependencies**
Install `tkinter` (for GUI) and `cryptography` (for encryption):
```sh
pip install tkinter
pip install cryptography
```

### **3. Verify Installed Packages**
Run the following command to check installed dependencies:
```sh
pip freeze
```
Expected output:
```
cffi==1.17.1
cryptography==44.0.1
pybase64==1.4.0
pycparser==2.22
```

### **4. Run the Application**
Navigate to the project directory and execute:
```sh
python main.py
```

---

## **How It Works**
1. **User Inputs a Custom Encryption Key**  
   - The user provides a custom key, which is used to generate a **secure AES key**.
2. **User Enters the Text to Encrypt**  
   - Click **"Encrypt"**, and the text is encrypted using **AES-128 (Fernet)**.
   - The encrypted text is displayed in the output box.
3. **Decryption Process**  
   - Paste the **encrypted text** into the input box.
   - Enter the **same encryption key**.
   - Click **"Decrypt"**, and the original text is recovered.

---

## **Encryption Algorithm Used**
- **AES-128 in CBC Mode with HMAC Authentication**
  - Uses the **Fernet encryption scheme** (from the `cryptography` library).
  - **AES-128 (Advanced Encryption Standard, 128-bit key).**
  - **CBC (Cipher Block Chaining) Mode** ensures strong encryption.
  - **HMAC (Hash-based Message Authentication Code)** provides integrity verification.
  - The encryption key is **derived from user input** using **SHA-256 hashing**.

---

## **Project Structure**
```
/Text-Encryption
│── main.py          # Main application file
│── README.md        # Project documentation
│── requirements.txt # List of dependencies (optional)
```

---

## **Features**
✅ **User-defined encryption key**  
✅ **Secure AES-128 encryption**  
✅ **GUI-based user-friendly interface**  
✅ **Black & `#45a29e` Themed UI**  
✅ **Cursor highlight and button hover effects**  
✅ **Error handling for incorrect keys**  

---

## **Screenshots**
![image](https://github.com/user-attachments/assets/1e3c83b8-77be-4b61-b3a5-fc90c97af660)

---

## **License**
This project is open-source and free to use. 🚀

