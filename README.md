# Hybrid Cryptography Secure File System (HC-SFS)

A secure hybrid cryptographic system implementing **AES-256-GCM**, **RSA-OAEP**, **RSA-PSS**, digital signatures, integrity verification, password-based key protection, and an easy-to-use **Flask Web UI + CLI interface**.

The project demonstrates real-world cryptography, secure programming practices, and system integration — fully suitable for academic assessment and practical use.

---

# Features

### Hybrid Encryption (AES-256-GCM + RSA-OAEP)
- AES encrypts file contents  
- AES key wrapped using RSA-2048 OAEP  
- Integrity protection via AES-GCM tag  
- Optional password strengthening (PBKDF2)

### Secure Decryption
- RSA private key unwraps AES key  
- AES-GCM verifies authenticity  
- Detects wrong password / tampering  

### Digital Signatures (RSA-PSS)
- Produces `.sig` signature file  
- Ensures authenticity & integrity  

### Signature Verification
- Confirms whether file matches signature  
- Detects modification instantly  

### Web Interface (Flask)
- Upload files  
- Encrypt, decrypt, sign, verify  
- Error messages displayed in UI  
- Secure handling of temporary files  

### CLI Interface
```
python main.py encrypt <input> <output> --receiver-pub keys/public.pem
python main.py decrypt <input> <output> --private keys/private.pem
python main.py sign <input> <sig> --private keys/private.pem
python main.py verify <input> <sig> --public keys/public.pem
```

---

# Cryptographic Architecture

### AES-256-GCM  
Used for file encryption + integrity tag.

### RSA-2048 OAEP  
Securely encrypts the AES key (Key Encapsulation Mechanism).

### RSA-PSS Signature  
Provides strong authenticity and integrity guarantees.

### PBKDF2-HMAC-SHA256  
Strengthens user passwords (optional).

### UUID + Secure Temp Storage  
Ensures safe file handling in the web version.

---

#  Installation

### 1️ Install Python 3.10–3.12  
https://www.python.org/downloads/  
Make sure to check **Add Python to PATH**.

### 2️ Install dependencies

```
pip install -r requirements.txt
```

### 3️ Generate keys (required before use)

```
python main.py generate-keys
```

---

# Running the Web App

```
python web/app.py
```

Then open:

```
http://localhost:5000
```

---

# Running the CLI

### Encrypt
```
python main.py encrypt input.txt secret.bin --receiver-pub keys/public.pem
```

### Decrypt
```
python main.py decrypt secret.bin output.txt --private keys/private.pem
```

### Sign
```
python main.py sign input.txt input.sig --private keys/private.pem
```

### Verify
```
python main.py verify input.txt input.sig --public keys/public.pem
```

---

# Security Practices Used

- AES-256-GCM (AEAD authenticated encryption)  
- RSA-2048 OAEP for key encapsulation  
- RSA-PSS for signatures  
- PBKDF2-HMAC-SHA256  
- No private keys stored in repository  
- Secure temp file handling  
- Proper exception handling  
- Separation of roles (public/private keys)  
- No plaintext keys or sensitive data stored