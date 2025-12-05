# Security Notes

- Uses AES-256-GCM providing confidentiality and integrity (authenticated encryption).
- RSA-2048 with OAEP (SHA-256) provides secure key encapsulation.
- PBKDF2-HMAC-SHA256 with 200,000 iterations is used if password protection is enabled.
- Digital signatures use RSA-PSS with SHA-256.
- Nonce length: 12 bytes for AES-GCM.
- File format includes length prefix for RSA-encrypted key, password flag and salt (if used), nonce and ciphertext.
- Do NOT hardcode private keys; protect private.pem appropriately.
