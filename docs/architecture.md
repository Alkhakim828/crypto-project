# Architecture

Components:
- CLI entrypoint: main.py
- src/crypto: crypto modules (RSA, AES hybrid, signing)
- keys/: stores generated RSA keys (private.pem, public.pem)
- docs/: architecture and security notes

Flow:
- Encryption: generate ephemeral AES-256 file key -> encrypt file with AES-GCM -> encrypt file key with receiver's RSA public key -> write combined file
- Decryption: RSA-decrypt file key -> if password protection used, derive password key and recover file key -> decrypt AES-GCM ciphertext
