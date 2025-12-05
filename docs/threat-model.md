# Threat Model

Threats considered:
- Passive eavesdroppers: mitigated by AES-GCM encryption.
- Active tampering: mitigated by authentication tag and RSA signatures.
- Weak passwords: mitigated by PBKDF2 if used, but users should choose strong passwords.
- Key leakage: private keys must be secured by OS-level file permissions.
