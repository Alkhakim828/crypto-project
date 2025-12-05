import os, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file_hybrid(input_path, output_path, receiver_public_key, password=None):
    file_key = os.urandom(32)
    aesgcm = AESGCM(file_key)
    nonce = os.urandom(12)
    data = open(input_path, 'rb').read()

    ciphertext = aesgcm.encrypt(nonce, data, None)

    if password:
        salt = os.urandom(16)
        pwdkey = derive_key_from_password(password, salt)
        protected_key = bytes(a ^ b for a, b in zip(file_key, pwdkey))
        key_to_encrypt = protected_key
        extra = salt
    else:
        key_to_encrypt = file_key
        extra = b''

    encrypted_key = receiver_public_key.encrypt(
        key_to_encrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_path, 'wb') as f:
        f.write(struct.pack('>I', len(encrypted_key)))
        f.write(encrypted_key)
        f.write(b'\x01' if password else b'\x00')
        if password:
            f.write(extra)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file_hybrid(input_path, output_path, receiver_private_key, password=None):
    import struct

    with open(input_path, 'rb') as f:
        raw = f.read()

    idx = 0
    (len_enc_key,) = struct.unpack('>I', raw[idx:idx + 4]); idx += 4
    enc_key = raw[idx:idx + len_enc_key]; idx += len_enc_key

    pw_flag = raw[idx]; idx += 1
    salt = b''

    if pw_flag == 1:
        salt = raw[idx:idx + 16]; idx += 16

    nonce = raw[idx:idx + 12]; idx += 12
    ciphertext = raw[idx:]

    key = receiver_private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if pw_flag == 1:
        pwdkey = derive_key_from_password(password, salt)
        file_key = bytes(a ^ b for a, b in zip(key, pwdkey))
    else:
        file_key = key

    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, 'wb') as f:
        f.write(plaintext)
