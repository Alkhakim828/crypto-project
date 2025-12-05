from .rsa_utils import generate_rsa_keypair, load_public_key, load_private_key
from .aes import encrypt_file_hybrid, decrypt_file_hybrid
from .sign import sign_bytes, verify_bytes
from pathlib import Path

def generate_keys(private_path='keys/private.pem', public_path='keys/public.pem'):
    generate_rsa_keypair(private_path, public_path)
    print(f'[OK] Generated keys: {private_path}, {public_path}')

def encrypt_file(input_file, output_file, receiver_pub='keys/public.pem', password=None):
    pub = load_public_key(receiver_pub)
    encrypt_file_hybrid(input_file, output_file, pub, password)
    print(f'[OK] Encrypted -> {output_file}')

def decrypt_file(input_file, output_file, private_path='keys/private.pem', password=None):
    priv = load_private_key(private_path)
    decrypt_file_hybrid(input_file, output_file, priv, password)
    print(f'[OK] Decrypted -> {output_file}')

def sign_file(input_file, signature_file, private_path='keys/private.pem'):
    data = Path(input_file).read_bytes()
    priv = load_private_key(private_path)
    sig = sign_bytes(data, priv)
    Path(signature_file).write_bytes(sig)
    print(f'[OK] Signature written to {signature_file}')

def verify_signature(input_file, signature_file, public_path='keys/public.pem'):
    data = Path(input_file).read_bytes()
    sig = Path(signature_file).read_bytes()
    pub = load_public_key(public_path)
    return verify_bytes(data, sig, pub)
