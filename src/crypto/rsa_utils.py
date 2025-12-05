from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(private_path='keys/private.pem', public_path='keys/public.pem', key_size=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    pub = priv.public_key()
    # write private
    with open(private_path,'wb') as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_path,'wb') as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(path):
    from cryptography.hazmat.primitives import serialization
    with open(path,'rb') as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path):
    from cryptography.hazmat.primitives import serialization
    with open(path,'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)
