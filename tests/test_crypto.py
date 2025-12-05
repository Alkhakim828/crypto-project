from src.crypto.rsa_utils import generate_rsa_keypair
from src.crypto.manager import encrypt_file, decrypt_file
def test_encrypt_decrypt(tmp_path):
    priv = tmp_path / 'private.pem'
    pub = tmp_path / 'public.pem'
    generate_rsa_keypair(str(priv), str(pub))
    inp = tmp_path / 'in.txt'
    inp.write_text('hello test')
    out_enc = tmp_path / 'enc.bin'
    out_dec = tmp_path / 'dec.txt'
    encrypt_file(str(inp), str(out_enc), str(pub))
    decrypt_file(str(out_enc), str(out_dec), str(priv))
    assert out_dec.read_text() == 'hello test'
