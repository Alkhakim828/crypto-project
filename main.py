import argparse
from src.crypto.manager import generate_keys, encrypt_file, decrypt_file, sign_file, verify_signature

def main():
    parser = argparse.ArgumentParser(description="Full-featured File Encryption CLI Tool")
    sub = parser.add_subparsers(dest='cmd', required=True)

    sub_gen = sub.add_parser('generate-keys', help='Generate RSA key pair')
    sub_gen.add_argument('--private', default='keys/private.pem', help='private key path')
    sub_gen.add_argument('--public', default='keys/public.pem', help='public key path')

    sub_enc = sub.add_parser('encrypt', help='Encrypt a file (hybrid: AES + RSA)')
    sub_enc.add_argument('input_file')
    sub_enc.add_argument('output_file')
    sub_enc.add_argument('--receiver-pub', default='keys/public.pem', help='receiver public key (RSA)')
    sub_enc.add_argument('--password', help='password to additionally protect AES key (optional)')

    sub_dec = sub.add_parser('decrypt', help='Decrypt previously encrypted file')
    sub_dec.add_argument('input_file')
    sub_dec.add_argument('output_file')
    sub_dec.add_argument('--private', default='keys/private.pem', help='private key path')
    sub_dec.add_argument('--password', help='password if used during encryption')

    sub_sign = sub.add_parser('sign', help='Sign a file with private RSA key')
    sub_sign.add_argument('input_file')
    sub_sign.add_argument('signature_file')
    sub_sign.add_argument('--private', default='keys/private.pem', help='private key path')

    sub_ver = sub.add_parser('verify', help='Verify file signature with public RSA key')
    sub_ver.add_argument('input_file')
    sub_ver.add_argument('signature_file')
    sub_ver.add_argument('--public', default='keys/public.pem', help='public key path')

    args = parser.parse_args()

    if args.cmd == 'generate-keys':
        generate_keys(args.private, args.public)
    elif args.cmd == 'encrypt':
        encrypt_file(args.input_file, args.output_file, args.receiver_pub, args.password)
    elif args.cmd == 'decrypt':
        decrypt_file(args.input_file, args.output_file, args.private, args.password)
    elif args.cmd == 'sign':
        sign_file(args.input_file, args.signature_file, args.private)
    elif args.cmd == 'verify':
        ok = verify_signature(args.input_file, args.signature_file, args.public)
        print('[OK] Signature valid' if ok else '[ERROR] Signature invalid')

if __name__ == '__main__':
    main()
