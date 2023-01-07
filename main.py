import gzip
import os
import base64
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_data(data, password):
    salt = os.urandom(16)

    print('Generating key using PBKDF2...')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    print('Key generated.')
    print('Encrypting data with key...')

    f = Fernet(key)
    encrypted_data = f.encrypt(data)

    print('Data encrypted.')

    return salt + encrypted_data

def decrypt_data(encrypted_data, password):
    salt = encrypted_data[:16]

    print('Generating key using PBKDF2...')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    print('Key generated.')
    print('Decrypting data with key...')

    f = Fernet(key)
    data = f.decrypt(encrypted_data[16:])

    print('Data decrypted.')

    return data

def compress_gzip(path, password):
    print('Walking through all files in given path...')

    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)

            print('Processing file:', file_path)

            with open(file_path, 'rb') as f_in:
                data = f_in.read()
                encrypted_data = encrypt_data(data, password)

                with gzip.GzipFile(file_path + '.gz', 'wb', compresslevel=9) as f_out:
                    f_out.write(encrypted_data)

            print('Removing original file...')

            os.remove(file_path)

def decompress_gzip(path, password):
    print('Walking through all files in given path...')

    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.gz'):
                file_path = os.path.join(root, file)

                print('Processing file:', file_path)

                with gzip.open(file_path, 'rb') as f_in:
                    encrypted_data = f_in.read()
                    data = decrypt_data(encrypted_data, password)

                    with open(file_path[:-3], 'wb') as f_out:
                        f_out.write(data)

                print('Removing gzip file...')

                os.remove(file_path)

parser = argparse.ArgumentParser()
parser.add_argument('--compress', '-c', action='store_true', help='compress the specified path')
parser.add_argument('--decompress', '-d', action='store_true', help='decompress the specified path')
parser.add_argument('--path', '-p', type=str, required=True, help='the path to work with')
parser.add_argument('--password', '-ps', type=str, required=True, help='the password to use for encryption or decryption')
args = parser.parse_args()

if not (args.compress or args.decompress):
    print('Error: a command must be specified. Use the -h flag to see the available commands.')

if args.compress:
    compress_gzip(args.path, args.password)

if args.decompress:
    decompress_gzip(args.path, args.password)
