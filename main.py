import gzip
import os
import base64
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_data(data, password):
  # generate a salt
  salt = os.urandom(16)
  # generate a key using PBKDF2
  print('Generating key using PBKDF2...')
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
  )
  key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
  print('Key generated:', key)
  # encrypt the data with the key
  print('Encrypting data with key...')
  f = Fernet(key)
  encrypted_data = f.encrypt(data)
  print('Data encrypted.')
  return salt + encrypted_data

def decrypt_data(encrypted_data, password):
  # extract the salt from the encrypted data
  salt = encrypted_data[:16]
  # generate a key using PBKDF2
  print('Generating key using PBKDF2...')
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
  )
  key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
  print('Key generated:', key)
  # decrypt the data with the key
  print('Decrypting data with key...')
  f = Fernet(key)
  data = f.decrypt(encrypted_data[16:])
  print('Data decrypted.')
  return data

def compress_gzip(path, password):
  # walk through all the files in the given path
  print('Walking through all files in given path...')
  for root, dirs, files in os.walk(path):
    for file in files:
      # get the full path of the file
      file_path = os.path.join(root, file)
      print('Processing file:', file_path)
      # open the file in read-binary mode
      with open(file_path, 'rb') as f_in:
        # read the contents of the file
        data = f_in.read()
        # encrypt the data
        encrypted_data = encrypt_data(data, password)
        # create a gzip object with mode 'wb' and compresssion level 9
        with gzip.GzipFile(file_path + '.gz', 'wb', compresslevel=9) as f_out:
          # write the encrypted data to the gzip object
          f_out.write(encrypted_data)
      # remove the original file
      print('Removing original file...')
      os.remove(file_path)

def decompress_gzip(path, password):
  # walk through all the files in the given path
  print('Walking through all files in given path...')
  for root, dirs, files in os.walk(path):
    for file in files:
      if file.endswith('.gz'):
        # get the full path of the file
        file_path = os.path.join(root, file)
        print('Processing file:', file_path)
        # open the file in read-binary mode
        with gzip.open(file_path, 'rb') as f_in:
          # read the contents of the gzip file
          encrypted_data = f_in.read()
          # decrypt the data
          data = decrypt_data(encrypted_data, password)
          # open the original file in write-binary mode
          with open(file_path[:-3], 'wb') as f_out:
            # write the decrypted data to the original file
            f_out.write(data)
        # remove the gzip file
        print('Removing gzip file...')
        os.remove(file_path)

def main():
  # create the parser
  parser = argparse.ArgumentParser()
  # add the commands
  parser.add_argument('--compress', '-c', action='store_true', help='compress the specified path')
  parser.add_argument('--decompress', '-d', action='store_true', help='decompress the specified path')
  parser.add_argument('--path', '-p', type=str, required=True, help='the path to work with')
  parser.add_argument('--password', '-ps', type=str, required=True, help='the password to use for encryption or decryption')
  # parse the arguments
  args = parser.parse_args()
  # check if a command was specified
  if not (args.compress or args.decompress):
    print('Error: a command must be specified. Use the -h flag to see the available commands.')
    return
  # compress or decompress
  if args.compress:
    compress_gzip(args.path, args.password)
  if args.decompress:
    decompress_gzip(args.path, args.password)

if __name__ == '__main__':
  main()

