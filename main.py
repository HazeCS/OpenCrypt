import tarfile
import os
import base64
import argparse
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_data(data, password):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    f = Fernet(key)
    encrypted_data = f.encrypt(data)

    return (salt + encrypted_data).hex()

def decrypt_data(encrypted_data, password):
    encrypted_data = bytes.fromhex(encrypted_data)
    salt = encrypted_data[:16]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    f = Fernet(key)
    data = f.decrypt(encrypted_data[16:])

    return data.decode()

def compress(folder_name):
    # Iterate through all the files in the directory
    for root, dirs, files in os.walk(folder_name):
        for filename in files:
            # Get the full path of the file
            file_path = os.path.join(root, filename)
            
            try:
                # Read the file
                read_file = open(file_path, 'r')
                data = read_file.read().encode()
                read_file.close()

                # Open the file to encrypt
                with open(file_path, 'w') as f:
                    # Encrypt the file
                    f.write(encrypt_data(data, 'secret'))
            except:
                print(f"Failed to encrypt {file_path}")
    
    # Create a TarFile object
    tar = tarfile.open(f"{folder_name}.tar.gz", "w:gz", compresslevel=9)
    
    # Add the folder to the TarFile object
    tar.add(folder_name, arcname=os.path.basename(folder_name))
    
    # Close the TarFile object
    tar.close()
    
    # Remove target folder
    shutil.rmtree(folder_name, ignore_errors=True)
    
    print(f"Successfully compressed {folder_name} to {folder_name}.tar.gz")

def decompress(file_name):
    # Create a TarFile object
    tar = tarfile.open(file_name, "r:gz")
    
    # Extract the contents of the TarFile object
    tar.extractall()
    
    # Close the TarFile object
    tar.close()
    
    # Iterate through all the files in the directory (including subdirectories)
    for root, dirs, files in os.walk(file_name.replace(".tar.gz", "")):
        for filename in files:
            # Get the full path of the file
            file_path = os.path.join(root, filename)

            try:
                # Read the file
                read_file = open(file_path, 'r')
                data = read_file.read()
                read_file.close()

                # Open the file to decrypt
                with open(file_path, 'w') as f:
                    # Decrypt the file
                    f.write(decrypt_data(data, 'secret'))
            
            except:
                print(f"Failed to decrypt {file_path}")
    
    # Remove target archive
    os.remove(file_name)
    
    print(f"Successfully decompressed {file_name}")

if __name__ == "__main__":
    # Prompt the user for the desired option (compress or decompress)
    option = input("Enter 'c' to compress or 'd' to decompress: ")
    
    # Prompt the user for the name of the folder to process
    folder_name = input("Enter the name of the folder to process: ")
    password = input("Enter the password: ")

    if option == 'c':
        compress(folder_name)
    elif option == 'd':
        decompress(folder_name)
    else:
        print("Invalid option")
