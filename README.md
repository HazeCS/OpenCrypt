# USB-Crypt

- A command line utility to compress and encrypts or decompress and decrypts a directory using GZip and encryption.
- USB-Crypt uses the up-to-date fernet encryption featuring AES encryption algorithim.

Installation
```
git clone https://github.com/KiwiTG/USB-Crypt.git
cd USB-Crypt
```

REQUIREMENTS
```
pip install gzip
pip install cryptography
pip install argparse
```

Usage
- To compress and encrypt a hard drive/usb stick load the script onto the drive and use `.` as the path

`python/3 main.py [-h] [--compress | --decompress] --path PATH --password PASSWORD`

Options

`--compress or -c: Compress the specified path.`
`--decompress or -d: Decompress the specified path.`
`--path or -p: The path to work with. Required.`
`--password or -ps: The password to use for encryption or decryption. Required.`

Note
- This utility will walk through all files in the specified directory and its subdirectories. Make sure you have the necessary permissions to access and modify these files.

Disclaimer:

By using this program, you acknowledge and agree that:

    This program is provided "as is" without any warranties of any kind, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

    You use this program at your own risk and you are solely responsible for any damage to your computer system or loss of data that may result from its use.

    The author of this program shall not be held responsible for any damages or losses resulting from the use of this program.

    This program is intended for educational and informational purposes only. It is not intended to be used for any illegal or malicious activities. If you use this program for any illegal or malicious purposes, you do so at your own risk and the author of this program shall not be held responsible for any consequences resulting from your actions.

    You are solely responsible for ensuring that you have the right to encrypt or decrypt any data that you use with this program. The author of this program shall not be held responsible for any legal issues that may arise from your use of this program.

    You are solely responsible for remembering and keeping your password secure. The author of this program shall not be held responsible for any loss of data or inability to access encrypted data due to your loss or forgetting of your password.

    You agree to indemnify and hold the author of this program harmless from any claims, damages, losses, or expenses that may arise from your use of this program.
