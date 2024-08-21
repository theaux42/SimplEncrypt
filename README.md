# SimplEncrypt

SimplEncrypt is a Python script that provides a simple interface for encrypting and decrypting files. It uses military-grade AES (Advanced Encryption Standard) encryption with a key derived from your password using PBKDF2 (Password-Based Key Derivation Function 2) and a random salt. This combination ensures a high level of security for your files.

## How it Works

When you choose to encrypt a file, SimplEncrypt will:

1. Ask for a password, which will be used to generate a unique encryption key.
2. Generate a random salt and use it along with your password to create a 256-bit encryption key using PBKDF2.
3. Use the AES cipher in CBC mode to encrypt your file.
4. Save the encrypted file with a prefix of "enc_" added to the original filename.

When you choose to decrypt a file, SimplEncrypt will:

1. Ask for the password that was used to encrypt the file.
2. Read the salt and IV from the encrypted file and use them along with your password to recreate the encryption key.
3. Use the AES cipher in CBC mode to decrypt your file.
4. Save the decrypted file with a prefix of "clear_" added to the original filename.

## Dependencies

SimplEncrypt uses the following Python libraries:

- `Crypto` for the AES cipher, PBKDF2, and other cryptographic functions.
- `getpass` for securely entering passwords in the console.
- `colorama` for colored console output.
- `os` and `time` for various system functions.

You can install these dependencies using pip:

```sh
pip3 install pycryptodome colorama
```

## Usage

To use SimplEncrypt, simply run the script in your console:

```sh
python3 SimplEncrypt.py
```

Then follow the prompts to encrypt or decrypt a file.
