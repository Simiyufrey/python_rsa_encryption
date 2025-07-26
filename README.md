# RSA Encryption/Decryption Utility

This project provides a simple Python utility for generating RSA key pairs, encrypting messages with a public key, and decrypting them with a private key using the [cryptography](https://cryptography.io/en/latest/) library.

## Features

- Generate RSA public/private key pairs
- Encrypt messages using the RSA public key
- Decrypt messages using the RSA private key
- Save/load keys and encrypted data from files

## File Structure

- [`Rsa.py`](Rsa.py): Main script containing all functionality
- `private_key.pem`: Generated RSA private key (PEM format)
- `public_key.pem`: Generated RSA public key (PEM format)
- `encrypted.bin`: Encrypted message (binary format)

## Requirements

- Python 3.6+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies with:

```sh
pip install cryptography
```

## Usage

1. **Generate RSA Key Pair**

   Uncomment the `generate_rsa_key_pair()` line in [`Rsa.py`](Rsa.py) and run the script once to generate `private_key.pem` and `public_key.pem`.

2. **Encrypt and Decrypt a Message**

   Run the script:

   ```sh
   python Rsa.py
   ```

   - Enter the message you want to encrypt when prompted.
   - The encrypted message will be saved to `encrypted.bin`.
   - The script will then decrypt the message and display the original plaintext.

## Example

```
Enter  the message to encrypt: Hello, RSA!
Data encrypted.
Encrypted message: 6a8f...
The Decryption Completed

 Hello, RSA!
```

## Functions

- [`generate_rsa_key_pair`](Rsa.py): Generates and saves RSA key pair.
- [`load_rsa_public_key`](Rsa.py): Loads a public key from a PEM file.
- [`encrypt_with_rsa`](Rsa.py): Encrypts a message with the public key.
- [`load_private_key`](Rsa.py): Loads a private key from a PEM file.
- [`load_encrypted_message`](Rsa.py): Loads the encrypted message from a file.
- [`decrypt`](Rsa.py): Decrypts the message with the private key.

## Security Note

- The private key is saved without encryption for demonstration purposes. For production use, protect your private key with a password and proper file permissions.

## License

This project is provided for educational purposes.