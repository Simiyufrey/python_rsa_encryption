from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding





def generate_rsa_key_pair():
    private_key= rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent
        key_size=2048,  # Key size in bits
    )

    public_key = private_key.public_key()


    # Save the private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("RSA key pair generated and saved.")

def load_rsa_public_key(file_path):
    with open(file_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    return public_key

def encrypt_with_rsa(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted.bin", "wb") as f:
        f.write(ciphertext)

    print("Data encrypted.")
    return ciphertext

def load_private_key(filepath):

    with open(filepath, "rb") as f:

        private_key = serialization.load_pem_private_key(f.read(), password= None)
        return private_key
    
def load_encrypted_message(file_path):
    with open(file_path, "rb") as f:
        ciphertext = f.read()

    return ciphertext


def decrypt(private_key, encrypted_message):

    plaintext = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )

    print(f"The Decryption Completed\n \n {plaintext.decode()}")


if __name__ == "__main__":

    #generate_rsa_key_pair()
    message = input("Enter  the message to encrypt: ").encode('utf-8')
    
    ciphertext = encrypt_with_rsa(load_rsa_public_key("public_key.pem"), message)

    print("Encrypted message:", ciphertext.hex())


    decrypt(load_private_key("private_key.pem"), load_encrypted_message("encrypted.bin"))