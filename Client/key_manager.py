# ---------------- New file: key_manager.py ---------------- #
# This module handles RSA key pair generation and saving

from cryptography.hazmat.primitives.asymmetric import rsa  # ---------------- Generate RSA keys ---------------- #
from cryptography.hazmat.primitives import serialization    # ---------------- PEM formatting for keys ---------------- #
from cryptography.hazmat.backends import default_backend
import os


def generate_and_save_rsa_keypair(private_key_path='private_key.pem', public_key_path='public_key.pem'):
    '''
    Function to generate an RSA key pair and save them to PEM files
    '''
    # ---------------- Generate 2048-bit RSA private key ---------------- #
    private_key = rsa.generate_private_key(
        public_exponent=65537,         # Common exponent value
        key_size=2048,                 # RSA key length
        backend=default_backend()      # Use default crypto backend
    )

    public_key = private_key.public_key()  # ---------------- Extract public key ---------------- #

    # ---------------- Save private key to PEM file ---------------- #
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,                         # Save as PEM format
            format=serialization.PrivateFormat.PKCS8,                    # Use standard PKCS#8 format
            encryption_algorithm=serialization.NoEncryption()            # No encryption on private key file
        ))

    # ---------------- Save public key to PEM file ---------------- #
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,                         # Save as PEM format
            format=serialization.PublicFormat.SubjectPublicKeyInfo       # Public key format
        ))

    print(f"RSA key pair generated:\n- {private_key_path}\n- {public_key_path}")
