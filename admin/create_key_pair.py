import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

load_dotenv()


def generate_key_pair():
    key_size = 8192  # Should be at least 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Do not change
        key_size=key_size,
    )

    raw_password = os.getenv("KEYPAIR_PWD", "")
    if raw_password == "":
        print("Password is invalid.")
        return

    public_key = private_key.public_key()
    password = raw_password.encode("ascii")

    key_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # PEM Format is specified
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_pem_path = Path("key.pem")
    key_pem_path.write_bytes(key_pem_bytes)
    public_pem_path = Path("public.pem")
    public_pem_path.write_bytes(public_pem_bytes)


if __name__ == "__main__":
    """Usage:
    Visual Studio Code : [F1] -> [Tasks: Run Task] -> [Generate Key Pair]
    """
    generate_key_pair()
