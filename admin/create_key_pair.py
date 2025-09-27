import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

load_dotenv()

FP_PROXY_SERVER_KEYPAIR_PWD = os.getenv("FP_PROXY_SERVER_KEYPAIR_PWD", None)
FP_PROXY_SERVER_KEYPAIR_DIR = os.getenv("FP_PROXY_SERVER_KEYPAIR_DIR", None)


def generate_key_pair():
    key_size = 2048  # Should be at least 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Do not change
        key_size=key_size,
    )

    if FP_PROXY_SERVER_KEYPAIR_PWD is None or FP_PROXY_SERVER_KEYPAIR_DIR is None:
        print("[FP_PROXY_SERVER_KEYPAIR_PWD] or [FP_PROXY_SERVER_KEYPAIR_DIR] is none.")
        return

    public_key = private_key.public_key()
    password = FP_PROXY_SERVER_KEYPAIR_PWD.encode()

    key_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # PEM Format is specified
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    output_dir = Path(FP_PROXY_SERVER_KEYPAIR_DIR).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    key_pem_path = output_dir / "key.pem"
    key_pem_path.write_bytes(key_pem_bytes)
    public_pem_path = output_dir / "public.pem"
    public_pem_path.write_bytes(public_pem_bytes)


if __name__ == "__main__":
    """Usage:
    Visual Studio Code : [F1] -> [Tasks: Run Task] -> [Generate Key Pair]
    """
    generate_key_pair()
