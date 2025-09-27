from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .logger import LoggerManager
from .params import Config


class HybridCrypto:
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None
    _fernet_cipher: Optional[Fernet] = None

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def symmetric_encrypt(cls, data: bytes | str) -> bytes:
        if cls._fernet_cipher is None:
            if Config.FP_PROXY_SERVER_FERNET_KEY is None:
                raise Exception("Internal Error")
            cls._fernet_cipher = Fernet(Config.FP_PROXY_SERVER_FERNET_KEY)
        if isinstance(data, str):
            data = data.encode()
        return cls._fernet_cipher.encrypt(data)

    @classmethod
    def symmetric_decrypt(cls, token: bytes | str) -> bytes:
        if cls._fernet_cipher is None:
            if Config.FP_PROXY_SERVER_FERNET_KEY is None:
                raise Exception("Internal Error")
            cls._fernet_cipher = Fernet(Config.FP_PROXY_SERVER_FERNET_KEY)
        return cls._fernet_cipher.decrypt(token)

    @classmethod
    def asymmetric_public_key(cls) -> Optional[str]:
        return cls._public_key

    @classmethod
    def asymmetric_decrypt(cls, msg_bytes: bytes) -> Optional[str]:
        if cls._private_key is None:
            return None
        try:
            message_decrypted: bytes = cls._private_key.decrypt(
                msg_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return message_decrypted.decode("utf-8")
        except Exception:
            LoggerManager.error("Decrypt failed")
            return None

    @classmethod
    def load(cls) -> bool:
        key_file_path = Path.cwd() / "key.pem"
        public_file_path = Path.cwd() / "public.pem"

        if not key_file_path.exists() or not public_file_path.exists():
            LoggerManager.error("Key files not found")
            return False

        if not Config.FP_PROXY_SERVER_KEYPAIR_PWD:
            LoggerManager.error("Keys password is invalid")
            return False

        try:
            private_pem_bytes = key_file_path.read_bytes()
            public_pem_bytes = public_file_path.read_bytes()
            password = Config.FP_PROXY_SERVER_KEYPAIR_PWD.encode("ascii")

            private_key = serialization.load_pem_private_key(
                private_pem_bytes, password=password
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError("Expected RSAPrivateKey")

            cls._private_key = private_key
            cls._public_key = public_pem_bytes.decode("utf-8")
            LoggerManager.info("Keys Correctly Loaded")
            return True

        except Exception:
            LoggerManager.error("Key loading failed")
            return False

    @classmethod
    def unload(cls):
        cls._private_key = None
        cls._public_key = None
