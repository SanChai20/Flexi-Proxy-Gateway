import base64
import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from cachetools import LRUCache
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from litellm import models_by_provider
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Config:
    FP_APP_TOKEN_PASS: str = os.getenv("FP_APP_TOKEN_PASS", "")
    FP_APP_BASE_URL: str = os.getenv("FP_APP_BASE_URL", "")
    FP_PROXY_SERVER_URL: str = os.getenv("FP_PROXY_SERVER_URL", "")
    FP_PROXY_SERVER_ID: str = os.getenv("FP_PROXY_SERVER_ID", "")
    FP_PROXY_SERVER_ADVANCED: int = int(os.getenv("FP_PROXY_SERVER_ADVANCED", "0"))
    FP_PROXY_SERVER_KEYPAIR_PWD: str = os.getenv("FP_PROXY_SERVER_KEYPAIR_PWD", "")
    FP_PROXY_SERVER_KEYPAIR_DIR: str = os.getenv("FP_PROXY_SERVER_KEYPAIR_DIR", "..")
    FP_PROXY_SERVER_FERNET_KEY: str = os.getenv("FP_PROXY_SERVER_FERNET_KEY", "")
    FP_LRU_MAX_CACHE_SIZE: int = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "2000"))
    FP_HTTP_MAX_POOL_CONNECTIONS_COUNT: int = int(
        os.getenv("FP_HTTP_MAX_POOL_CONNECTIONS_COUNT", "50")
    )
    FP_HTTP_CONNECT_TIMEOUT_LIMIT: int = int(
        os.getenv("FP_HTTP_CONNECT_TIMEOUT_LIMIT", "3")
    )
    FP_HTTP_READ_TIMEOUT_LIMIT: int = int(
        os.getenv("FP_HTTP_READ_TIMEOUT_LIMIT", "120")
    )
    FP_HTTP_MAX_RETRY_COUNT: int = int(os.getenv("FP_HTTP_MAX_RETRY_COUNT", "2"))
    FP_HTTP_RETRY_BACKOFF: float = float(os.getenv("FP_HTTP_RETRY_BACKOFF", "0.2"))
    FP_HTTP_POOL_MAX_SIZE: int = int(os.getenv("FP_HTTP_POOL_MAX_SIZE", "100"))
    FP_TOKEN_REFRESH_INTERVAL: int = int(os.getenv("FP_TOKEN_REFRESH_INTERVAL", "120"))
    FP_TOKEN_REFRESH_BUFFER: int = int(os.getenv("FP_TOKEN_REFRESH_BUFFER", "300"))


class ProxyRequestCounter:
    __slots__ = ()
    _value: int = 0
    _lock: threading.Lock = threading.Lock()

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def increment(cls) -> int:
        with cls._lock:
            cls._value += 1
            return cls._value

    @classmethod
    def status(cls) -> str:
        with cls._lock:
            current = cls._value
            cls._value = 0
            if current < 100:
                return "spare"
            elif current < 300:
                return "busy"
            return "full"


class HTTPClient:
    __slots__ = ("timeout", "session")

    def __init__(self):
        self.timeout: Tuple[int, int] = (
            Config.FP_HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.FP_HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=Config.FP_HTTP_MAX_RETRY_COUNT,
            backoff_factor=Config.FP_HTTP_RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=Config.FP_HTTP_MAX_POOL_CONNECTIONS_COUNT,
            pool_maxsize=Config.FP_HTTP_POOL_MAX_SIZE,
            pool_block=False,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"Connection": "keep-alive", "Keep-Alive": "300"})
        return session

    def post(self, url: str, headers: Dict[str, str], json: Any) -> requests.Response:
        return self.session.post(url, timeout=self.timeout, headers=headers, json=json)

    def get(self, url: str, headers: Dict[str, str]) -> requests.Response:
        return self.session.get(url, timeout=self.timeout, headers=headers)


class HybridCrypto:
    __slots__ = ()
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None
    _fernet_cipher: Optional[Fernet] = None

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def _get_fernet(cls) -> Fernet:
        if cls._fernet_cipher is None:
            key = Config.FP_PROXY_SERVER_FERNET_KEY
            cls._fernet_cipher = Fernet(
                key.encode("utf-8") if isinstance(key, str) else key
            )
        return cls._fernet_cipher

    @classmethod
    def symmetric_encrypt(cls, data: bytes | str) -> bytes:
        return cls._get_fernet().encrypt(
            data.encode("utf-8") if isinstance(data, str) else data
        )

    @classmethod
    def symmetric_decrypt(cls, token: bytes | str) -> bytes:
        return cls._get_fernet().decrypt(
            token.encode("utf-8") if isinstance(token, str) else token
        )

    @classmethod
    def asymmetric_public_key(cls) -> Optional[str]:
        return cls._public_key

    @classmethod
    def asymmetric_decrypt(cls, msg_bytes: bytes) -> Optional[str]:
        if cls._private_key is None:
            return None
        try:
            message_decrypted = cls._private_key.decrypt(
                msg_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return message_decrypted.decode("utf-8")
        except:
            return None

    @classmethod
    def load(cls) -> bool:
        try:
            output_dir = Path(Config.FP_PROXY_SERVER_KEYPAIR_DIR).resolve()
            private_pem_bytes = (output_dir / "key.pem").read_bytes()
            public_pem_bytes = (output_dir / "public.pem").read_bytes()
            password = Config.FP_PROXY_SERVER_KEYPAIR_PWD.encode("ascii")
            cls._private_key = serialization.load_pem_private_key(private_pem_bytes, password=password)  # type: ignore
            cls._public_key = public_pem_bytes.decode("utf-8")
            return True
        except:
            return False


class TokenRotator:
    __slots__ = ()
    _lock = threading.RLock()
    _token_cache: Optional[bytes] = None
    _expires_at: float = 0
    _initial_failed: bool = False
    _rotating: bool = False
    _stop_thread: bool = False

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60) -> None:
        def _refresher():
            while True:
                if cls._stop_thread:
                    break
                time.sleep(interval)
                now = time.time()
                if (
                    cls._token_cache is None
                    or now > cls._expires_at - Config.FP_TOKEN_REFRESH_BUFFER
                ):
                    try:
                        cls._rotate_token()
                    except:
                        pass

        threading.Thread(target=_refresher, daemon=True, name="TokenRefresher").start()

    @classmethod
    def token(cls) -> Optional[str]:
        with cls._lock:
            now = time.time()
            if cls._token_cache is not None and now < cls._expires_at:
                return HybridCrypto.symmetric_decrypt(cls._token_cache).decode("utf-8")
            if cls._initial_failed:
                return Config.FP_APP_TOKEN_PASS
            if not cls._rotating:
                cls._rotating = True
                try:
                    if cls._rotate_token():
                        return (
                            HybridCrypto.symmetric_decrypt(cls._token_cache).decode(
                                "utf-8"
                            )
                            if cls._token_cache
                            else None
                        )
                    cls._initial_failed = True
                    return Config.FP_APP_TOKEN_PASS
                finally:
                    cls._rotating = False
        return Config.FP_APP_TOKEN_PASS

    @classmethod
    def _rotate_token(cls) -> bool:
        current_token = (
            HybridCrypto.symmetric_decrypt(cls._token_cache).decode("utf-8")
            if cls._token_cache
            else Config.FP_APP_TOKEN_PASS
        )
        try:
            response = http_client.post(
                url=f"{Config.FP_APP_BASE_URL}/api/auth/exchange",
                headers={"authorization": f"Bearer {current_token}"},
                json={
                    "url": Config.FP_PROXY_SERVER_URL,
                    "status": ProxyRequestCounter.status(),
                    "adv": Config.FP_PROXY_SERVER_ADVANCED == 1,
                    "id": Config.FP_PROXY_SERVER_ID,
                },
            )
            if response.status_code != 200:
                return False
            data = response.json()
            new_token = data.get("token")
            expires_in = data.get("expiresIn")
            if not new_token or expires_in is None:
                return False
            with cls._lock:
                cls._token_cache = HybridCrypto.symmetric_encrypt(new_token)
                cls._expires_at = (
                    time.time() + expires_in - Config.FP_TOKEN_REFRESH_BUFFER
                )
                cls._initial_failed = False
            return True
        except:
            return False


# Initialize
http_client = HTTPClient()


def convert_sets_to_lists(obj: Any) -> Any:
    """Recursively convert sets to lists for JSON serialization."""

    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    return obj


try:
    http_client.post(
        f"{Config.FP_APP_BASE_URL}/api/{Config.FP_PROXY_SERVER_ID}/registry",
        headers={"authorization": f"Bearer {Config.FP_APP_TOKEN_PASS}"},
        json={"models_by_provider": convert_sets_to_lists(models_by_provider)},
    )
except:
    pass

HybridCrypto.load()
TokenRotator.background_refresh(interval=Config.FP_TOKEN_REFRESH_INTERVAL)

_key_cache: LRUCache = LRUCache(maxsize=Config.FP_LRU_MAX_CACHE_SIZE)


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    if not api_key:
        raise ValueError("API key is required")

    hashed_token = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    cache_entry = _key_cache.get(hashed_token)  # type: ignore

    if cache_entry:
        ProxyRequestCounter.increment()
        return UserAPIKeyAuth(
            metadata={
                "fp_key": HybridCrypto.symmetric_decrypt(cache_entry["enc"]).decode(
                    "utf-8"
                ),
                "fp_mid": cache_entry["mid"],
                "fp_llm": cache_entry["llm"],
            },
            api_key=api_key,
            user_role=LitellmUserRoles.CUSTOMER,
        )

    app_token = TokenRotator.token()
    if not app_token:
        raise RuntimeError("Failed to obtain app token")

    headers = {"authorization": f"Bearer {app_token}", "X-API-Key": api_key}

    response = http_client.get(
        f"{Config.FP_APP_BASE_URL}/api/auth/validate", headers=headers
    )
    response.raise_for_status()

    response = http_client.post(
        f"{Config.FP_APP_BASE_URL}/api/auth/validate",
        headers=headers,
        json={"public_key": HybridCrypto.asymmetric_public_key()},
    )
    response.raise_for_status()

    response_data = response.json()
    message_bytes = base64.b64decode(response_data["enc"])
    message_decrypted = HybridCrypto.asymmetric_decrypt(message_bytes)

    if not message_decrypted:
        raise ValueError("Failed to decrypt API key")

    entry = {
        "enc": HybridCrypto.symmetric_encrypt(message_decrypted),
        "mid": response_data["mid"],
        "llm": response_data["llm"],
    }
    _key_cache[hashed_token] = entry
    ProxyRequestCounter.increment()

    return UserAPIKeyAuth(
        metadata={
            "fp_key": message_decrypted,
            "fp_mid": entry["mid"],
            "fp_llm": entry["llm"],
        },
        api_key=api_key,
        user_role=LitellmUserRoles.CUSTOMER,
    )
