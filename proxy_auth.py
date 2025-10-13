# str - bytes
import base64
import logging
import os
import sys
import threading
import time
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Literal, Optional

import requests
from cachetools import LRUCache
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from litellm import models_by_provider
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# [TODO]
load_dotenv()


class Config:
    # App
    FP_APP_TOKEN_PASS = os.getenv("FP_APP_TOKEN_PASS", None)
    FP_APP_BASE_URL = os.getenv("FP_APP_BASE_URL", None)

    # Proxy Server
    FP_PROXY_SERVER_URL = os.getenv("FP_PROXY_SERVER_URL", None)
    FP_PROXY_SERVER_ID = os.getenv("FP_PROXY_SERVER_ID", None)
    FP_PROXY_SERVER_ADVANCED = int(os.getenv("FP_PROXY_SERVER_ADVANCED", "0"))
    FP_PROXY_SERVER_KEYPAIR_PWD = os.getenv("FP_PROXY_SERVER_KEYPAIR_PWD", None)
    FP_PROXY_SERVER_KEYPAIR_DIR = os.getenv("FP_PROXY_SERVER_KEYPAIR_DIR", "..")
    FP_PROXY_SERVER_FERNET_KEY = os.getenv("FP_PROXY_SERVER_FERNET_KEY", None)

    # LRU Cache
    FP_LRU_MAX_CACHE_SIZE = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "500"))

    # Http
    FP_HTTP_MAX_POOL_CONNECTIONS_COUNT = int(
        os.getenv("FP_HTTP_MAX_POOL_CONNECTIONS_COUNT", "10")
    )
    FP_HTTP_CONNECT_TIMEOUT_LIMIT = int(os.getenv("FP_HTTP_CONNECT_TIMEOUT_LIMIT", "8"))
    FP_HTTP_READ_TIMEOUT_LIMIT = int(os.getenv("FP_HTTP_READ_TIMEOUT_LIMIT", "240"))
    FP_HTTP_MAX_RETRY_COUNT = int(os.getenv("FP_HTTP_MAX_RETRY_COUNT", "5"))
    FP_HTTP_RETRY_BACKOFF = float(os.getenv("FP_HTTP_RETRY_BACKOFF", "0.5"))
    FP_HTTP_POOL_MAX_SIZE = int(os.getenv("FP_HTTP_POOL_MAX_SIZE", "30"))


class LoggerManager:
    _logger: Optional[logging.Logger] = None
    _initialized: bool = False

    @classmethod
    def init(
        cls,
        log_file: str = "app.log",
        log_dir: str = ".",
        level: int = logging.INFO,
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 7,
    ):
        if cls._initialized:
            return
        cls._initialized = True

        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.setLevel(level)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_path = Path(log_dir) / log_file
        file_handler = TimedRotatingFileHandler(
            file_path, when=when, interval=interval, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # Dev [TODO...Remove]
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        cls._logger = logging.getLogger(__name__)

    @classmethod
    def info(cls, msg: str):
        if cls._logger:
            cls._logger.info(msg)

    @classmethod
    def warn(cls, msg: str):
        if cls._logger:
            cls._logger.warning(msg)

    @classmethod
    def error(cls, msg: str):
        if cls._logger:
            cls._logger.error(msg)

    @classmethod
    def debug(cls, msg: str):
        if cls._logger:
            cls._logger.debug(msg)


# [TODO]
class ProxyRequestCounter:
    _value: int = 0
    _lock: threading.Lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def increment(cls) -> int:
        with cls._lock:
            cls._value += 1
            return cls._value

    @classmethod
    def status(cls) -> str:
        with cls._lock:
            if cls._value < 100:
                status: Literal["unavailable", "spare", "busy", "full"] = "spare"
            elif cls._value < 500:
                status = "busy"
            else:
                status = "full"
            cls._value = 0
            return status


class TimestampedLRUCache(LRUCache[str, Any]):
    _last_used: dict[str, float] = {}

    def __init__(self, maxsize, getsizeof=None):
        super().__init__(maxsize, getsizeof)
        self._last_used = {}

    def __getitem__(self, key):
        try:
            value = super().__getitem__(key)
            self._last_used[key] = time.time()
            return value
        except Exception:
            return None

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._last_used[key] = time.time()

    def popitem(self):
        lru_key = min(self._last_used, key=lambda k: self._last_used[k])
        lru_value = super().__getitem__(lru_key)
        del self._last_used[lru_key]
        super().pop(lru_key, None)
        return lru_key, lru_value


class HTTPClient:
    """HTTP Client Wrapper, Support retry & connection pool"""

    def __init__(
        self,
    ):
        self.timeout = (
            Config.FP_HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.FP_HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = requests.Session()

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
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _request(
        self, method: str, url: str, headers: Any, json: Any
    ) -> requests.Response:
        return self.session.request(
            method, url, timeout=self.timeout, headers=headers, json=json
        )

    def post(self, url: str, headers: Any, json: Any) -> requests.Response:
        return self._request("POST", url, headers, json)

    def get(self, url: str, headers: Any) -> requests.Response:
        return self._request("GET", url, headers, None)

    def close(self):
        self.session.close()


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
        output_dir = Path(Config.FP_PROXY_SERVER_KEYPAIR_DIR).resolve()
        key_file_path = output_dir / "key.pem"
        public_file_path = output_dir / "public.pem"

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
        cls._fernet_cipher = None


class TokenRotator:
    _lock = threading.RLock()
    _condition = threading.Condition(_lock)
    _token_cache: Optional[bytes] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False
    _stop_thread: bool = False
    _background_thread: Optional[threading.Thread] = None

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60):
        def _refresher():
            while True:
                with cls._lock:
                    if cls._stop_thread:
                        LoggerManager.debug("Background refresher stopping...")
                        break
                time.sleep(interval)
                with cls._lock:
                    now = time.time()
                    should_refresh = (
                        cls._token_cache is None or now > cls._expires_at - 600
                    )

                if should_refresh:
                    try:
                        LoggerManager.debug(
                            "Background refresher: token nearing expiry, rotating..."
                        )
                        cls.token()
                    except Exception:
                        LoggerManager.error("Background token refresh failed")

        if cls._background_thread is None or not cls._background_thread.is_alive():
            cls._stop_thread = False
            t = threading.Thread(target=_refresher, daemon=True)
            cls._background_thread = t
            t.start()

    @classmethod
    def token(cls) -> Optional[str]:
        current_token: Optional[str] = None
        was_using_cache: bool = False
        is_initial: bool = False

        while True:
            with cls._lock:
                now = time.time()

                # Check if we have a valid cached token
                if cls._token_cache is not None and now < cls._expires_at:
                    return HybridCrypto.symmetric_decrypt(cls._token_cache).decode()

                # Early fallback for initial failure
                if not cls._initial_exchange_done and cls._initial_failed:
                    LoggerManager.warn(
                        "Initial token exchange failed previously; falling back to env token"
                    )
                    return Config.FP_APP_TOKEN_PASS

                # If another thread is rotating, wait for it to complete
                if cls._rotating:
                    LoggerManager.debug("Token rotation in progress; waiting...")
                    cls._condition.wait()
                    continue  # Recheck conditions after wakeup

                # No valid token; start rotation
                current_token = (
                    HybridCrypto.symmetric_decrypt(cls._token_cache).decode()
                    if cls._token_cache is not None
                    else Config.FP_APP_TOKEN_PASS
                )
                if current_token is None:
                    LoggerManager.error("No current token available for exchange")
                    return None

                was_using_cache = cls._token_cache is not None
                is_initial = not cls._initial_exchange_done and not was_using_cache
                cls._rotating = True
                LoggerManager.debug("Starting token rotation...")

            # Only the rotator thread reaches here (others wait)
            # Perform the HTTP exchange outside the lock to avoid blocking
            success_token: Optional[str] = None
            new_expires_at: float = 0
            try:
                response: requests.Response = http_client.post(
                    url=f"{Config.FP_APP_BASE_URL}/api/auth/exchange",
                    headers={"authorization": f"Bearer {current_token}"},
                    json={
                        "url": Config.FP_PROXY_SERVER_URL,
                        "status": ProxyRequestCounter.status(),
                        "adv": Config.FP_PROXY_SERVER_ADVANCED == 1,
                        "id": Config.FP_PROXY_SERVER_ID,
                    },
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except ValueError:
                        LoggerManager.error("Failed to parse token response JSON")
                        raise  # Treat as failure

                    new_token = data.get("token")
                    expires_in = data.get("expiresIn")

                    if new_token and expires_in is not None:
                        success_token = new_token
                        new_expires_at = (
                            time.time() + expires_in - 300
                        )  # 5-minute buffer
                        LoggerManager.info("Token rotated successfully")
                    else:
                        LoggerManager.error("Token response missing field")
                        raise  # Treat as failure
                else:
                    LoggerManager.error(f"Token rotate failed: {response.status_code}")
                    raise  # Treat as failure

            except requests.RequestException:  # Adjust exception if HTTPClient differs
                LoggerManager.error("Token rotate request failed")
            except Exception:
                LoggerManager.error("Unexpected error in token rotate")

            # Update state after exchange attempt
            with cls._lock:
                cls._rotating = False
                if success_token:
                    cls._token_cache = HybridCrypto.symmetric_encrypt(success_token)
                    cls._expires_at = new_expires_at
                    if is_initial:
                        cls._initial_exchange_done = True
                    cls._initial_failed = False
                    cls._condition.notify_all()
                    LoggerManager.debug("Token rotation completed; notified waiters")
                    return success_token  # Rotator returns the new token directly
                else:
                    # Failure handling
                    if is_initial:
                        cls._initial_failed = True
                        LoggerManager.warn(
                            "Initial token exchange failed; will fallback to env token on future calls"
                        )
                    elif was_using_cache:
                        # For non-initial failures, clear the invalid cache
                        cls._token_cache = None
                        cls._expires_at = 0
                        LoggerManager.warn(
                            "Cleared invalid cached token after rotation failure"
                        )
                    cls._condition.notify_all()
                    LoggerManager.debug("Token rotation failed; notified waiters")

    @classmethod
    def clear(cls) -> None:
        """Clear the cached token and stop the background refresher."""
        with cls._lock:
            cls._token_cache = None
            cls._expires_at = 0
            cls._stop_thread = True
            cls._condition.notify_all()
        if cls._background_thread:
            cls._background_thread.join(timeout=1)
            cls._background_thread = None
        LoggerManager.info("Token cache cleared and background refresher stopped")


def convert_sets_to_lists(obj):
    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    else:
        return obj


LoggerManager.init()
http_client = HTTPClient()
http_client.post(
    f"{Config.FP_APP_BASE_URL}/api/{Config.FP_PROXY_SERVER_ID}/registry",
    headers={"authorization": f"Bearer {Config.FP_APP_TOKEN_PASS}"},
    json={"models_by_provider": convert_sets_to_lists(models_by_provider)},
)
HybridCrypto.unload()
if not HybridCrypto.load():
    raise RuntimeError(
        "Failed to load keys. Check *key.pem, *public.pem and PROXY_SERVER_KEYPAIR_PWD."
    )

TokenRotator.clear()
TokenRotator.background_refresh(60)

# str - dict
_key_cache: "TimestampedLRUCache" = TimestampedLRUCache(
    maxsize=Config.FP_LRU_MAX_CACHE_SIZE
)


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    global _key_cache
    import hashlib

    if api_key is None:
        raise Exception("Internal Error")
    hashed_token = hashlib.sha256(api_key.encode()).hexdigest()
    cache_entry: Optional[dict[str, str]] = _key_cache[hashed_token]
    if cache_entry is not None:
        ProxyRequestCounter.increment()
        return UserAPIKeyAuth(
            metadata={
                "fp_key": HybridCrypto.symmetric_decrypt(cache_entry["enc"]).decode(),
                "fp_mid": cache_entry["mid"],
                "fp_llm": cache_entry["llm"],
            },
            api_key=api_key,
            user_role=LitellmUserRoles.CUSTOMER,
        )

    app_token = TokenRotator.token()
    if app_token is None:
        raise Exception("Internal Error")
    try:
        response = http_client.get(
            f"{Config.FP_APP_BASE_URL}/api/auth/validate",
            headers={
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
            },
        )
        response.raise_for_status()
        response = http_client.post(
            f"{Config.FP_APP_BASE_URL}/api/auth/validate",
            headers={
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
            },
            json={"public_key": HybridCrypto.asymmetric_public_key()},
        )
        response.raise_for_status()
    except requests.RequestException:
        raise Exception("Internal Error")

    try:
        response_data = response.json()
        message_bytes = base64.b64decode(response_data["enc"])
        message_decrypted: Optional[str] = HybridCrypto.asymmetric_decrypt(
            message_bytes
        )
        if message_decrypted is None:
            raise Exception("Internal Error")

        entry = {
            "enc": HybridCrypto.symmetric_encrypt(message_decrypted).decode(),
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
    except ValueError:
        raise Exception("Internal Error")
    except KeyError:
        raise Exception("Internal Error")
    except Exception:
        raise Exception
