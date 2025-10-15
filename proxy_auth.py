# proxy_auth.py
import base64
import hashlib
import logging
import os
import threading
import time
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Tuple

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
    """Configuration with type hints and validation."""

    # App
    FP_APP_TOKEN_PASS: Optional[str] = os.getenv("FP_APP_TOKEN_PASS")
    FP_APP_BASE_URL: Optional[str] = os.getenv("FP_APP_BASE_URL")

    # Proxy Server
    FP_PROXY_SERVER_URL: Optional[str] = os.getenv("FP_PROXY_SERVER_URL")
    FP_PROXY_SERVER_ID: Optional[str] = os.getenv("FP_PROXY_SERVER_ID")
    FP_PROXY_SERVER_ADVANCED: int = int(os.getenv("FP_PROXY_SERVER_ADVANCED", "0"))
    FP_PROXY_SERVER_KEYPAIR_PWD: Optional[str] = os.getenv(
        "FP_PROXY_SERVER_KEYPAIR_PWD"
    )
    FP_PROXY_SERVER_KEYPAIR_DIR: str = os.getenv("FP_PROXY_SERVER_KEYPAIR_DIR", "..")
    FP_PROXY_SERVER_FERNET_KEY: Optional[str] = os.getenv("FP_PROXY_SERVER_FERNET_KEY")

    # LRU Cache
    FP_LRU_MAX_CACHE_SIZE: int = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "500"))

    # HTTP - Optimized defaults
    FP_HTTP_MAX_POOL_CONNECTIONS_COUNT: int = int(
        os.getenv("FP_HTTP_MAX_POOL_CONNECTIONS_COUNT", "20")
    )
    FP_HTTP_CONNECT_TIMEOUT_LIMIT: int = int(
        os.getenv("FP_HTTP_CONNECT_TIMEOUT_LIMIT", "5")
    )
    FP_HTTP_READ_TIMEOUT_LIMIT: int = int(
        os.getenv("FP_HTTP_READ_TIMEOUT_LIMIT", "240")
    )
    FP_HTTP_MAX_RETRY_COUNT: int = int(os.getenv("FP_HTTP_MAX_RETRY_COUNT", "3"))
    FP_HTTP_RETRY_BACKOFF: float = float(os.getenv("FP_HTTP_RETRY_BACKOFF", "0.3"))
    FP_HTTP_POOL_MAX_SIZE: int = int(os.getenv("FP_HTTP_POOL_MAX_SIZE", "50"))


class LoggerManager:
    """Singleton logger manager with lazy initialization."""

    _logger: Optional[logging.Logger] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def init(
        cls,
        log_file: str = "app.log",
        log_dir: str = ".",
        level: int = logging.INFO,
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 7,
    ) -> None:
        if cls._logger is not None:
            return

        with cls._lock:
            if cls._logger is not None:  # Double-check
                return

            root_logger = logging.getLogger()
            root_logger.handlers.clear()
            root_logger.setLevel(level)

            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )

            Path(log_dir).mkdir(parents=True, exist_ok=True)
            file_path = Path(log_dir) / log_file
            file_handler = TimedRotatingFileHandler(
                file_path, when=when, interval=interval, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

            cls._logger = logging.getLogger(__name__)

    @classmethod
    def _ensure_logger(cls) -> logging.Logger:
        if cls._logger is None:
            cls.init()
        return cls._logger  # type: ignore

    @classmethod
    def info(cls, msg: str) -> None:
        cls._ensure_logger().info(msg)

    @classmethod
    def warn(cls, msg: str) -> None:
        cls._ensure_logger().warning(msg)

    @classmethod
    def error(cls, msg: str) -> None:
        cls._ensure_logger().error(msg)

    @classmethod
    def debug(cls, msg: str) -> None:
        cls._ensure_logger().debug(msg)


class ProxyRequestCounter:
    """Thread-safe request counter with atomic operations."""

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
    def status(cls) -> Literal["unavailable", "spare", "busy", "full"]:
        with cls._lock:
            current = cls._value
            cls._value = 0

            if current < 100:
                return "spare"
            elif current < 500:
                return "busy"
            else:
                return "full"


class TimestampedLRUCache(LRUCache):
    """LRU Cache with timestamp tracking for better eviction."""

    __slots__ = ("_last_used",)

    def __init__(self, maxsize: int, getsizeof=None):
        super().__init__(maxsize, getsizeof)  # type: ignore
        self._last_used: Dict[str, float] = {}

    def __getitem__(self, key: str) -> Any:
        try:
            value = super().__getitem__(key)  # type: ignore
            self._last_used[key] = time.time()
            return value
        except KeyError:
            return None

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)  # type: ignore
        self._last_used[key] = time.time()

    def popitem(self) -> Tuple[str, Any]:
        if not self._last_used:
            return super().popitem()

        lru_key = min(self._last_used, key=lambda k: self._last_used[k])
        lru_value = super().__getitem__(lru_key)  # type: ignore
        del self._last_used[lru_key]
        super().__delitem__(lru_key)  # type: ignore
        return lru_key, lru_value


class HTTPClient:
    """Optimized HTTP client with connection pooling and retry logic."""

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
            pool_block=False,  # Don't block when pool is full
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Keep-alive headers
        session.headers.update({"Connection": "keep-alive", "Keep-Alive": "300"})

        return session

    def post(self, url: str, headers: Dict[str, str], json: Any) -> requests.Response:
        return self.session.post(url, timeout=self.timeout, headers=headers, json=json)

    def get(self, url: str, headers: Dict[str, str]) -> requests.Response:
        return self.session.get(url, timeout=self.timeout, headers=headers)

    def close(self) -> None:
        self.session.close()


class HybridCrypto:
    """Optimized crypto operations with caching."""

    __slots__ = ()
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None
    _fernet_cipher: Optional[Fernet] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def _get_fernet(cls) -> Fernet:
        if cls._fernet_cipher is None:
            with cls._lock:
                if cls._fernet_cipher is None:
                    if Config.FP_PROXY_SERVER_FERNET_KEY is None:
                        raise ValueError("FERNET_KEY not configured")
                    cls._fernet_cipher = Fernet(
                        Config.FP_PROXY_SERVER_FERNET_KEY.encode()
                        if isinstance(Config.FP_PROXY_SERVER_FERNET_KEY, str)
                        else Config.FP_PROXY_SERVER_FERNET_KEY
                    )
        return cls._fernet_cipher

    @classmethod
    def symmetric_encrypt(cls, data: bytes | str) -> bytes:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return cls._get_fernet().encrypt(data)

    @classmethod
    def symmetric_decrypt(cls, token: bytes | str) -> bytes:
        if isinstance(token, str):
            token = token.encode("utf-8")
        return cls._get_fernet().decrypt(token)

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
        except Exception as e:
            LoggerManager.error(f"Decrypt failed: {e}")
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
            # Read files once
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
            LoggerManager.info("Keys loaded successfully")
            return True

        except Exception as e:
            LoggerManager.error(f"Key loading failed: {e}")
            return False

    @classmethod
    def unload(cls) -> None:
        cls._private_key = None
        cls._public_key = None
        cls._fernet_cipher = None


class TokenRotator:
    """
    Optimized token rotation with background refresh.

    Key improvements:
    - Uses RLock for reentrant locking
    - Implements proper wait/notify pattern
    - Background thread for proactive rotation
    - Better error handling and fallback
    """

    __slots__ = ()
    _lock = threading.RLock()
    _condition = threading.Condition(_lock)
    _token_cache: Optional[bytes] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False
    _stop_thread: bool = False
    _background_thread: Optional[threading.Thread] = None
    _refresh_buffer: int = 300  # Refresh 5 minutes before expiry

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60) -> None:
        """Start background token refresh thread."""

        def _refresher():
            while True:
                with cls._lock:
                    if cls._stop_thread:
                        LoggerManager.debug("Background refresher stopping")
                        break

                time.sleep(interval)

                with cls._lock:
                    now = time.time()
                    should_refresh = (
                        cls._token_cache is None
                        or now > cls._expires_at - cls._refresh_buffer
                    )

                if should_refresh:
                    try:
                        LoggerManager.debug("Background refresh: rotating token")
                        cls._rotate_token()
                    except Exception as e:
                        LoggerManager.error(f"Background token refresh failed: {e}")

        if cls._background_thread is None or not cls._background_thread.is_alive():
            cls._stop_thread = False
            cls._background_thread = threading.Thread(
                target=_refresher, daemon=True, name="TokenRefresher"
            )
            cls._background_thread.start()
            LoggerManager.info("Token background refresher started")

    @classmethod
    def token(cls) -> Optional[str]:
        """Get current valid token, rotating if necessary."""

        while True:
            with cls._lock:
                now = time.time()

                # Return cached token if valid
                if cls._token_cache is not None and now < cls._expires_at:
                    return HybridCrypto.symmetric_decrypt(cls._token_cache).decode(
                        "utf-8"
                    )

                # Fallback for initial failure
                if not cls._initial_exchange_done and cls._initial_failed:
                    LoggerManager.warn("Using fallback env token after initial failure")
                    return Config.FP_APP_TOKEN_PASS

                # Wait if another thread is rotating
                if cls._rotating:
                    LoggerManager.debug("Waiting for token rotation")
                    cls._condition.wait(timeout=30)  # Prevent infinite wait
                    continue

                # Start rotation
                cls._rotating = True

            # Rotate outside lock
            try:
                success = cls._rotate_token()
                if success:
                    return cls.token()  # Recursively get the new token
                else:
                    # Rotation failed
                    if not cls._initial_exchange_done:
                        cls._initial_failed = True
                        return Config.FP_APP_TOKEN_PASS
                    return None
            finally:
                with cls._lock:
                    cls._rotating = False
                    cls._condition.notify_all()

    @classmethod
    def _rotate_token(cls) -> bool:
        """Perform actual token rotation. Returns True on success."""

        current_token = (
            HybridCrypto.symmetric_decrypt(cls._token_cache).decode("utf-8")
            if cls._token_cache is not None
            else Config.FP_APP_TOKEN_PASS
        )

        if current_token is None:
            LoggerManager.error("No current token for exchange")
            return False

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
                LoggerManager.error(
                    f"Token rotation failed: HTTP {response.status_code}"
                )
                return False

            data = response.json()
            new_token = data.get("token")
            expires_in = data.get("expiresIn")

            if not new_token or expires_in is None:
                LoggerManager.error("Invalid token response")
                return False

            with cls._lock:
                cls._token_cache = HybridCrypto.symmetric_encrypt(new_token)
                cls._expires_at = time.time() + expires_in - cls._refresh_buffer
                cls._initial_exchange_done = True
                cls._initial_failed = False

            LoggerManager.info(f"Token rotated successfully (expires in {expires_in}s)")
            return True

        except requests.RequestException as e:
            LoggerManager.error(f"Token rotation request failed: {e}")
            return False
        except Exception as e:
            LoggerManager.error(f"Token rotation failed: {e}")
            return False

    @classmethod
    def clear(cls) -> None:
        """Clear token cache and stop background thread."""

        with cls._lock:
            cls._token_cache = None
            cls._expires_at = 0
            cls._stop_thread = True
            cls._condition.notify_all()

        if cls._background_thread and cls._background_thread.is_alive():
            cls._background_thread.join(timeout=2)
            cls._background_thread = None

        LoggerManager.info("Token cache cleared and refresher stopped")


def convert_sets_to_lists(obj: Any) -> Any:
    """Recursively convert sets to lists for JSON serialization."""

    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    return obj


# ============================================================================
# Module Initialization
# ============================================================================

LoggerManager.init()
http_client = HTTPClient()

# Register proxy server
try:
    response = http_client.post(
        f"{Config.FP_APP_BASE_URL}/api/{Config.FP_PROXY_SERVER_ID}/registry",
        headers={"authorization": f"Bearer {Config.FP_APP_TOKEN_PASS}"},
        json={"models_by_provider": convert_sets_to_lists(models_by_provider)},
    )
    response.raise_for_status()
    LoggerManager.info("Proxy server registered successfully")
except Exception as e:
    LoggerManager.error(f"Failed to register proxy server: {e}")

# Load crypto keys
if not HybridCrypto.load():
    raise RuntimeError(
        "Failed to load cryptographic keys. "
        "Check key.pem, public.pem, and FP_PROXY_SERVER_KEYPAIR_PWD."
    )

# Initialize token rotation
TokenRotator.clear()
TokenRotator.background_refresh(interval=60)

# Cache for API key validation
_key_cache: TimestampedLRUCache = TimestampedLRUCache(
    maxsize=Config.FP_LRU_MAX_CACHE_SIZE
)


# ============================================================================
# LiteLLM Auth Hook
# ============================================================================


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    """
    Custom authentication hook for LiteLLM.

    Optimizations:
    - SHA-256 hashing for cache key
    - LRU cache with timestamps
    - Parallel validation requests where possible
    - Reuses HTTP connection pool
    """

    if not api_key:
        raise ValueError("API key is required")

    # Hash API key for cache lookup
    hashed_token = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    # Check cache first
    cache_entry = _key_cache[hashed_token]
    if cache_entry is not None:
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

    # Get current app token
    app_token = TokenRotator.token()
    if not app_token:
        raise RuntimeError("Failed to obtain app token")

    # Validate API key with backend
    try:
        headers = {
            "authorization": f"Bearer {app_token}",
            "X-API-Key": api_key,
        }

        # Initial validation
        response = http_client.get(
            f"{Config.FP_APP_BASE_URL}/api/auth/validate",
            headers=headers,
        )
        response.raise_for_status()

        # Get encrypted key
        response = http_client.post(
            f"{Config.FP_APP_BASE_URL}/api/auth/validate",
            headers=headers,
            json={"public_key": HybridCrypto.asymmetric_public_key()},
        )
        response.raise_for_status()

        response_data = response.json()

        # Decrypt the key
        message_bytes = base64.b64decode(response_data["enc"])
        message_decrypted = HybridCrypto.asymmetric_decrypt(message_bytes)

        if not message_decrypted:
            raise ValueError("Failed to decrypt API key")

        # Cache the result
        entry = {
            "enc": HybridCrypto.symmetric_encrypt(message_decrypted).decode("utf-8"),
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

    except requests.RequestException as e:
        LoggerManager.error(f"API key validation request failed: {e}")
        raise RuntimeError("Authentication service unavailable")
    except (ValueError, KeyError) as e:
        LoggerManager.error(f"API key validation failed: {e}")
        raise ValueError("Invalid API key")
    except Exception as e:
        LoggerManager.error(f"Unexpected authentication error: {e}")
        raise RuntimeError("Authentication failed")
