# proxy_auth.py
import base64
import hashlib
import logging
import os
import sys
import threading
import time
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Tuple

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

load_dotenv()


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
    FP_TOKEN_REFRESH_BUFFER: int = int(os.getenv("FP_TOKEN_REFRESH_BUFFER", "1500"))


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

            # Dev console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

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
    """Optimized token rotation with background refresh."""

    def __init__(
        self,
        base_url: str,
        initial_token: str,
        refresh_buffer: int = 300,
        check_interval: int = 60,
    ):
        """
        :param base_url: API base URL
        :param initial_token: Initial token
        :param refresh_buffer: Refresh token N seconds before expiry
        :param check_interval: Background check interval in seconds
        """
        self._base_url = base_url
        self._initial_token = initial_token
        self._refresh_buffer = refresh_buffer
        self._check_interval = check_interval

        # Token state
        self._token: Optional[str] = None
        self._expires_at: float = 0

        # Thread safety
        self._lock = threading.RLock()
        self._refresh_event = threading.Event()

        # Background thread
        self._background_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()

        # Statistics
        self._consecutive_failures = 0
        self._max_failures = 3

    def start(self) -> None:
        """Start background refresh thread."""
        if self._background_thread and self._background_thread.is_alive():
            return

        self._stop_flag.clear()
        self._background_thread = threading.Thread(
            target=self._background_refresh_loop,
            daemon=True,
            name="TokenRefresher",
        )
        self._background_thread.start()
        LoggerManager.info("Token rotator background thread started")

    def stop(self) -> None:
        """Stop background thread and clear cache."""
        self._stop_flag.set()

        if self._background_thread and self._background_thread.is_alive():
            self._background_thread.join(timeout=5)

        with self._lock:
            self._token = None
            self._expires_at = 0

        LoggerManager.info("Token rotator stopped")

    def get_token(self) -> Optional[str]:
        """Get current valid token, refresh if necessary."""
        with self._lock:
            # Return cached token if still valid
            if self._token and time.time() < self._expires_at:
                return self._token

            # Use initial token if no valid token exists
            if not self._token:
                return self._initial_token

        # Token expired, trigger refresh
        if self._refresh_token_with_retry():
            with self._lock:
                return self._token

        # Fallback to initial token if refresh failed
        LoggerManager.warn("Using fallback initial token")
        return self._initial_token

    def _background_refresh_loop(self) -> None:
        """Background thread loop for automatic token refresh."""
        while not self._stop_flag.wait(self._check_interval):
            try:
                if self._should_refresh():
                    self._refresh_token()
            except Exception as e:
                LoggerManager.error(f"Background refresh error: {e}")

    def _should_refresh(self) -> bool:
        """Check if token needs refresh."""
        with self._lock:
            if not self._token:
                return True

            time_until_expiry = self._expires_at - time.time()
            return time_until_expiry <= self._refresh_buffer

    def _refresh_token_with_retry(self, max_attempts: int = 3) -> bool:
        """Refresh token with retry logic."""
        for attempt in range(1, max_attempts + 1):
            if self._refresh_token():
                return True

            if attempt < max_attempts:
                wait_time = min(2**attempt, 10)
                LoggerManager.warn(
                    f"Token refresh attempt {attempt} failed, retrying in {wait_time}s"
                )
                time.sleep(wait_time)

        LoggerManager.error(f"Token refresh failed after {max_attempts} attempts")
        return False

    def _refresh_token(self) -> bool:
        """Perform actual token rotation. Thread-safe."""
        with self._lock:
            # Get current token for exchange
            current_token = self._token if self._token else self._initial_token

            if not current_token:
                LoggerManager.error("No token available for rotation")
                return False

        try:
            # Perform rotation request (outside lock to avoid blocking)
            response = http_client.post(
                url=f"{self._base_url}/api/auth/exchange",
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
                    f"Token rotation failed: HTTP {response.status_code}, "
                    f"Response: {response.text[:200]}"
                )
                self._consecutive_failures += 1
                return False

            data = response.json()
            new_token = data.get("token")
            expires_in = data.get("expiresIn")

            if not new_token or expires_in is None:
                LoggerManager.error(f"Invalid token response: {data}")
                self._consecutive_failures += 1
                return False

            # Update token cache
            with self._lock:
                self._token = new_token
                self._expires_at = time.time() + expires_in - self._refresh_buffer
                self._consecutive_failures = 0

            LoggerManager.info(
                f"Token rotated successfully (expires in {expires_in}s, "
                f"next refresh at {datetime.fromtimestamp(self._expires_at).strftime('%Y-%m-%d %H:%M:%S')})"
            )

            # Check for consecutive failures
            if self._consecutive_failures >= self._max_failures:
                LoggerManager.error(
                    f"Token refresh failed {self._consecutive_failures} times consecutively"
                )

            return True

        except requests.Timeout:
            LoggerManager.error("Token rotation request timeout")
            self._consecutive_failures += 1
            return False
        except requests.RequestException as e:
            LoggerManager.error(f"Token rotation request failed: {e}")
            self._consecutive_failures += 1
            return False
        except Exception as e:
            LoggerManager.error(f"Unexpected error during token rotation: {e}")
            self._consecutive_failures += 1
            return False

    @property
    def is_healthy(self) -> bool:
        """Check if token rotator is healthy."""
        return self._consecutive_failures < self._max_failures

    def get_status(self) -> dict:
        """Get current status for monitoring."""
        with self._lock:
            time_until_expiry = max(0, self._expires_at - time.time())
            return {
                "has_token": self._token is not None,
                "expires_in_seconds": int(time_until_expiry),
                "consecutive_failures": self._consecutive_failures,
                "is_healthy": self.is_healthy,
                "background_thread_alive": (
                    self._background_thread.is_alive()
                    if self._background_thread
                    else False
                ),
            }


class EncryptedTokenRotator(TokenRotator):
    """Token rotator with encrypted storage."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._encrypted_token: Optional[bytes] = None

    @property
    def _token(self) -> Optional[str]:
        if self._encrypted_token is None:
            return None
        return HybridCrypto.symmetric_decrypt(self._encrypted_token).decode("utf-8")

    @_token.setter
    def _token(self, value: Optional[str]) -> None:
        if value is None:
            self._encrypted_token = None
        else:
            self._encrypted_token = HybridCrypto.symmetric_encrypt(value)


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
token_rotator = EncryptedTokenRotator(
    base_url=Config.FP_APP_BASE_URL,
    initial_token=Config.FP_APP_TOKEN_PASS,
    refresh_buffer=Config.FP_TOKEN_REFRESH_BUFFER,
    check_interval=300,
)

token_rotator.start()

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
    app_token = token_rotator.get_token()
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
