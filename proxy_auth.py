import base64
import hashlib
import logging
import os
import random
import signal
import socket
import ssl
import sys
import threading
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime
from itertools import count
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, ContextManager, Dict, Iterator, Literal, Optional, Tuple

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
    """Configuration with validation and fail-fast."""

    # App
    FP_APP_TOKEN_PASS: str = os.getenv("FP_APP_TOKEN_PASS", "")
    FP_APP_BASE_URL: str = os.getenv("FP_APP_BASE_URL", "")

    # Proxy Server
    FP_PROXY_SERVER_URL: str = os.getenv("FP_PROXY_SERVER_URL", "")
    FP_PROXY_SERVER_ID: str = os.getenv("FP_PROXY_SERVER_ID", "")
    FP_PROXY_SERVER_ADVANCED: int = int(os.getenv("FP_PROXY_SERVER_ADVANCED", "0"))
    FP_PROXY_SERVER_KEYPAIR_PWD: str = os.getenv("FP_PROXY_SERVER_KEYPAIR_PWD", "")
    FP_PROXY_SERVER_KEYPAIR_DIR: str = os.getenv("FP_PROXY_SERVER_KEYPAIR_DIR", "..")
    FP_PROXY_SERVER_FERNET_KEY: str = os.getenv("FP_PROXY_SERVER_FERNET_KEY", "")

    # LRU Cache
    FP_LRU_MAX_CACHE_SIZE: int = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "1000"))

    # HTTP - Production-optimized defaults
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

    # Token Rotation
    FP_TOKEN_REFRESH_INTERVAL: int = int(os.getenv("FP_TOKEN_REFRESH_INTERVAL", "300"))
    FP_TOKEN_REFRESH_BUFFER: int = int(os.getenv("FP_TOKEN_REFRESH_BUFFER", "1500"))

    # Logging
    FP_LOG_LEVEL: str = os.getenv("FP_LOG_LEVEL", "WARNING")
    FP_LOG_DIR: str = os.getenv("FP_LOG_DIR", "/var/log/litellm")
    FP_LOG_FILE: str = os.getenv("FP_LOG_FILE", "proxy_auth.log")
    FP_LOG_BACKUP_COUNT: int = int(os.getenv("FP_LOG_BACKUP_COUNT", "7"))

    FP_DIAG: int = int(os.getenv("FP_DIAG", "1"))
    FP_DIAG_SLOW_MS: int = int(os.getenv("FP_DIAG_SLOW_MS", "20"))
    FP_DIAG_SAMPLE_RATE: float = float(os.getenv("FP_DIAG_SAMPLE_RATE", "1.0"))

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration on startup."""
        required_fields = [
            "FP_APP_TOKEN_PASS",
            "FP_APP_BASE_URL",
            "FP_PROXY_SERVER_URL",
            "FP_PROXY_SERVER_ID",
            "FP_PROXY_SERVER_KEYPAIR_PWD",
            "FP_PROXY_SERVER_FERNET_KEY",
        ]

        missing = [field for field in required_fields if not getattr(cls, field)]

        if missing:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing)}. "
                f"Please set these environment variables."
            )

        # Validate URLs
        if not cls.FP_APP_BASE_URL.startswith(("http://", "https://")):
            raise ValueError("FP_APP_BASE_URL must be a valid HTTP(S) URL")

        if not cls.FP_PROXY_SERVER_URL.startswith(("http://", "https://")):
            raise ValueError("FP_PROXY_SERVER_URL must be a valid HTTP(S) URL")


class LoggerManager:
    """Lightweight logger with minimal overhead."""

    _logger: Optional[logging.Logger] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def init(
        cls,
        log_file: str = "proxy_auth.log",
        log_dir: str = "./logs",
        level: str = "WARNING",
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 7,
    ) -> None:
        if cls._logger is not None:
            return

        with cls._lock:
            if cls._logger is not None:
                return

            numeric_level = getattr(logging, level.upper(), logging.WARNING)

            root_logger = logging.getLogger()
            root_logger.handlers.clear()
            root_logger.setLevel(numeric_level)

            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

            # Ensure log directory exists
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)

            # Single file handler
            file_path = log_path / log_file
            file_handler = TimedRotatingFileHandler(
                file_path,
                when=when,
                interval=interval,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            root_logger.addHandler(file_handler)

            cls._logger = logging.getLogger(__name__)
            cls._logger.info("Logger initialized")

    @classmethod
    def _ensure_logger(cls) -> logging.Logger:
        if cls._logger is None:
            cls.init(
                log_file=Config.FP_LOG_FILE,
                log_dir=Config.FP_LOG_DIR,
                level=Config.FP_LOG_LEVEL,
                backup_count=Config.FP_LOG_BACKUP_COUNT,
            )
        return cls._logger  # type: ignore

    @classmethod
    def info(cls, msg: str) -> None:
        cls._ensure_logger().info(msg)

    @classmethod
    def warn(cls, msg: str) -> None:
        cls._ensure_logger().warning(msg)

    @classmethod
    def error(cls, msg: str, exc_info: bool = False) -> None:
        cls._ensure_logger().error(msg, exc_info=exc_info)

    @classmethod
    def debug(cls, msg: str) -> None:
        cls._ensure_logger().debug(msg)


class Diag:
    _enabled = False
    _slow_ms = 100
    _sample_rate = 1.0
    _req_id_counter = count(1)

    # 保存原始函数，便于恢复
    _orig_getaddrinfo = None
    _orig_create_connection = None
    _orig_do_handshake = None

    @classmethod
    def enable(cls, slow_ms: int, sample_rate: float):
        if cls._enabled:
            return
        cls._enabled = True
        cls._slow_ms = slow_ms
        cls._sample_rate = max(0.0, min(1.0, sample_rate))
        cls._patch_network()

    @classmethod
    def _should_sample(cls) -> bool:
        if cls._sample_rate >= 1.0:
            return True
        return random.random() < cls._sample_rate

    @classmethod
    def _patch_network(cls):
        # DNS
        if cls._orig_getaddrinfo is None:  # type: ignore
            cls._orig_getaddrinfo = socket.getaddrinfo

            def timed_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                t0 = time.perf_counter()
                try:
                    return cls._orig_getaddrinfo(host, port, family, type, proto, flags)  # type: ignore
                finally:
                    dt = (time.perf_counter() - t0) * 1000.0
                    if cls._should_sample() and dt >= cls._slow_ms:
                        LoggerManager.warn(f"[DIAG][DNS] host={host} dt_ms={dt:.1f}")

            socket.getaddrinfo = timed_getaddrinfo  # type: ignore

        # TCP connect
        if cls._orig_create_connection is None:  # type: ignore
            cls._orig_create_connection = socket.create_connection

            def timed_create_connection(address, timeout=None, source_address=None):
                t0 = time.perf_counter()
                try:
                    return cls._orig_create_connection(address, timeout, source_address)  # type: ignore
                finally:
                    dt = (time.perf_counter() - t0) * 1000.0
                    if cls._should_sample() and dt >= cls._slow_ms:
                        LoggerManager.warn(
                            f"[DIAG][TCP_CONNECT] addr={address} dt_ms={dt:.1f}"
                        )

            socket.create_connection = timed_create_connection  # type: ignore

        # TLS handshake
        if cls._orig_do_handshake is None and hasattr(ssl, "SSLSocket"):
            cls._orig_do_handshake = ssl.SSLSocket.do_handshake

            def timed_do_handshake(self, *args, **kwargs):
                t0 = time.perf_counter()
                try:
                    return Diag._orig_do_handshake(self, *args, **kwargs)  # type: ignore
                finally:
                    dt = (time.perf_counter() - t0) * 1000.0
                    if Diag._should_sample() and dt >= Diag._slow_ms:
                        peer = None
                        try:
                            peer = self.getpeername()  # type: ignore
                        except Exception:
                            pass
                        LoggerManager.warn(
                            f"[DIAG][TLS_HANDSHAKE] peer={peer} dt_ms={dt:.1f}"
                        )

            ssl.SSLSocket.do_handshake = timed_do_handshake  # type: ignore

    @classmethod
    @contextmanager
    def stage_timer(cls, title: str, req_id: int) -> Iterator[None]:
        t0 = time.perf_counter()
        try:
            yield
        finally:
            dt = (time.perf_counter() - t0) * 1000.0
            if Diag._should_sample() and dt >= Diag._slow_ms:
                LoggerManager.warn(f"[DIAG][STAGE] req={req_id} {title} dt_ms={dt:.1f}")

    @classmethod
    def new_req_id(cls) -> int:
        return next(cls._req_id_counter)


class ProxyRequestCounter:
    """Thread-safe request counter."""

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
    """LRU Cache with timestamp tracking - simplified version."""

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
    """Optimized HTTP client with connection pooling."""

    __slots__ = ("timeout", "session")

    def __init__(self):
        self.timeout: Tuple[int, int] = (
            Config.FP_HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.FP_HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=Config.FP_HTTP_MAX_RETRY_COUNT,
                backoff_factor=Config.FP_HTTP_RETRY_BACKOFF,
                status_forcelist=[502, 503, 504],
                allowed_methods=["POST", "GET"],
                raise_on_status=False,
            ),
            pool_connections=Config.FP_HTTP_MAX_POOL_CONNECTIONS_COUNT,
            pool_maxsize=Config.FP_HTTP_POOL_MAX_SIZE,
            pool_block=False,
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update(
            {
                "Connection": "keep-alive",
                "Keep-Alive": "timeout=300, max=1000",
                "User-Agent": f"LiteLLM-Proxy/{Config.FP_PROXY_SERVER_ID}",
            }
        )

        return session

    def post(self, url: str, headers: Dict[str, str], json: Any) -> requests.Response:
        return self.session.post(url, timeout=self.timeout, headers=headers, json=json)

    def get(self, url: str, headers: Dict[str, str]) -> requests.Response:
        return self.session.get(url, timeout=self.timeout, headers=headers)

    def close(self) -> None:
        self.session.close()


class HybridCrypto:
    """Crypto operations with minimal overhead."""

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
                    if not Config.FP_PROXY_SERVER_FERNET_KEY:
                        raise ValueError("FERNET_KEY not configured")

                    key = Config.FP_PROXY_SERVER_FERNET_KEY
                    if isinstance(key, str):
                        key = key.encode("utf-8")

                    cls._fernet_cipher = Fernet(key)
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
            LoggerManager.error(f"Asymmetric decryption failed: {e}")
            return None

    @classmethod
    def load(cls) -> bool:
        output_dir = Path(Config.FP_PROXY_SERVER_KEYPAIR_DIR).resolve()
        key_file_path = output_dir / "key.pem"
        public_file_path = output_dir / "public.pem"

        if not key_file_path.exists():
            LoggerManager.error(f"Private key file not found: {key_file_path}")
            return False

        if not public_file_path.exists():
            LoggerManager.error(f"Public key file not found: {public_file_path}")
            return False

        if not Config.FP_PROXY_SERVER_KEYPAIR_PWD:
            LoggerManager.error("Key password not configured")
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
            LoggerManager.info("Cryptographic keys loaded successfully")
            return True

        except Exception as e:
            LoggerManager.error(f"Failed to load keys: {e}", exc_info=True)
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

# Validate configuration first
try:
    Config.validate()
except ValueError as e:
    print(f"Configuration error: {e}", file=sys.stderr)
    sys.exit(1)

# Initialize logger
LoggerManager.init(
    log_file=Config.FP_LOG_FILE,
    log_dir=Config.FP_LOG_DIR,
    level=Config.FP_LOG_LEVEL,
    backup_count=Config.FP_LOG_BACKUP_COUNT,
)

LoggerManager.info("=== Proxy Auth Module Initializing ===")
LoggerManager.info(f"Proxy ID: {Config.FP_PROXY_SERVER_ID}")

# Enable diagnostics if requested
if Config.FP_DIAG == 1:
    Diag.enable(slow_ms=Config.FP_DIAG_SLOW_MS, sample_rate=Config.FP_DIAG_SAMPLE_RATE)
    LoggerManager.warn(
        f"Diagnostics enabled: slow_ms={Config.FP_DIAG_SLOW_MS}, sample_rate={Config.FP_DIAG_SAMPLE_RATE}"
    )


# Initialize HTTP client
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
    LoggerManager.error(f"Failed to register proxy server: {e}", exc_info=True)

# Load crypto keys
if not HybridCrypto.load():
    LoggerManager.error("Failed to load cryptographic keys")
    sys.exit(1)

# Initialize token rotation
token_rotator = EncryptedTokenRotator(
    base_url=Config.FP_APP_BASE_URL,
    initial_token=Config.FP_APP_TOKEN_PASS,
    refresh_buffer=Config.FP_TOKEN_REFRESH_BUFFER,
    check_interval=Config.FP_TOKEN_REFRESH_INTERVAL,
)

token_rotator.start()


# Register signal handlers
def graceful_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    LoggerManager.info(f"Received signal {signum}, initiating graceful shutdown")

    try:
        token_rotator.stop()
        http_client.close()
        LoggerManager.info("Graceful shutdown completed")
    except Exception as e:
        LoggerManager.error(f"Error during shutdown: {e}", exc_info=True)
    finally:
        sys.exit(0)


signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


# Cache for API key validation
_key_cache: TimestampedLRUCache = TimestampedLRUCache(
    maxsize=Config.FP_LRU_MAX_CACHE_SIZE
)


# ============================================================================
# LiteLLM Auth Hook
# ============================================================================
_CACHE_TTL = 7200  # 2 hours


class CacheEntry:
    __slots__ = ("enc", "mid", "llm", "expires_at")

    def __init__(self, enc: bytes, mid: str, llm: str, ttl: int = 3600):
        self.enc = enc
        self.mid = mid
        self.llm = llm
        self.expires_at = time.time() + ttl

    def is_valid(self) -> bool:
        return time.time() < self.expires_at


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    """
    Custom authentication hook for LiteLLM - Optimized version.
    """

    if not api_key:
        raise ValueError("API key is required")
    req_id = Diag.new_req_id() if Config.FP_DIAG == 1 else 0
    # cache lookup
    # Hash API key for cache lookup
    hashed_token = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    # Check cache first
    cache_entry: CacheEntry | None = _key_cache[hashed_token]
    if cache_entry and cache_entry.is_valid():
        ProxyRequestCounter.increment()
        return UserAPIKeyAuth(
            metadata={
                "fp_key": HybridCrypto.symmetric_decrypt(cache_entry.enc).decode(
                    "utf-8"
                ),
                "fp_mid": cache_entry.mid,
                "fp_llm": cache_entry.llm,
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
        post_cm: ContextManager[None] = (
            Diag.stage_timer("http_post", req_id)
            if Config.FP_DIAG == 1
            else nullcontext()
        )
        with post_cm:
            response = http_client.post(
                f"{Config.FP_APP_BASE_URL}/api/auth/validate",
                headers={
                    "authorization": f"Bearer {app_token}",
                    "X-API-Key": api_key,
                },
                json={
                    "public_key": HybridCrypto.asymmetric_public_key(),
                    "validate_and_encrypt": True,
                },
            )
            response.raise_for_status()
            response_data = response.json()

        # Decrypt the key
        message_bytes = base64.b64decode(response_data["enc"])
        message_decrypted = HybridCrypto.asymmetric_decrypt(message_bytes)
        if not message_decrypted:
            raise ValueError("Failed to decrypt API key")

        # Cache the result
        entry = CacheEntry(
            enc=HybridCrypto.symmetric_encrypt(message_decrypted),
            mid=response_data["mid"],
            llm=response_data["llm"],
            ttl=_CACHE_TTL,
        )
        _key_cache[hashed_token] = entry
        ProxyRequestCounter.increment()
        return UserAPIKeyAuth(
            metadata={
                "fp_key": message_decrypted,
                "fp_mid": entry.mid,
                "fp_llm": entry.llm,
            },
            api_key=api_key,
            user_role=LitellmUserRoles.CUSTOMER,
        )
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response else 0
        if status_code == 401:
            raise ValueError("Invalid API key")
        elif status_code == 403:
            raise ValueError("Access forbidden")
        else:
            raise RuntimeError("Authentication service error")
    except Exception as e:
        LoggerManager.error(f"Auth error: {e}", exc_info=True)
        raise RuntimeError("Authentication failed")
