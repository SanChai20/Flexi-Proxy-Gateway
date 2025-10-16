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

        session.headers.update(
            {
                "Connection": "keep-alive",
                "Keep-Alive": "300",
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

    __slots__ = ()
    _lock = threading.RLock()
    _token_cache: Optional[bytes] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False
    _stop_thread: bool = False
    _background_thread: Optional[threading.Thread] = None

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60) -> None:
        """Start background token refresh thread."""

        def _refresher():
            consecutive_failures = 0
            max_failures = 3

            while True:
                with cls._lock:
                    if cls._stop_thread:
                        break

                time.sleep(interval)

                with cls._lock:
                    now = time.time()
                    should_refresh = (
                        cls._token_cache is None
                        or now > cls._expires_at - Config.FP_TOKEN_REFRESH_BUFFER
                    )

                if should_refresh:
                    try:
                        success = cls._rotate_token()

                        if success:
                            consecutive_failures = 0
                        else:
                            consecutive_failures += 1

                        if consecutive_failures >= max_failures:
                            LoggerManager.error(
                                f"Token refresh failed {consecutive_failures} times consecutively"
                            )

                    except Exception as e:
                        consecutive_failures += 1
                        LoggerManager.error(f"Background token refresh error: {e}")

        if cls._background_thread is None or not cls._background_thread.is_alive():
            cls._stop_thread = False
            cls._background_thread = threading.Thread(
                target=_refresher, daemon=True, name="TokenRefresher"
            )
            cls._background_thread.start()

    @classmethod
    def token(cls) -> Optional[str]:
        """Get current valid token, rotating if necessary."""

        max_attempts = 3
        attempt = 0

        while attempt < max_attempts:
            attempt += 1

            with cls._lock:
                now = time.time()

                # Return cached token if valid
                if cls._token_cache is not None and now < cls._expires_at:
                    return HybridCrypto.symmetric_decrypt(cls._token_cache).decode(
                        "utf-8"
                    )

                # Fallback for initial failure
                if not cls._initial_exchange_done and cls._initial_failed:
                    return Config.FP_APP_TOKEN_PASS

                # Wait if another thread is rotating
                if cls._rotating:
                    # Simple wait without condition variable
                    pass
                else:
                    cls._rotating = True

            if cls._rotating:
                try:
                    success = cls._rotate_token()
                    if success:
                        with cls._lock:
                            if cls._token_cache is not None:
                                return HybridCrypto.symmetric_decrypt(
                                    cls._token_cache
                                ).decode("utf-8")
                    else:
                        if not cls._initial_exchange_done:
                            cls._initial_failed = True
                            return Config.FP_APP_TOKEN_PASS

                        if attempt < max_attempts:
                            time.sleep(1)
                            continue

                        return None
                finally:
                    with cls._lock:
                        cls._rotating = False

        return None

    @classmethod
    def _rotate_token(cls) -> bool:
        """Perform actual token rotation. Returns True on success."""

        current_token = (
            HybridCrypto.symmetric_decrypt(cls._token_cache).decode("utf-8")
            if cls._token_cache is not None
            else Config.FP_APP_TOKEN_PASS
        )

        if not current_token:
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
                return False

            with cls._lock:
                cls._token_cache = HybridCrypto.symmetric_encrypt(new_token)
                cls._expires_at = (
                    time.time() + expires_in - Config.FP_TOKEN_REFRESH_BUFFER
                )
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

        if cls._background_thread and cls._background_thread.is_alive():
            cls._background_thread.join(timeout=5)
            cls._background_thread = None


def convert_sets_to_lists(obj: Any) -> Any:
    """Recursively convert sets to lists for JSON serialization."""

    if isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(v) for v in obj]
    return obj


def graceful_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT."""
    LoggerManager.info(f"Received signal {signum}, initiating graceful shutdown")

    try:
        TokenRotator.clear()
        http_client.close()
        LoggerManager.info("Graceful shutdown completed")
    except Exception as e:
        LoggerManager.error(f"Error during shutdown: {e}", exc_info=True)
    finally:
        sys.exit(0)


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

# Register signal handlers
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


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
TokenRotator.clear()
TokenRotator.background_refresh(interval=Config.FP_TOKEN_REFRESH_INTERVAL)

# Cache for API key validation
_key_cache: TimestampedLRUCache = TimestampedLRUCache(
    maxsize=Config.FP_LRU_MAX_CACHE_SIZE
)


# ============================================================================
# LiteLLM Auth Hook
# ============================================================================


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    """
    Custom authentication hook for LiteLLM - Optimized version.
    """

    if not api_key:
        raise ValueError("API key is required")
    req_id = Diag.new_req_id() if Config.FP_DIAG == 1 else 0
    total_cm: ContextManager[None] = (
        Diag.stage_timer("total", req_id) if Config.FP_DIAG == 1 else nullcontext()
    )
    with total_cm:
        # 1) cache lookup
        cache_cm: ContextManager[None] = (
            Diag.stage_timer("cache_lookup", req_id)
            if Config.FP_DIAG == 1
            else nullcontext()
        )
        with cache_cm:
            # Hash API key for cache lookup
            hashed_token = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

            # Check cache first
            cache_entry = _key_cache[hashed_token]
            if cache_entry is not None:
                ProxyRequestCounter.increment()
                return UserAPIKeyAuth(
                    metadata={
                        "fp_key": HybridCrypto.symmetric_decrypt(
                            cache_entry["enc"]
                        ).decode("utf-8"),
                        "fp_mid": cache_entry["mid"],
                        "fp_llm": cache_entry["llm"],
                    },
                    api_key=api_key,
                    user_role=LitellmUserRoles.CUSTOMER,
                )

        token_cm: ContextManager[None] = (
            Diag.stage_timer("token_get", req_id)
            if Config.FP_DIAG == 1
            else nullcontext()
        )
        with token_cm:
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

            get_cm: ContextManager[None] = (
                Diag.stage_timer("http_get", req_id)
                if Config.FP_DIAG == 1
                else nullcontext()
            )
            with get_cm:
                # Initial validation
                response = http_client.get(
                    f"{Config.FP_APP_BASE_URL}/api/auth/validate",
                    headers=headers,
                )
                response.raise_for_status()

            post_cm: ContextManager[None] = (
                Diag.stage_timer("http_post", req_id)
                if Config.FP_DIAG == 1
                else nullcontext()
            )
            with post_cm:
                # Get encrypted key
                response = http_client.post(
                    f"{Config.FP_APP_BASE_URL}/api/auth/validate",
                    headers=headers,
                    json={"public_key": HybridCrypto.asymmetric_public_key()},
                )
                response.raise_for_status()

                response_data = response.json()

            decrypt_cm: ContextManager[None] = (
                Diag.stage_timer("decrypt", req_id)
                if Config.FP_DIAG == 1
                else nullcontext()
            )
            with decrypt_cm:
                # Decrypt the key
                message_bytes = base64.b64decode(response_data["enc"])
                message_decrypted = HybridCrypto.asymmetric_decrypt(message_bytes)

                if not message_decrypted:
                    raise ValueError("Failed to decrypt API key")

                # Cache the result
                entry = {
                    "enc": HybridCrypto.symmetric_encrypt(message_decrypted).decode(
                        "utf-8"
                    ),
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

        except requests.HTTPError as e:
            status_code = e.response.status_code if e.response else "unknown"

            if status_code == 401:
                raise ValueError("Invalid API key")
            elif status_code == 403:
                raise ValueError("Access forbidden")
            else:
                LoggerManager.error(f"Authentication service error: HTTP {status_code}")
                raise RuntimeError("Authentication service error")

        except requests.RequestException as e:
            LoggerManager.error(f"API key validation request failed: {e}")
            raise RuntimeError("Authentication service unavailable")

        except (ValueError, KeyError) as e:
            LoggerManager.error(f"API key validation failed: {e}")
            raise ValueError("Invalid API key")

        except Exception as e:
            LoggerManager.error(f"Unexpected authentication error: {e}", exc_info=True)
            raise RuntimeError("Authentication failed")
