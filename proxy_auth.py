# proxy_auth.py - Production-Ready Version
import base64
import hashlib
import logging
import os
import signal
import sys
import threading
import time
from contextlib import contextmanager
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
    FP_HTTP_MAX_RETRY_COUNT: int = int(os.getenv("FP_HTTP_MAX_RETRY_COUNT", "3"))
    FP_HTTP_RETRY_BACKOFF: float = float(os.getenv("FP_HTTP_RETRY_BACKOFF", "0.2"))
    FP_HTTP_POOL_MAX_SIZE: int = int(os.getenv("FP_HTTP_POOL_MAX_SIZE", "100"))

    # Token Rotation
    FP_TOKEN_REFRESH_INTERVAL: int = int(os.getenv("FP_TOKEN_REFRESH_INTERVAL", "60"))
    FP_TOKEN_REFRESH_BUFFER: int = int(os.getenv("FP_TOKEN_REFRESH_BUFFER", "300"))

    # Health Check
    FP_ENABLE_HEALTH_CHECK: bool = os.getenv("FP_ENABLE_HEALTH_CHECK", "1") == "1"
    FP_HEALTH_CHECK_INTERVAL: int = int(os.getenv("FP_HEALTH_CHECK_INTERVAL", "300"))

    # Logging
    FP_LOG_LEVEL: str = os.getenv("FP_LOG_LEVEL", "INFO")
    FP_LOG_DIR: str = os.getenv("FP_LOG_DIR", "/var/log/litellm")
    FP_LOG_FILE: str = os.getenv("FP_LOG_FILE", "proxy_auth.log")
    FP_LOG_BACKUP_COUNT: int = int(os.getenv("FP_LOG_BACKUP_COUNT", "30"))

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
    """Production-ready logger with structured logging."""

    _logger: Optional[logging.Logger] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def init(
        cls,
        log_file: str = "proxy_auth.log",
        log_dir: str = "./logs",
        level: str = "INFO",
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 30,
    ) -> None:
        if cls._logger is not None:
            return

        with cls._lock:
            if cls._logger is not None:
                return

            # Map string level to logging constant
            numeric_level = getattr(logging, level.upper(), logging.INFO)

            root_logger = logging.getLogger()
            root_logger.handlers.clear()
            root_logger.setLevel(numeric_level)

            # Production formatter with more context
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

            # Ensure log directory exists
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)

            # File handler with rotation
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

            # Error-only file handler
            error_file_path = log_path / f"error_{log_file}"
            error_handler = TimedRotatingFileHandler(
                error_file_path,
                when=when,
                interval=interval,
                backupCount=backup_count,
                encoding="utf-8",
            )
            error_handler.setFormatter(formatter)
            error_handler.setLevel(logging.ERROR)
            root_logger.addHandler(error_handler)

            cls._logger = logging.getLogger(__name__)
            cls._logger.info("Logger initialized successfully")

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
    def info(cls, msg: str, **kwargs) -> None:
        cls._ensure_logger().info(msg, extra=kwargs)

    @classmethod
    def warn(cls, msg: str, **kwargs) -> None:
        cls._ensure_logger().warning(msg, extra=kwargs)

    @classmethod
    def error(cls, msg: str, exc_info: bool = False, **kwargs) -> None:
        cls._ensure_logger().error(msg, exc_info=exc_info, extra=kwargs)

    @classmethod
    def debug(cls, msg: str, **kwargs) -> None:
        cls._ensure_logger().debug(msg, extra=kwargs)


class MetricsCollector:
    """Simple metrics collector for monitoring."""

    _lock = threading.Lock()
    _metrics: Dict[str, int] = {
        "total_requests": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "auth_failures": 0,
        "token_rotations": 0,
        "token_rotation_failures": 0,
    }

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def increment(cls, metric: str, value: int = 1) -> None:
        with cls._lock:
            if metric in cls._metrics:
                cls._metrics[metric] += value

    @classmethod
    def get_metrics(cls) -> Dict[str, int]:
        with cls._lock:
            return cls._metrics.copy()

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            for key in cls._metrics:
                cls._metrics[key] = 0


class ProxyRequestCounter:
    """Thread-safe request counter with metrics integration."""

    __slots__ = ()
    _value: int = 0
    _lock: threading.Lock = threading.Lock()

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def increment(cls) -> int:
        with cls._lock:
            cls._value += 1
            MetricsCollector.increment("total_requests")
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
    """LRU Cache with timestamp tracking and TTL support."""

    __slots__ = ("_last_used", "_ttl")

    def __init__(self, maxsize: int, ttl: int = 3600, getsizeof=None):
        super().__init__(maxsize, getsizeof)  # type: ignore
        self._last_used: Dict[str, float] = {}
        self._ttl = ttl

    def __getitem__(self, key: str) -> Any:
        try:
            value = super().__getitem__(key)  # type: ignore

            # Check TTL
            if key in self._last_used:
                if time.time() - self._last_used[key] > self._ttl:
                    # Entry expired
                    del self._last_used[key]
                    super().__delitem__(key)  # type: ignore
                    return None

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

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        now = time.time()
        expired_keys = [
            key
            for key, timestamp in self._last_used.items()
            if now - timestamp > self._ttl
        ]

        for key in expired_keys:
            try:
                del self._last_used[key]
                super().__delitem__(key)  # type: ignore
            except KeyError:
                pass

        return len(expired_keys)


class HTTPClient:
    """Production-ready HTTP client with circuit breaker pattern."""

    __slots__ = ("timeout", "session", "_failure_count", "_last_failure", "_lock")

    # Circuit breaker thresholds
    MAX_FAILURES = 5
    FAILURE_WINDOW = 60  # seconds
    CIRCUIT_OPEN_TIME = 30  # seconds

    def __init__(self):
        self.timeout: Tuple[int, int] = (
            Config.FP_HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.FP_HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = self._create_session()
        self._failure_count = 0
        self._last_failure = 0.0
        self._lock = threading.Lock()

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

        # Production headers
        session.headers.update(
            {
                "Connection": "keep-alive",
                "Keep-Alive": "300",
                "User-Agent": f"LiteLLM-Proxy/{Config.FP_PROXY_SERVER_ID}",
            }
        )

        return session

    def _check_circuit_breaker(self) -> None:
        """Check if circuit breaker should block request."""
        with self._lock:
            now = time.time()

            # Reset if failure window has passed
            if now - self._last_failure > self.FAILURE_WINDOW:
                self._failure_count = 0
                return

            # Check if circuit is open
            if self._failure_count >= self.MAX_FAILURES:
                if now - self._last_failure < self.CIRCUIT_OPEN_TIME:
                    raise RuntimeError(
                        f"Circuit breaker open. Service unavailable. "
                        f"Retry after {int(self.CIRCUIT_OPEN_TIME - (now - self._last_failure))}s"
                    )
                else:
                    # Try to close circuit
                    self._failure_count = 0
                    LoggerManager.info("Circuit breaker: attempting to close")  # type: ignore

    def _record_failure(self) -> None:
        """Record a failure for circuit breaker."""
        with self._lock:
            self._failure_count += 1
            self._last_failure = time.time()
            if self._failure_count >= self.MAX_FAILURES:
                LoggerManager.error(  # type: ignore
                    f"Circuit breaker opened after {self._failure_count} failures"
                )

    def _record_success(self) -> None:
        """Record a success for circuit breaker."""
        with self._lock:
            if self._failure_count > 0:
                self._failure_count = 0
                LoggerManager.info("Circuit breaker: service recovered")  # type: ignore

    @contextmanager
    def _request_context(self, method: str, url: str):
        """Context manager for request execution with circuit breaker."""
        self._check_circuit_breaker()
        start_time = time.time()

        try:
            yield
            self._record_success()
            duration = time.time() - start_time
            LoggerManager.debug(  # type: ignore
                f"{method} {url} completed in {duration:.3f}s",
                duration=duration,
            )
        except requests.RequestException as e:
            self._record_failure()
            duration = time.time() - start_time
            LoggerManager.error(  # type: ignore
                f"{method} {url} failed after {duration:.3f}s: {e}",
                exc_info=False,
                duration=duration,
            )
            raise

    def post(self, url: str, headers: Dict[str, str], json: Any) -> requests.Response:
        with self._request_context("POST", url):
            return self.session.post(
                url, timeout=self.timeout, headers=headers, json=json
            )

    def get(self, url: str, headers: Dict[str, str]) -> requests.Response:
        with self._request_context("GET", url):
            return self.session.get(url, timeout=self.timeout, headers=headers)

    def close(self) -> None:
        self.session.close()
        LoggerManager.info("HTTP client closed")  # type: ignore


class HybridCrypto:
    """Crypto operations with error handling and monitoring."""

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
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")
            return cls._get_fernet().encrypt(data)
        except Exception as e:
            LoggerManager.error(f"Symmetric encryption failed: {e}", exc_info=True)  # type: ignore
            raise

    @classmethod
    def symmetric_decrypt(cls, token: bytes | str) -> bytes:
        try:
            if isinstance(token, str):
                token = token.encode("utf-8")
            return cls._get_fernet().decrypt(token)
        except Exception as e:
            LoggerManager.error(f"Symmetric decryption failed: {e}", exc_info=True)  # type: ignore
            raise

    @classmethod
    def asymmetric_public_key(cls) -> Optional[str]:
        return cls._public_key

    @classmethod
    def asymmetric_decrypt(cls, msg_bytes: bytes) -> Optional[str]:
        if cls._private_key is None:
            LoggerManager.error("Private key not loaded")  # type: ignore
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
            LoggerManager.error(f"Asymmetric decryption failed: {e}", exc_info=True)  # type: ignore
            return None

    @classmethod
    def load(cls) -> bool:
        output_dir = Path(Config.FP_PROXY_SERVER_KEYPAIR_DIR).resolve()
        key_file_path = output_dir / "key.pem"
        public_file_path = output_dir / "public.pem"

        if not key_file_path.exists():
            LoggerManager.error(f"Private key file not found: {key_file_path}")  # type: ignore
            return False

        if not public_file_path.exists():
            LoggerManager.error(f"Public key file not found: {public_file_path}")  # type: ignore
            return False

        if not Config.FP_PROXY_SERVER_KEYPAIR_PWD:
            LoggerManager.error("Key password not configured")  # type: ignore
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
            LoggerManager.info("Cryptographic keys loaded successfully")  # type: ignore
            return True

        except Exception as e:
            LoggerManager.error(f"Failed to load keys: {e}", exc_info=True)  # type: ignore
            return False

    @classmethod
    def unload(cls) -> None:
        cls._private_key = None
        cls._public_key = None
        cls._fernet_cipher = None
        LoggerManager.info("Cryptographic keys unloaded")  # type: ignore


class TokenRotator:
    """Production token rotation with monitoring and health checks."""

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
    _last_rotation_time: float = 0

    def __new__(cls):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60) -> None:
        """Start background token refresh thread."""

        def _refresher():
            LoggerManager.info("Token refresher thread started")  # type: ignore
            consecutive_failures = 0
            max_failures = 3

            while True:
                with cls._lock:
                    if cls._stop_thread:
                        LoggerManager.info("Token refresher thread stopping")  # type: ignore
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
                        LoggerManager.debug("Background token refresh initiated")  # type: ignore
                        success = cls._rotate_token()

                        if success:
                            consecutive_failures = 0
                        else:
                            consecutive_failures += 1
                            LoggerManager.warn(  # type: ignore
                                f"Token refresh failed ({consecutive_failures}/{max_failures})"
                            )

                        if consecutive_failures >= max_failures:
                            LoggerManager.error(  # type: ignore
                                f"Token refresh failed {consecutive_failures} times consecutively. "
                                "Service may be degraded."
                            )
                            # Don't stop the thread, keep trying

                    except Exception as e:
                        consecutive_failures += 1
                        LoggerManager.error(  # type: ignore
                            f"Background token refresh error: {e}", exc_info=True
                        )

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
                    LoggerManager.warn("Using fallback env token after initial failure")  # type: ignore
                    return Config.FP_APP_TOKEN_PASS

                # Wait if another thread is rotating
                if cls._rotating:
                    LoggerManager.debug(  # type: ignore
                        f"Waiting for token rotation (attempt {attempt})"
                    )
                    wait_success = cls._condition.wait(timeout=30)

                    if not wait_success:
                        LoggerManager.warn("Token rotation wait timed out")  # type: ignore
                        if attempt < max_attempts:
                            continue
                        else:
                            return None
                    continue

                # Start rotation
                cls._rotating = True

            # Rotate outside lock
            try:
                success = cls._rotate_token()
                if success:
                    # Don't recurse, just fetch from cache
                    with cls._lock:
                        if cls._token_cache is not None:
                            return HybridCrypto.symmetric_decrypt(
                                cls._token_cache
                            ).decode("utf-8")
                else:
                    # Rotation failed
                    if not cls._initial_exchange_done:
                        cls._initial_failed = True
                        return Config.FP_APP_TOKEN_PASS

                    if attempt < max_attempts:
                        LoggerManager.warn(  # type: ignore
                            f"Token rotation failed, retrying ({attempt}/{max_attempts})"
                        )
                        time.sleep(1)  # Brief delay before retry
                        continue

                    return None
            finally:
                with cls._lock:
                    cls._rotating = False
                    cls._condition.notify_all()

        LoggerManager.error("Failed to obtain token after maximum attempts")  # type: ignore
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
            LoggerManager.error("No current token available for rotation")  # type: ignore
            MetricsCollector.increment("token_rotation_failures")
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
                LoggerManager.error(  # type: ignore
                    f"Token rotation failed: HTTP {response.status_code} - {response.text[:200]}"
                )
                MetricsCollector.increment("token_rotation_failures")
                return False

            data = response.json()
            new_token = data.get("token")
            expires_in = data.get("expiresIn")

            if not new_token or expires_in is None:
                LoggerManager.error(f"Invalid token response: {data}")  # type: ignore
                MetricsCollector.increment("token_rotation_failures")
                return False

            with cls._lock:
                cls._token_cache = HybridCrypto.symmetric_encrypt(new_token)
                cls._expires_at = (
                    time.time() + expires_in - Config.FP_TOKEN_REFRESH_BUFFER
                )
                cls._initial_exchange_done = True
                cls._initial_failed = False
                cls._last_rotation_time = time.time()

            MetricsCollector.increment("token_rotations")
            LoggerManager.info(  # type: ignore
                f"Token rotated successfully (expires in {expires_in}s)",
                expires_in=expires_in,
            )
            return True

        except requests.RequestException as e:
            LoggerManager.error(f"Token rotation request failed: {e}", exc_info=False)  # type: ignore
            MetricsCollector.increment("token_rotation_failures")
            return False
        except Exception as e:
            LoggerManager.error(f"Token rotation failed: {e}", exc_info=True)  # type: ignore
            MetricsCollector.increment("token_rotation_failures")
            return False

    @classmethod
    def health_status(cls) -> Dict[str, Any]:
        """Get token rotation health status."""
        with cls._lock:
            now = time.time()
            return {
                "has_token": cls._token_cache is not None,
                "token_valid": cls._token_cache is not None and now < cls._expires_at,
                "expires_in": max(0, cls._expires_at - now) if cls._token_cache else 0,
                "initial_exchange_done": cls._initial_exchange_done,
                "last_rotation": cls._last_rotation_time,
                "seconds_since_rotation": (
                    now - cls._last_rotation_time if cls._last_rotation_time > 0 else -1
                ),
            }

    @classmethod
    def clear(cls) -> None:
        """Clear token cache and stop background thread."""

        with cls._lock:
            cls._token_cache = None
            cls._expires_at = 0
            cls._stop_thread = True
            cls._condition.notify_all()

        if cls._background_thread and cls._background_thread.is_alive():
            cls._background_thread.join(timeout=5)
            if cls._background_thread.is_alive():
                LoggerManager.warn("Token refresher thread did not stop cleanly")  # type: ignore
            cls._background_thread = None

        LoggerManager.info("Token rotation cleared and stopped")  # type: ignore


class HealthCheck:
    """System health check."""

    _last_check: float = 0
    _lock = threading.Lock()

    @classmethod
    def status(cls) -> Dict[str, Any]:
        """Get comprehensive health status."""
        with cls._lock:
            now = time.time()
            cls._last_check = now

            token_health = TokenRotator.health_status()
            metrics = MetricsCollector.get_metrics()

            cache_hit_rate = 0.0
            if metrics["cache_hits"] + metrics["cache_misses"] > 0:
                cache_hit_rate = metrics["cache_hits"] / (
                    metrics["cache_hits"] + metrics["cache_misses"]
                )

            return {
                "timestamp": now,
                "status": "healthy" if token_health["token_valid"] else "degraded",
                "token": token_health,
                "metrics": metrics,
                "cache_hit_rate": cache_hit_rate,
                "cache_size": len(_key_cache.data),  # type: ignore
            }


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
    LoggerManager.info(f"Received signal {signum}, initiating graceful shutdown")  # type: ignore

    try:
        TokenRotator.clear()
        http_client.close()
        LoggerManager.info("Graceful shutdown completed")  # type: ignore
    except Exception as e:
        LoggerManager.error(f"Error during shutdown: {e}", exc_info=True)  # type: ignore
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

LoggerManager.info("=== Proxy Auth Module Initializing ===")  # type: ignore
LoggerManager.info(f"Proxy ID: {Config.FP_PROXY_SERVER_ID}")  # type: ignore
LoggerManager.info(f"App URL: {Config.FP_APP_BASE_URL}")  # type: ignore

# Register signal handlers
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

# Initialize HTTP client
http_client = HTTPClient()

# Register proxy server
try:
    LoggerManager.info("Registering proxy server...")  # type: ignore
    response = http_client.post(
        f"{Config.FP_APP_BASE_URL}/api/{Config.FP_PROXY_SERVER_ID}/registry",
        headers={"authorization": f"Bearer {Config.FP_APP_TOKEN_PASS}"},
        json={"models_by_provider": convert_sets_to_lists(models_by_provider)},
    )
    response.raise_for_status()
    LoggerManager.info("Proxy server registered successfully")  # type: ignore
except Exception as e:
    LoggerManager.error(f"Failed to register proxy server: {e}", exc_info=True)  # type: ignore
    # Don't exit, continue with degraded functionality

# Load crypto keys
LoggerManager.info("Loading cryptographic keys...")  # type: ignore
if not HybridCrypto.load():
    LoggerManager.error("Failed to load cryptographic keys")  # type: ignore
    sys.exit(1)

# Initialize token rotation
LoggerManager.info("Initializing token rotation...")  # type: ignore
TokenRotator.clear()
TokenRotator.background_refresh(interval=Config.FP_TOKEN_REFRESH_INTERVAL)

# Cache for API key validation with TTL
_key_cache: TimestampedLRUCache = TimestampedLRUCache(
    maxsize=Config.FP_LRU_MAX_CACHE_SIZE, ttl=3600  # 1 hour TTL
)


# Background cache cleanup
def _cache_cleanup_worker():
    """Periodically clean up expired cache entries."""
    while True:
        time.sleep(300)  # Every 5 minutes
        try:
            removed = _key_cache.cleanup_expired()
            if removed > 0:
                LoggerManager.info(f"Cleaned up {removed} expired cache entries")  # type: ignore
        except Exception as e:
            LoggerManager.error(f"Cache cleanup error: {e}", exc_info=True)  # type: ignore


_cleanup_thread = threading.Thread(
    target=_cache_cleanup_worker, daemon=True, name="CacheCleanup"
)
_cleanup_thread.start()

LoggerManager.info("=== Proxy Auth Module Initialized Successfully ===")  # type: ignore


# ============================================================================
# LiteLLM Auth Hook
# ============================================================================


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    """
    Custom authentication hook for LiteLLM - Production version.

    Features:
    - Request validation
    - Cache with TTL
    - Metrics collection
    - Detailed error logging
    - Graceful degradation
    """

    request_start = time.time()

    try:
        # Validate input
        if not api_key:
            MetricsCollector.increment("auth_failures")
            LoggerManager.warn("Authentication attempted with empty API key")  # type: ignore
            raise ValueError("API key is required")

        if len(api_key) > 256:  # Sanity check
            MetricsCollector.increment("auth_failures")
            LoggerManager.warn("Authentication attempted with oversized API key")  # type: ignore
            raise ValueError("Invalid API key format")

        # Hash API key for cache lookup
        hashed_token = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        # Check cache first
        cache_entry = _key_cache[hashed_token]
        if cache_entry is not None:
            ProxyRequestCounter.increment()
            MetricsCollector.increment("cache_hits")

            duration = time.time() - request_start
            LoggerManager.debug(  # type: ignore
                f"Auth cache hit (took {duration:.3f}s)",
                duration=duration,
                cached=True,
            )

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

        MetricsCollector.increment("cache_misses")

        # Get current app token
        app_token = TokenRotator.token()
        if not app_token:
            MetricsCollector.increment("auth_failures")
            LoggerManager.error("Failed to obtain app token for authentication")  # type: ignore
            raise RuntimeError("Authentication service temporarily unavailable")

        # Validate API key with backend
        try:
            headers = {
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
            }

            # Initial validation
            validate_start = time.time()
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

            validate_duration = time.time() - validate_start

            response_data = response.json()

            # Decrypt the key
            decrypt_start = time.time()
            message_bytes = base64.b64decode(response_data["enc"])
            message_decrypted = HybridCrypto.asymmetric_decrypt(message_bytes)
            decrypt_duration = time.time() - decrypt_start

            if not message_decrypted:
                MetricsCollector.increment("auth_failures")
                LoggerManager.error("Failed to decrypt API key from backend")  # type: ignore
                raise ValueError("Authentication failed - decryption error")

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

            duration = time.time() - request_start
            LoggerManager.info(  # type: ignore
                f"Auth successful (total: {duration:.3f}s, validate: {validate_duration:.3f}s, decrypt: {decrypt_duration:.3f}s)",
                duration=duration,
                validate_duration=validate_duration,
                decrypt_duration=decrypt_duration,
                cached=False,
            )

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
            MetricsCollector.increment("auth_failures")
            status_code = e.response.status_code if e.response else "unknown"

            if status_code == 401:
                LoggerManager.warn("Authentication failed: Invalid API key")  # type: ignore
                raise ValueError("Invalid API key")
            elif status_code == 403:
                LoggerManager.warn("Authentication failed: Access forbidden")  # type: ignore
                raise ValueError("Access forbidden")
            else:
                LoggerManager.error(  # type: ignore
                    f"Authentication service error: HTTP {status_code}",
                    exc_info=False,
                )
                raise RuntimeError("Authentication service error")

        except requests.RequestException as e:
            MetricsCollector.increment("auth_failures")
            LoggerManager.error(  # type: ignore
                f"API key validation request failed: {e}",
                exc_info=True,
            )
            raise RuntimeError("Authentication service unavailable")

    except (ValueError, RuntimeError) as e:
        # Expected errors - already logged
        duration = time.time() - request_start
        LoggerManager.debug(f"Auth failed in {duration:.3f}s: {e}", duration=duration)  # type: ignore
        raise

    except Exception as e:
        MetricsCollector.increment("auth_failures")
        duration = time.time() - request_start
        LoggerManager.error(  # type: ignore
            f"Unexpected authentication error after {duration:.3f}s: {e}",
            exc_info=True,
            duration=duration,
        )
        raise RuntimeError("Authentication failed")
