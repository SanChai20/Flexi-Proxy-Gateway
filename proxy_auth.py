import asyncio
import base64
import hashlib
import logging
import os
import signal
import socket
import sys
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
    FP_LRU_MAX_CACHE_SIZE: int = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "2000"))

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
    FP_HTTP_POOL_BLOCK: int = int(os.getenv("FP_HTTP_POOL_BLOCK", "1"))
    FP_FORCE_IPV4: int = int(os.getenv("FP_FORCE_IPV4", "0"))

    # TCP socket tuning (all optional, safe defaults keep behavior unchanged)
    FP_TCP_NODELAY: int = int(os.getenv("FP_TCP_NODELAY", "1"))  # 1=enable Nagle off
    FP_TCP_KEEPALIVE: int = int(
        os.getenv("FP_TCP_KEEPALIVE", "1")
    )  # 1=enable SO_KEEPALIVE
    FP_TCP_KEEPIDLE_SECS: int = int(
        os.getenv("FP_TCP_KEEPIDLE_SECS", "30")
    )  # idle before probes
    FP_TCP_KEEPINTVL_SECS: int = int(
        os.getenv("FP_TCP_KEEPINTVL_SECS", "10")
    )  # interval between probes
    FP_TCP_KEEPCNT: int = int(
        os.getenv("FP_TCP_KEEPCNT", "5")
    )  # probe count before drop
    FP_TCP_FASTOPEN: int = int(
        os.getenv("FP_TCP_FASTOPEN", "0")
    )  # 1=enable if kernel/path supports
    FP_TCP_NOTSENT_LOWAT: int = int(
        os.getenv("FP_TCP_NOTSENT_LOWAT", "0")
    )  # 0=disabled; >0 to enable
    FP_TCP_MAXSEG: int = int(
        os.getenv("FP_TCP_MAXSEG", "0")
    )  # 0=default; >0 to bound MSS

    # Token Rotation
    FP_TOKEN_REFRESH_INTERVAL: int = int(os.getenv("FP_TOKEN_REFRESH_INTERVAL", "60"))
    FP_TOKEN_REFRESH_BUFFER: int = int(os.getenv("FP_TOKEN_REFRESH_BUFFER", "300"))

    # Logging
    FP_LOG_LEVEL: str = os.getenv("FP_LOG_LEVEL", "WARNING")
    FP_LOG_DIR: str = os.getenv("FP_LOG_DIR", "/var/log/litellm")
    FP_LOG_FILE: str = os.getenv("FP_LOG_FILE", "proxy_auth.log")
    FP_LOG_BACKUP_COUNT: int = int(os.getenv("FP_LOG_BACKUP_COUNT", "7"))

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


def _build_socket_options() -> list[tuple[int, int, int]]:
    """
    Cross-platform TCP socket options with platform/version guards.
    Defaults are conservative to keep behavior unchanged; enable via Config.
    """
    opts: list[tuple[int, int, int]] = []

    # Always safe to try SO_KEEPALIVE (if enabled via config)
    if Config.FP_TCP_KEEPALIVE:
        try:
            opts.append((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1))
        except Exception:
            pass

    # Disable Nagle for lower latency on small requests
    if Config.FP_TCP_NODELAY and hasattr(socket, "TCP_NODELAY"):
        try:
            opts.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))
        except Exception:
            pass

    # Keepalive platform specifics
    # Linux/BSD usually: TCP_KEEPIDLE/KEEPINTVL/KEEPCNT
    if hasattr(socket, "TCP_KEEPIDLE") and sys.platform != "darwin":
        try:
            opts.append(
                (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, Config.FP_TCP_KEEPIDLE_SECS)
            )
        except Exception:
            pass

    if hasattr(socket, "TCP_KEEPINTVL"):
        try:
            opts.append(
                (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, Config.FP_TCP_KEEPINTVL_SECS)
            )
        except Exception:
            pass

    if hasattr(socket, "TCP_KEEPCNT"):
        try:
            opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPCNT, Config.FP_TCP_KEEPCNT))
        except Exception:
            pass

    # macOS: Python 3.10+ exposes TCP_KEEPALIVE as idle seconds
    # guard: sys.version_info >= (3,10) and platform == darwin
    if sys.platform == "darwin" and hasattr(socket, "TCP_KEEPALIVE"):
        try:
            opts.append(
                (socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, Config.FP_TCP_KEEPIDLE_SECS)
            )
        except Exception:
            pass

    # Optional: TCP Fast Open (client side)
    # Linux >= 4.11 prefers TCP_FASTOPEN_CONNECT; fallback to TCP_FASTOPEN if available.
    # if Config.FP_TCP_FASTOPEN:
    #     try:
    #         if hasattr(socket, "TCP_FASTOPEN_CONNECT"):
    #             opts.append((socket.IPPROTO_TCP, socket.TCP_FASTOPEN_CONNECT, 1))
    #         elif hasattr(socket, "TCP_FASTOPEN"):
    #             # On some platforms, TCP_FASTOPEN toggles client/server behavior via bit flags.
    #             opts.append((socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1))
    #     except Exception:
    #         # Some kernels or middleboxes may block TFO; keep silent fallback.
    #         pass

    # Optional: NOTSENT_LOWAT (reduce head-of-line blocking for buffered data)
    if (
        Config.FP_TCP_NOTSENT_LOWAT > 0
        and hasattr(socket, "TCP_NOTSENT_LOWAT")
        and sys.platform != "win32"
    ):
        try:
            opts.append(
                (
                    socket.IPPROTO_TCP,
                    socket.TCP_NOTSENT_LOWAT,
                    Config.FP_TCP_NOTSENT_LOWAT,
                )
            )
        except Exception:
            pass

    # Optional: clamp MSS if you know the path MTU; otherwise keep default (0)
    if Config.FP_TCP_MAXSEG > 0 and hasattr(socket, "TCP_MAXSEG"):
        try:
            opts.append((socket.IPPROTO_TCP, socket.TCP_MAXSEG, Config.FP_TCP_MAXSEG))
        except Exception:
            pass

    return opts


class TunedHTTPAdapter(HTTPAdapter):
    """HTTPAdapter with tuned socket options and pool behavior."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs = dict(pool_kwargs or {})
        sock_opts = pool_kwargs.get("socket_options", [])  # type: ignore
        sock_opts.extend(_build_socket_options())  # type: ignore
        pool_kwargs["socket_options"] = sock_opts
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)  # type: ignore

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        # Ensure proxy pools also inherit socket options
        proxy_kwargs = dict(proxy_kwargs or {})
        sock_opts = proxy_kwargs.get("socket_options", [])  # type: ignore
        sock_opts.extend(_build_socket_options())  # type: ignore
        proxy_kwargs["socket_options"] = sock_opts
        return super().proxy_manager_for(proxy, **proxy_kwargs)  # type: ignore


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

        # Avoid reading proxies/certs from env, which may introduce unexpected DNS/proxy hops.
        session.trust_env = False

        retry_strategy = Retry(
            total=Config.FP_HTTP_MAX_RETRY_COUNT,
            backoff_factor=Config.FP_HTTP_RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
            respect_retry_after_header=True,
        )

        adapter = TunedHTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=Config.FP_HTTP_MAX_POOL_CONNECTIONS_COUNT,
            pool_maxsize=Config.FP_HTTP_POOL_MAX_SIZE,
            pool_block=bool(Config.FP_HTTP_POOL_BLOCK),
        )

        # Optional: force IPv4 if your IPv6 path is flaky/slow
        if Config.FP_FORCE_IPV4 == 1:
            try:
                # Works for urllib3 v1/v2
                from urllib3.util import connection as urllib3_connection

                def _allowed_gai_family():
                    return socket.AF_INET

                urllib3_connection.allowed_gai_family = _allowed_gai_family
            except Exception as e:
                LoggerManager.warn(f"Failed to force IPv4 resolution: {e}")

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
    _cond = threading.Condition(_lock)
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
                    if not should_refresh:
                        continue
                    if cls._rotating:
                        # another rotation in progress, skip and let it notify
                        continue
                    cls._rotating = True

                try:
                    success = cls._rotate_token()

                    with cls._lock:
                        if success:
                            consecutive_failures = 0
                        else:
                            consecutive_failures += 1
                except Exception as e:
                    consecutive_failures += 1
                    LoggerManager.error(f"Background token refresh error: {e}")
                finally:
                    with cls._lock:
                        cls._rotating = False
                        cls._cond.notify_all()  # wake up any waiters

                if consecutive_failures >= max_failures:
                    LoggerManager.error(
                        f"Token refresh failed {consecutive_failures} times consecutively"
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
                    return Config.FP_APP_TOKEN_PASS

                # If a rotation is in progress, wait for it to complete
                if cls._rotating:
                    cls._cond.wait(timeout=2.0)
                    # loop and re-check state
                    continue

                # Start rotation ourselves
                cls._rotating = True

            # Do rotation outside lock
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
                        with cls._lock:
                            cls._initial_failed = True
                        return Config.FP_APP_TOKEN_PASS

                    if attempt < max_attempts:
                        time.sleep(1)
                        continue

                    return None
            finally:
                with cls._lock:
                    cls._rotating = False
                    cls._cond.notify_all()

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
                # store "absolute" expiry; we already subtract buffer here
                cls._expires_at = (
                    time.time()
                    + float(expires_in)
                    - float(Config.FP_TOKEN_REFRESH_BUFFER)
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
            cls._cond.notify_all()

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
    - Avoids blocking the event loop by running requests in a thread via asyncio.to_thread.
    - Optimistic single-POST validate when server supports it, with automatic fallback to GET+POST.
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

    # Validate API key with backend (non-blocking for async loop)
    try:
        headers = {
            "authorization": f"Bearer {app_token}",
            "X-API-Key": api_key,
        }

        # Optimistically attempt single POST (if backend supports returning enc directly)
        response = await asyncio.to_thread(
            http_client.post,
            f"{Config.FP_APP_BASE_URL}/api/auth/validate",
            headers=headers,
            json={"public_key": HybridCrypto.asymmetric_public_key()},
        )

        use_fallback = False
        response_data: Dict[str, Any] = {}
        if response.status_code == 200:
            try:
                response_data = response.json()
                if "enc" not in response_data:
                    use_fallback = True
            except Exception:
                use_fallback = True
        else:
            # If 401/403 etc., let the error handling below process after fallback path
            use_fallback = True

        if use_fallback:
            # Step 1: GET validate
            response = await asyncio.to_thread(
                http_client.get,
                f"{Config.FP_APP_BASE_URL}/api/auth/validate",
                headers=headers,
            )
            response.raise_for_status()

            # Step 2: POST to get encrypted key
            response = await asyncio.to_thread(
                http_client.post,
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
