from __future__ import annotations

import atexit
import base64
import logging
import os
import sys
import threading
import time
from enum import Enum
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Literal, Optional

import requests
from cachetools import LRUCache
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth
from litellm.types.utils import LLMResponseTypes, ModelResponseStream
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()
root_logger = logging.getLogger()
root_logger.handlers.clear()
formatter = logging.Formatter("%(asctime)s - %(message)s")

# File
file_handler = TimedRotatingFileHandler(
    "app.log", when="midnight", interval=1, backupCount=7
)
file_handler.setFormatter(formatter)
root_logger.addHandler(file_handler)

# Console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

# level
root_logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)


class PreCallResponse(Enum):
    COMPATIBILITY = "Compatibility Issue"
    AUTHORIZATION = "Authorization Issue"
    INTERNAL = "Internal Error"


class Config:
    # App
    APP_TOKEN_PASS = os.getenv("APP_TOKEN_PASS", None)
    APP_BASE_URL = os.getenv("APP_BASE_URL", None)

    # Proxy Server
    PROXY_SERVER_URL = os.getenv("PROXY_SERVER_URL", None)
    PROXY_SERVER_ID = os.getenv("PROXY_SERVER_ID", None)
    PROXY_SERVER_ADVANCED = int(os.getenv("PROXY_SERVER_ADVANCED", "0"))
    PROXY_SERVER_KEYPAIR_PWD = os.getenv("PROXY_SERVER_KEYPAIR_PWD", None)

    # LRU Cache
    LRU_MAX_CACHE_SIZE = int(os.getenv("LRU_MAX_CACHE_SIZE", "500"))

    # Http related
    HTTP_CONNECT_TIMEOUT_LIMIT = int(os.getenv("HTTP_CONNECT_TIMEOUT_LIMIT", "8"))
    HTTP_READ_TIMEOUT_LIMIT = int(os.getenv("HTTP_READ_TIMEOUT_LIMIT", "120"))
    HTTP_MAX_RETRY_COUNT = int(os.getenv("HTTP_MAX_RETRY_COUNT", "3"))
    HTTP_POOL_MAX_SIZE = int(os.getenv("HTTP_POOL_MAX_SIZE", "30"))
    HTTP_MAX_POOL_CONNECTIONS_COUNT = int(
        os.getenv("HTTP_MAX_POOL_CONNECTIONS_COUNT", "10")
    )
    HTTP_RETRY_BACKOFF = float(os.getenv("HTTP_RETRY_BACKOFF", "0.5"))


class TimestampedLRUCache(LRUCache[str, dict[str, str]]):
    _last_used: dict[str, float] = {}  # key - timestamp

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
            Config.HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = requests.Session()

        retry_strategy = Retry(
            total=Config.HTTP_MAX_RETRY_COUNT,
            backoff_factor=Config.HTTP_RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=Config.HTTP_MAX_POOL_CONNECTIONS_COUNT,
            pool_maxsize=Config.HTTP_POOL_MAX_SIZE,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _request(
        self, method: str, url: str, headers: Any, data: Any
    ) -> requests.Response:
        return self.session.request(
            method, url, timeout=self.timeout, headers=headers, json=data
        )

    def post(self, url: str, headers: Any, data: Any) -> requests.Response:
        return self._request("POST", url, headers, data)

    def close(self):
        self.session.close()


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


class TokenRotator:
    _env_lock = threading.RLock()
    _condition = threading.Condition(_env_lock)
    _token_cache: Optional[str] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, http_client: "HTTPClient", interval: int = 60):
        def _refresher():
            while True:
                time.sleep(interval)
                should_refresh = False
                with cls._env_lock:
                    now = time.time()
                    if (
                        cls._token_cache is None or now > cls._expires_at - 600
                    ):  # 10分钟窗口
                        should_refresh = True
                if should_refresh:
                    try:
                        logger.debug(
                            "Background refresher: token nearing expiry, rotating..."
                        )
                        cls.token(http_client)
                    except Exception as e:
                        logger.error(f"Background token refresh failed: {e}")

        t = threading.Thread(target=_refresher, daemon=True)
        t.start()

    @classmethod
    def token(cls, http_client: "HTTPClient") -> Optional[str]:
        current_token: Optional[str] = None
        was_using_cache: bool = False
        is_initial: bool = False

        while True:
            with cls._env_lock:
                now = time.time()

                # Check if we have a valid cached token
                if cls._token_cache is not None and now < cls._expires_at:
                    return cls._token_cache

                # Early fallback for initial failure
                if not cls._initial_exchange_done and cls._initial_failed:
                    logger.warning(
                        "Initial token exchange failed previously; falling back to env token"
                    )
                    return Config.APP_TOKEN_PASS

                # If another thread is rotating, wait for it to complete
                if cls._rotating:
                    logger.debug("Token rotation in progress; waiting...")
                    cls._condition.wait()
                    continue  # Recheck conditions after wakeup

                # No valid token; start rotation
                current_token = (
                    cls._token_cache
                    if cls._token_cache is not None
                    else Config.APP_TOKEN_PASS
                )
                if current_token is None:
                    logger.error("No current token available for exchange")
                    return None

                was_using_cache = cls._token_cache is not None
                is_initial = not cls._initial_exchange_done and not was_using_cache
                cls._rotating = True
                logger.debug("Starting token rotation...")

            # Only the rotator thread reaches here (others wait)
            # Perform the HTTP exchange outside the lock to avoid blocking
            success_token: Optional[str] = None
            new_expires_at: float = 0
            try:
                response: requests.Response = http_client.post(
                    url=f"{Config.APP_BASE_URL}/api/auth/exchange",
                    headers={"authorization": f"Bearer {current_token}"},
                    data={
                        "url": Config.PROXY_SERVER_URL,
                        "status": ProxyRequestCounter.status(),
                        "adv": Config.PROXY_SERVER_ADVANCED == 1,
                        "id": Config.PROXY_SERVER_ID,
                    },
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except ValueError as e:
                        logger.error(f"Failed to parse token response JSON: {e}")
                        raise  # Treat as failure

                    new_token = data.get("token")
                    expires_in = data.get("expiresIn")

                    if new_token and expires_in is not None:
                        success_token = new_token
                        new_expires_at = (
                            time.time() + expires_in - 300
                        )  # 5-minute buffer
                        logger.info(
                            f"Token rotated successfully, expires in {expires_in}s"
                        )
                    else:
                        logger.error(
                            "Token response missing 'token' or 'expiresIn' field"
                        )
                        raise  # Treat as failure
                else:
                    logger.error(f"Token rotate failed: {response.status_code}")
                    raise  # Treat as failure

            except (
                requests.RequestException
            ) as e:  # Adjust exception if HTTPClient differs
                logger.error(f"Token rotate request failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected error in token rotate: {e}")

            # Update state after exchange attempt
            with cls._env_lock:
                cls._rotating = False
                if success_token:
                    cls._token_cache = success_token
                    cls._expires_at = new_expires_at
                    if is_initial:
                        cls._initial_exchange_done = True
                    cls._initial_failed = False
                    cls._condition.notify_all()
                    logger.debug("Token rotation completed; notified waiters")
                    return success_token  # Rotator returns the new token directly
                else:
                    # Failure handling
                    if is_initial:
                        cls._initial_failed = True
                        logger.warning(
                            "Initial token exchange failed; will fallback to env token on future calls"
                        )
                    elif was_using_cache:
                        # For non-initial failures, clear the invalid cache
                        cls._token_cache = None
                        cls._expires_at = 0
                        logger.warning(
                            "Cleared invalid cached token after rotation failure"
                        )
                    cls._condition.notify_all()
                    logger.debug("Token rotation failed; notified waiters")

    @classmethod
    def clear(cls) -> None:
        """Clear the cached token, forcing a rotation on next token() call."""
        with cls._env_lock:
            cls._token_cache = None
            cls._expires_at = 0


class KeyPairLoader:
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def public_key(cls) -> Optional[str]:
        return cls._public_key

    @classmethod
    def decrypt(cls, msg_bytes: bytes) -> Optional[str]:
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
        except Exception as e:
            logger.error(f"Decrypt failed: {e}")
            return None

    @classmethod
    def load(cls) -> bool:
        key_file_path = Path.cwd() / "key.pem"
        public_file_path = Path.cwd() / "public.pem"

        if not key_file_path.exists() or not public_file_path.exists():
            logger.error("Key files not found")
            return False

        if not Config.PROXY_SERVER_KEYPAIR_PWD:
            logger.error("Keys password is invalid")
            return False

        try:
            private_pem_bytes = key_file_path.read_bytes()
            public_pem_bytes = public_file_path.read_bytes()
            password = Config.PROXY_SERVER_KEYPAIR_PWD.encode("ascii")

            private_key = serialization.load_pem_private_key(
                private_pem_bytes, password=password
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError(f"Expected RSAPrivateKey, got {type(private_key)}")

            cls._private_key = private_key
            cls._public_key = public_pem_bytes.decode("utf-8")
            logger.info("Keys Correctly Loaded")
            return True

        except Exception as e:
            logger.error(f"Key loading failed: {e}")
            return False

    @classmethod
    def unload(cls):
        cls._private_key = None
        cls._public_key = None


# This file includes the custom callbacks for LiteLLM Proxy
class FlexiProxyCustomHandler(CustomLogger):
    _http_client: "HTTPClient"
    _api_cache: "TimestampedLRUCache"

    def __init__(self):
        super().__init__(True)  # type: ignore
        self._http_client = HTTPClient()
        self._api_cache = TimestampedLRUCache(maxsize=Config.LRU_MAX_CACHE_SIZE)
        # Start background refresh
        TokenRotator.background_refresh(self._http_client, 30)
        if not KeyPairLoader.load():
            raise RuntimeError(
                "Failed to load keys. Check key.pem, public.pem and PROXY_SERVER_KEYPAIR_PWD."
            )  # 加验证，抛错

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        logger.info("Request success")

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        logger.error("Request failure")

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        logger.info("Async request success")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        logger.error("Async request failure")

    #### CALL HOOKS - proxy only ####

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Literal[
            "completion",
            "text_completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
            "pass_through_endpoint",
            "rerank",
            "mcp_call",
        ],
    ):
        if "secret_fields" not in data:
            logger.error('"secret_fields" field not found in data')
            return PreCallResponse.COMPATIBILITY

        if "raw_headers" not in data["secret_fields"]:
            logger.error('"raw_headers" field not found in data["secret_fields"]')
            return PreCallResponse.COMPATIBILITY

        raw_headers: Optional[dict] = data["secret_fields"]["raw_headers"]
        if raw_headers is None:
            logger.error('"raw_headers" field is invalid')
            return PreCallResponse.COMPATIBILITY

        # Extract client API key
        client_api_key = None
        if "x-api-key" in raw_headers:
            client_api_key = raw_headers["x-api-key"]
        elif (
            "authorization" in raw_headers
            and isinstance(raw_headers["authorization"], str)
            and str(raw_headers["authorization"]).startswith("Bearer ")
        ):
            client_api_key = raw_headers["authorization"][7:]

        if client_api_key is None:
            logger.error("Client API key not found in headers")
            return PreCallResponse.AUTHORIZATION

        app_token: Optional[str] = TokenRotator.token(self._http_client)
        if app_token is None:
            logger.error("App token is invalid")
            return PreCallResponse.INTERNAL

        cached_key = f"{client_api_key}:{app_token}"
        cached_entry = self._api_cache[cached_key]
        if cached_entry is None:
            try:
                response: requests.Response = self._http_client.post(
                    f"{Config.APP_BASE_URL}/api/adapters",
                    headers={
                        "authorization": f"Bearer {app_token}",
                        "X-API-Key": client_api_key,
                        "Content-Type": "application/json",
                    },
                    data={"public_key": KeyPairLoader.public_key()},
                )
                response.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"Request failed: {e}")
                return PreCallResponse.INTERNAL

            try:
                response_data = response.json()
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                return PreCallResponse.INTERNAL

            result: dict[str, str] = {}
            try:
                required_fields = ["uid", "url", "mid", "enc"]
                if not all(field in response_data for field in required_fields):
                    logger.error("Missing required fields in response")
                    return PreCallResponse.INTERNAL

                # result["uid"] = response_data["uid"]
                result["url"] = response_data["url"]
                result["mid"] = response_data["mid"]

                message_bytes = base64.b64decode(response_data["enc"])

                try:
                    message_decrypted: Optional[str] = KeyPairLoader.decrypt(
                        message_bytes
                    )
                    if message_decrypted is None:
                        logger.error("Decryption failed")
                        return PreCallResponse.INTERNAL
                    result["key"] = message_decrypted
                except ValueError as e:
                    logger.error(f"Decryption failed: {e}")
                    return PreCallResponse.INTERNAL

                self._api_cache[cached_key] = cached_entry = result
            except KeyError as e:
                logger.error(f"Missing key in response data: {e}")
                return PreCallResponse.INTERNAL
            except Exception as e:
                logger.error(f"Error processing adapter response: {e}")
                return PreCallResponse.INTERNAL

        if cached_entry is None:
            logger.error("Failed to retrieve user authorization information")
            return PreCallResponse.INTERNAL

        # Update data
        data["api_base"] = cached_entry["url"]
        data["api_key"] = cached_entry["key"]
        data["model"] = cached_entry["mid"]

        ProxyRequestCounter.increment()
        return data


proxy_handler_instance = FlexiProxyCustomHandler()


def shutdown():
    KeyPairLoader.unload()
    TokenRotator.clear()


atexit.register(shutdown)
