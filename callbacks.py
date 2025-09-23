import base64
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, Literal, Optional, OrderedDict

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth
from requests.adapters import HTTPAdapter
from urllib3 import Retry

load_dotenv()

handler = TimedRotatingFileHandler(
    "app.log", when="midnight", interval=1, backupCount=7
)
logging.basicConfig(
    handlers=[handler], level=logging.INFO, format="%(asctime)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Config:
    # App
    APP_TOKEN_PASS = os.getenv("APP_TOKEN_PASS", None)
    APP_BASE_URL = os.getenv("APP_BASE_URL", None)

    # Proxy Server
    PROXY_SERVER_URL = os.getenv("PROXY_SERVER_URL", None)
    PROXY_SERVER_ID = os.getenv("PROXY_SERVER_ID", None)
    PROXY_SERVER_ADVANCED = int(os.getenv("PROXY_SERVER_ADVANCED", "0"))
    PROXY_SERVER_KEYPAIR_PWD = os.getenv("PROXY_SERVER_KEYPAIR_PWD", None)

    # Scheduler
    SCHEDULE_TOKEN_ROTATION_INTERVAL = int(
        os.getenv("SCHEDULE_TOKEN_ROTATION_INTERVAL", "10")
    )
    SCHEDULE_STATUS_REPORT_INTERVAL = int(
        os.getenv("SCHEDULE_STATUS_REPORT_INTERVAL", "30")
    )

    # Thread
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "8"))

    # LRU Cache
    LRU_MAX_CACHE_SIZE = int(os.getenv("LRU_MAX_CACHE_SIZE", "500"))
    LRU_MAX_CACHE_TTL = int(os.getenv("LRU_MAX_CACHE_TTL", "1800"))

    # Http related
    HTTP_CONNECT_TIMEOUT_LIMIT = int(os.getenv("HTTP_CONNECT_TIMEOUT_LIMIT", "8"))
    HTTP_READ_TIMEOUT_LIMIT = int(os.getenv("HTTP_READ_TIMEOUT_LIMIT", "120"))
    HTTP_MAX_RETRY_COUNT = int(os.getenv("HTTP_MAX_RETRY_COUNT", "3"))
    HTTP_POOL_MAX_SIZE = int(os.getenv("HTTP_POOL_MAX_SIZE", "30"))
    HTTP_MAX_POOL_CONNECTIONS_COUNT = int(
        os.getenv("HTTP_MAX_POOL_CONNECTIONS_COUNT", "10")
    )


@dataclass
class AdapterCacheEntry:
    data: Dict[str, str]
    timestamp: float
    ttl: int


class LRUCache:
    """Thread-safe LRU + TTL Cache"""

    def __init__(self):
        self._cache: OrderedDict[str, "AdapterCacheEntry"] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional["AdapterCacheEntry"]:
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            if time.time() - entry.timestamp > entry.ttl:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)  # 最近访问
            return entry

    def set(self, key: str, value: "AdapterCacheEntry"):
        with self._lock:
            if key in self._cache:
                self._cache.pop(key)
            elif len(self._cache) >= Config.LRU_MAX_CACHE_SIZE:
                self._cache.popitem(last=False)  # 移除最久未使用
            self._cache[key] = value

    def clear_expired(self):
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._cache.items() if now - v.timestamp > v.ttl]
            for k in expired:
                self._cache.pop(k, None)


class ThreadSafeCounter:
    """Thread-safe counter"""

    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def increment(self) -> int:
        with self._lock:
            self._value += 1
            return self._value

    def get_and_reset(self) -> int:
        with self._lock:
            current = self._value
            self._value = 0
            return current

    def get(self) -> int:
        with self._lock:
            return self._value


class HTTPClient:
    """HTTP Client Wrapper, Support retry & connetion pool"""

    def __init__(
        self,
        pool_connections: int = Config.HTTP_MAX_POOL_CONNECTIONS_COUNT,
        pool_maxsize=Config.HTTP_POOL_MAX_SIZE,
        read_timeout: int = Config.HTTP_READ_TIMEOUT_LIMIT,
    ):
        self.timeout = (
            Config.HTTP_CONNECT_TIMEOUT_LIMIT,
            read_timeout,
        )  # connect timeout + read timeout
        self.session = requests.Session()

        retry_strategy = Retry(
            total=Config.HTTP_MAX_RETRY_COUNT,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)  # type: ignore
        logger.info(f"{method} request to {url}")
        return self.session.request(method, url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._request("POST", url, **kwargs)  # type: ignore

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request("GET", url, **kwargs)  # type: ignore

    def close(self):
        self.session.close()


class TokenRotator:
    _env_lock = threading.RLock()
    _token_cache: Optional[str] = None
    _expires_at: float = 0

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def token(cls) -> str | None:
        if cls._token_cache is not None and time.time() < cls._expires_at:
            return cls._token_cache

        with cls._env_lock:
            if cls._token_cache is not None:
                if time.time() < cls._expires_at:
                    return cls._token_cache
                else:
                    logger.error("Token expired. Try using deprecated token from env.")
            return Config.APP_TOKEN_PASS

    @classmethod
    def clear(cls) -> None:
        with cls._env_lock:
            cls._token_cache = None
            cls._expires_at = 0

    @classmethod
    def rotate(cls, http_client: HTTPClient) -> bool:
        if Config.APP_BASE_URL is None:
            logger.error("Missing APP_BASE_URL environment variable")
            return False

        current_token = cls.token()
        if not current_token:
            logger.error("No current token available for exchange")
            return False

        try:
            response = http_client.post(  # type: ignore
                url=f"{Config.APP_BASE_URL}/api/auth/exchange",
                headers={"authorization": f"Bearer {current_token}"},
            )

            if response.status_code == 200:
                data = response.json()
                new_token = data.get("token")
                expires_in = data.get("expiresIn", 7200)  # 默认2小时

                if new_token:
                    with cls._env_lock:
                        cls._token_cache = new_token
                        cls._expires_at = (
                            time.time() + expires_in - 300
                        )  # 提前5分钟过期

                    logger.info(
                        f"Token exchanged successfully, expires in {expires_in} seconds."
                    )
                    return True
                else:
                    logger.error("Token exchange response missing token")
                    cls.clear()
                    return False
            else:
                logger.error(
                    f"Token exchange failed with status {response.status_code}"
                )
                cls.clear()
                return False

        except Exception as e:
            logger.error(f"Token exchange request failed: {e}")
            cls.clear()
            return False


class KeyPairLoader:
    _private_key: None | rsa.RSAPrivateKey = None
    _public_key: None | str = None
    _loaded: bool = False
    _lock: threading.RLock = threading.RLock()
    _adapter_cache: LRUCache = LRUCache()
    _http_client: HTTPClient = HTTPClient(10, 50, 180)

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def load(cls) -> bool:
        if cls._loaded:
            return True

        with cls._lock:
            if cls._loaded:  # 双重检查
                return True

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
                cls._loaded = True
                logger.info("Keys Correctly Loaded")
                return True

            except Exception as e:
                logger.error(f"Key loading failed: {e}")
                return False

    @classmethod
    def exchange(
        cls, api_key: str | None, app_token: str | None
    ) -> None | dict[str, str]:
        if cls._public_key is None or cls._private_key is None:
            logger.error("Keys not loaded")
            return None

        if not all([Config.APP_BASE_URL, api_key, app_token]):
            logger.error("Invalid request params")
            return None

        cache_key = f"{api_key}:{app_token}"
        cached_entry = cls._adapter_cache.get(cache_key)
        if cached_entry:
            return cached_entry.data

        headers = {
            "authorization": f"Bearer {app_token}",
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }
        data = {"public_key": cls._public_key}
        try:
            response = cls._http_client.post(  # type: ignore
                f"{Config.APP_BASE_URL}/api/adapters", headers=headers, json=data
            )
            response.raise_for_status()  # Raise an exception for bad status codes
        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None

        try:
            response_data = response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            return None

        result: dict[str, str] = {}
        try:
            required_fields = ["uid", "url", "mid", "enc"]
            if not all(field in response_data for field in required_fields):
                raise KeyError("Missing required fields in response")

            result["uid"] = response_data["uid"]
            result["url"] = response_data["url"]
            result["mid"] = response_data["mid"]

            message_bytes = base64.b64decode(response_data["enc"])
            try:
                message_decrypted: bytes = cls._private_key.decrypt(
                    message_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except ValueError as e:
                logger.error(f"Decryption failed: {e}")
                return None
            result["key"] = message_decrypted.decode("utf-8")
            cache_entry = AdapterCacheEntry(
                data=result, timestamp=time.time(), ttl=Config.LRU_MAX_CACHE_TTL
            )
            cls._adapter_cache.set(cache_key, cache_entry)
            return result
        except KeyError as e:
            logger.error(f"Missing key in response data: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing adapter response: {e}")
            return None

    @classmethod
    def cleanup_cache(cls):
        cls._adapter_cache.clear_expired()

    @classmethod
    def unload(cls):
        with cls._lock:
            cls._private_key = None
            cls._public_key = None
            cls._loaded = False
            cls._adapter_cache = LRUCache()


class StatusReporter:
    _request_counter: ThreadSafeCounter = ThreadSafeCounter()

    @classmethod
    def upload(cls, http_client: HTTPClient, app_token: str | None) -> bool:
        """
        Returns True if successful, False otherwise.
        """
        if not all(
            [
                Config.APP_BASE_URL,
                Config.PROXY_SERVER_URL,
                Config.PROXY_SERVER_ID,
            ]
        ):
            logger.error("Missing upload required environment variables")
            return False
        if app_token is None:
            logger.error("Invalid request params")
            return False

        request_count = cls._request_counter.get_and_reset()
        if request_count < 100:
            status: Literal["unavailable", "spare", "busy", "full"] = "spare"
        elif request_count < 500:
            status = "busy"
        else:
            status = "full"
        data = {
            "url": Config.PROXY_SERVER_URL,
            "status": status,
            "ex": 14400,  # seconds = 4 hour
            "adv": Config.PROXY_SERVER_ADVANCED == 1,
        }
        headers = {
            "Authorization": f"Bearer {app_token}",
            "Content-Type": "application/json",
        }
        try:
            response = http_client.post(  # type: ignore
                f"{Config.APP_BASE_URL}/api/providers/{Config.PROXY_SERVER_ID}",
                json=data,
                headers=headers,
            )
            response.raise_for_status()  # Raise an exception for bad status codes
            logger.info("Status update succeed.")
            return True
        except requests.RequestException as e:
            logger.error(f"Status update failed: {e}")
            return False

    @classmethod
    def update(cls):
        """
        Trigger per request
        """
        cls._request_counter.increment()


class OptimizedScheduler:
    """Stable-first scheduler"""

    _running: bool = False
    _thread: threading.Thread | None = None
    _executor: ThreadPoolExecutor = ThreadPoolExecutor(
        max_workers=Config.MAX_WORKERS, thread_name_prefix="Scheduler"
    )

    _next_token_rotation: float = Config.SCHEDULE_TOKEN_ROTATION_INTERVAL * 60
    _next_status_report: float = 0
    _next_cache_cleanup: float = 0

    _http_client: HTTPClient = HTTPClient(10, 10, 90)

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def start(cls):
        if cls._running:
            return
        cls._running = True
        cls._thread = threading.Thread(
            target=cls._run_scheduler,
            daemon=True,
        )
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False
        if cls._thread:
            cls._thread.join(timeout=5)
        cls._executor.shutdown(wait=False)

    @classmethod
    def _run_scheduler(cls):
        while cls._running:
            now = time.time()
            try:
                if now >= cls._next_token_rotation:
                    cls._executor.submit(TokenRotator.rotate, cls._http_client)
                    cls._next_token_rotation = (
                        now + Config.SCHEDULE_TOKEN_ROTATION_INTERVAL * 60
                    )

                if now >= cls._next_status_report:
                    cls._executor.submit(
                        StatusReporter.upload, cls._http_client, TokenRotator.token()
                    )
                    cls._next_status_report = (
                        now + Config.SCHEDULE_STATUS_REPORT_INTERVAL * 60
                    )

                if now >= cls._next_cache_cleanup:
                    KeyPairLoader.cleanup_cache()
                    cls._next_cache_cleanup = now + 3600
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            time.sleep(30)


# This file includes the custom callbacks for LiteLLM Proxy
# Once defined, these can be passed in config.yaml
class FlexiProxyCustomHandler(
    CustomLogger
):  # https://docs.litellm.ai/docs/observability/custom_callback#callback-class
    # Class variables or attributes

    def __init__(self):
        KeyPairLoader.load()
        OptimizedScheduler.start()

    def __del__(self):
        OptimizedScheduler.stop()
        KeyPairLoader.unload()
        TokenRotator.clear()

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
        # Validate data structure
        if "secret_fields" not in data:
            return "[secret_fields] field not found in data"

        if "raw_headers" not in data["secret_fields"]:
            return '[raw_headers] field not found in data["secret_fields"]'

        raw_headers: dict | None = data["secret_fields"]["raw_headers"]
        if raw_headers is None:
            return "[raw_headers] field is invalid"

        # Extract client API key from headers
        client_api_key = None
        if "x-api-key" in raw_headers:
            client_api_key = raw_headers["x-api-key"]
        elif (
            "authorization" in raw_headers
            and isinstance(raw_headers["authorization"], str)
            and str(raw_headers["authorization"]).startswith("Bearer ")
        ):
            client_api_key = str(raw_headers["authorization"]).replace("Bearer ", "")

        # Validate client API key
        if client_api_key is None:
            return "Client API key not found in headers"

        # Request key pair information
        response = KeyPairLoader.exchange(
            api_key=client_api_key, app_token=TokenRotator.token()
        )
        if response is None:
            return "Internal Error"

        # Update data with response information
        data["api_base"] = response["url"]
        data["api_key"] = response["key"]
        data["model"] = response["mid"]

        # Update request counter
        StatusReporter.update()
        return data


proxy_handler_instance = FlexiProxyCustomHandler()
