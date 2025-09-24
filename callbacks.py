import atexit  # 新增: 用于 shutdown
import base64
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Literal, Optional

import requests
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

    # 新增: 其他硬编码
    TOKEN_EXPIRES_DEFAULT = int(os.getenv("TOKEN_EXPIRES_DEFAULT", "7200"))
    CLEANUP_INTERVAL = int(os.getenv("CLEANUP_INTERVAL", "3600"))
    STATUS_REPORT_EXPIRES = int(os.getenv("STATUS_REPORT_EXPIRES", "7200"))
    HTTP_RETRY_BACKOFF = float(os.getenv("HTTP_RETRY_BACKOFF", "0.5"))


@dataclass
class AdapterCacheEntry:
    data: Dict[str, str]
    timestamp: float
    ttl: int


class LRUCache:
    """Thread-safe LRU + TTL Cache"""

    def __init__(self):
        self._cache: Dict[str, "AdapterCacheEntry"] = {}
        self._lock = threading.RLock()
        self._order: list[str] = []  # 简单 LRU 实现（生产用 cachetools）

    def get(self, key: str) -> Optional["AdapterCacheEntry"]:
        with self._lock:
            if key not in self._cache:
                return None
            entry = self._cache[key]
            if time.time() - entry.timestamp > entry.ttl:
                del self._cache[key]
                self._order.remove(key)
                return None
            # Move to end (LRU)
            self._order.remove(key)
            self._order.append(key)
            return entry

    def set(self, key: str, value: "AdapterCacheEntry"):
        with self._lock:
            if key in self._cache:
                self._order.remove(key)
            elif len(self._cache) >= Config.LRU_MAX_CACHE_SIZE:
                old_key = self._order.pop(0)
                del self._cache[old_key]
            self._cache[key] = value
            self._order.append(key)

    def clear_expired(self):
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._cache.items() if now - v.timestamp > v.ttl]
            for k in expired:
                del self._cache[k]
                if k in self._order:
                    self._order.remove(k)


class ThreadSafeCounter:
    """Thread-safe counter"""

    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()
        self._total = 0  # 新增: 累计总计

    def increment(self) -> int:
        with self._lock:
            self._value += 1
            self._total += 1
            return self._value

    def get_and_report(
        self,
    ) -> tuple[int, float]:  # 改: 返回周期 + 平均 (total / cycles)
        with self._lock:
            current = self._value
            avg = (
                self._total / max(1, self._report_count)
                if hasattr(self, "_report_count")
                else 0
            )
            self._value = 0
            if not hasattr(self, "_report_count"):
                self._report_count = 0
            self._report_count += 1
            return current, avg

    def get(self) -> int:
        with self._lock:
            return self._value


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

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._request("POST", url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request("GET", url, **kwargs)

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
        with cls._env_lock:
            if cls._token_cache is not None and time.time() < cls._expires_at:
                return cls._token_cache
            # Fallback to env, but log warning
            if Config.APP_TOKEN_PASS:
                logger.warning("Using fallback token from env (may be expired)")
                return Config.APP_TOKEN_PASS
            logger.error("No valid token available")
            return None

    @classmethod
    def clear(cls) -> None:
        with cls._env_lock:
            cls._token_cache = None
            cls._expires_at = 0

    @classmethod
    @retry()  # 加重试
    def rotate(cls, http_client: HTTPClient) -> bool:
        if Config.APP_BASE_URL is None:
            logger.error("Missing APP_BASE_URL environment variable")
            return False

        current_token = cls.token()
        if not current_token:
            logger.error("No current token available for exchange")
            return False

        try:
            response = http_client.post(
                url=f"{Config.APP_BASE_URL}/api/auth/exchange",
                headers={"authorization": f"Bearer {current_token}"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError as e:
                    logger.error(f"Failed to parse token response JSON: {e}")
                    return False

                new_token = data.get("token")
                expires_in = data.get("expiresIn", Config.TOKEN_EXPIRES_DEFAULT)

                if new_token:
                    with cls._env_lock:
                        cls._token_cache = new_token
                        cls._expires_at = time.time() + expires_in - 300  # 提前5min

                    logger.info(f"Token rotated successfully, expires in {expires_in}s")
                    return True
                else:
                    logger.error("Token response missing 'token' field")
                    cls.clear()
                    return False
            else:
                logger.error(f"Token rotate failed: {response.status_code}")
                cls.clear()
                return False

        except requests.RequestException as e:
            logger.error(f"Token rotate request failed: {e}")
            cls.clear()
            return False
        except Exception as e:  # 窄: 只 catch 意外
            logger.error(f"Unexpected error in token rotate: {e}")
            return False


class KeyPairLoader:
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None
    _loaded: bool = False
    _lock: threading.RLock = threading.RLock()
    _exchange_locks: Dict[str, threading.Lock] = {}  # 新增: per-key 锁防重复 exchange
    _adapter_cache: LRUCache = LRUCache()
    _http_client = HTTPClient()  # 统一用 Config

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def load(cls) -> bool:
        if cls._loaded:
            return True

        with cls._lock:
            if cls._loaded:
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
    ) -> Optional[Dict[str, str]]:
        # 加锁检查密钥
        with cls._lock:
            if not cls._loaded or cls._public_key is None or cls._private_key is None:
                logger.error("Keys not loaded")
                return None

        if not all([Config.APP_BASE_URL, api_key, app_token]):
            logger.error("Invalid request params")
            return None

        cache_key = f"{api_key}:{app_token}"

        # 先查缓存
        cached_entry = cls._adapter_cache.get(cache_key)
        if cached_entry:
            return cached_entry.data

        # Per-key 锁防重复
        if cache_key not in cls._exchange_locks:
            with cls._lock:  # 原子创建锁
                if cache_key not in cls._exchange_locks:
                    cls._exchange_locks[cache_key] = threading.Lock()
        lock = cls._exchange_locks[cache_key]

        with lock:
            # 双查缓存 (其他线程可能已填充)
            cached_entry = cls._adapter_cache.get(cache_key)
            if cached_entry:
                return cached_entry.data

            # 执行 HTTP
            headers = {
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
                "Content-Type": "application/json",
            }
            data = {"public_key": cls._public_key}
            try:
                response = cls._http_client.post(
                    f"{Config.APP_BASE_URL}/api/adapters", headers=headers, json=data
                )
                response.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"Request failed: {e}")
                return None

            try:
                response_data = response.json()
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                return None

            result: Dict[str, str] = {}
            try:
                required_fields = ["uid", "url", "mid", "enc"]
                if not all(field in response_data for field in required_fields):
                    raise KeyError("Missing required fields in response")

                result["uid"] = response_data["uid"]
                result["url"] = response_data["url"]
                result["mid"] = response_data["mid"]

                message_bytes = base64.b64decode(response_data["enc"])  # 加 try
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

                # 加 try decode
                try:
                    result["key"] = message_decrypted.decode("utf-8")
                except UnicodeDecodeError as e:
                    logger.error(f"Key decode failed: {e}")
                    return None

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
        # 清理旧锁 (可选, 定期)
        if len(cls._exchange_locks) > Config.LRU_MAX_CACHE_SIZE * 2:
            cls._exchange_locks.clear()

    @classmethod
    def unload(cls):
        with cls._lock:
            cls._private_key = None
            cls._public_key = None
            cls._loaded = False
            cls._adapter_cache = LRUCache()
            cls._exchange_locks.clear()
        cls._http_client.close()


class StatusReporter:
    _request_counter: ThreadSafeCounter = ThreadSafeCounter()

    @classmethod
    @retry()
    def upload(cls, http_client: HTTPClient) -> bool:
        if not all(
            [Config.APP_BASE_URL, Config.PROXY_SERVER_URL, Config.PROXY_SERVER_ID]
        ):
            logger.error("Missing upload required environment variables")
            return False

        current_token = TokenRotator.token()
        if not current_token:
            logger.error("No current token available")
            return False

        # 改: 用 get_and_report 获取周期 + 平均
        period_count, avg_count = cls._request_counter.get_and_report()

        # 基于平均 (累计)
        if avg_count < 100:
            status: Literal["unavailable", "spare", "busy", "full"] = "spare"
        elif avg_count < 500:
            status = "busy"
        else:
            status = "full"

        data = {
            "url": Config.PROXY_SERVER_URL,
            "status": status,
            "ex": Config.STATUS_REPORT_EXPIRES,
            "adv": Config.PROXY_SERVER_ADVANCED == 1,
            "avg_requests": avg_count,  # 新增: 上报平均
        }
        headers = {
            "Authorization": f"Bearer {current_token}",
            "Content-Type": "application/json",
        }
        try:
            response = http_client.post(
                f"{Config.APP_BASE_URL}/api/providers/{Config.PROXY_SERVER_ID}",
                json=data,
                headers=headers,
            )
            response.raise_for_status()
            logger.info("Status update succeed.")
            return True
        except requests.RequestException as e:
            logger.error(f"Status update failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected status update error: {e}")
            return False

    @classmethod
    def update(cls):
        cls._request_counter.increment()


class OptimizedScheduler:
    """Stable-first scheduler"""

    _running: bool = False
    _thread: Optional[threading.Thread] = None
    _executor: Optional[ThreadPoolExecutor] = None
    _lock = threading.Lock()  # 新增: 保护启动/停止

    _next_token_rotation: float = (
        time.time() + Config.SCHEDULE_TOKEN_ROTATION_INTERVAL * 60
    )
    _next_status_report: float = (
        time.time() + Config.SCHEDULE_STATUS_REPORT_INTERVAL * 60
    )  # 改: 延迟首次
    _next_cache_cleanup: float = time.time() + Config.CLEANUP_INTERVAL

    _http_client: HTTPClient = HTTPClient()

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def start(cls):
        with cls._lock:
            if cls._running:
                return
            cls._running = True
            cls._executor = ThreadPoolExecutor(
                max_workers=Config.MAX_WORKERS, thread_name_prefix="Scheduler"
            )
            cls._thread = threading.Thread(target=cls._run_scheduler, daemon=True)
            cls._thread.start()
            atexit.register(cls.stop)  # 新增: 自动 shutdown

    @classmethod
    def stop(cls):
        with cls._lock:
            if not cls._running:
                return
            cls._running = False
            if cls._thread:
                cls._thread.join(timeout=5)
            if cls._executor:
                cls._executor.shutdown(wait=True)  # 改: wait=True
            cls._http_client.close()

    @classmethod
    def _run_scheduler(cls):
        import heapq  # 新增: 精确定时

        events = [  # heap of (time, task_func, args)
            (cls._next_token_rotation, cls._run_token_rotation, ()),
            (cls._next_status_report, cls._run_status_report, ()),
            (cls._next_cache_cleanup, cls._run_cache_cleanup, ()),
        ]
        heapq.heapify(events)

        while cls._running:
            try:
                now = time.time()
                while events and events[0][0] <= now:
                    event_time, task, args = heapq.heappop(events)
                    if cls._running:
                        future = cls._executor.submit(task, *args)
                        future.add_done_callback(
                            lambda f: logger.debug(f"Task {task.__name__} completed")
                        )  # 监控

                    # 重新调度
                    if task == cls._run_token_rotation:
                        new_time = now + Config.SCHEDULE_TOKEN_ROTATION_INTERVAL * 60
                    elif task == cls._run_status_report:
                        new_time = now + Config.SCHEDULE_STATUS_REPORT_INTERVAL * 60
                    else:  # cleanup
                        new_time = now + Config.CLEANUP_INTERVAL
                    heapq.heappush(events, (new_time, task, args))

                if events:
                    sleep_time = events[0][0] - now
                    time.sleep(max(0, sleep_time))
                else:
                    time.sleep(10)  # 防止空转

            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(10)  # 退避

    # 分离任务方法 (便于 submit)
    @classmethod
    @retry()
    def _run_token_rotation(cls):
        TokenRotator.rotate(cls._http_client)

    @classmethod
    @retry()
    def _run_status_report(cls):
        StatusReporter.upload(cls._http_client)

    @classmethod
    def _run_cache_cleanup(cls):
        KeyPairLoader.cleanup_cache()


# This file includes the custom callbacks for LiteLLM Proxy
class FlexiProxyCustomHandler(CustomLogger):
    def __init__(self):
        if not KeyPairLoader.load():
            raise RuntimeError(
                "Failed to load keys. Check key.pem, public.pem and PROXY_SERVER_KEYPAIR_PWD."
            )  # 加验证，抛错
        OptimizedScheduler.start()
        super().__init__()

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        logger.info("Request success")  # 改: 用 logger

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
        # 保持原逻辑，但加 async 兼容 (exchange 同步，但短)
        if "secret_fields" not in data:
            return '"[secret_fields] field not found in data"'

        if "raw_headers" not in data["secret_fields"]:
            return '"[raw_headers] field not found in data["secret_fields"]"'

        raw_headers: Optional[dict] = data["secret_fields"].get("raw_headers")
        if raw_headers is None:
            return '"[raw_headers] field is invalid"'

        # Extract client API key
        client_api_key = None
        if "x-api-key" in raw_headers:
            client_api_key = raw_headers["x-api-key"]
        elif (
            "authorization" in raw_headers
            and isinstance(raw_headers["authorization"], str)
            and raw_headers["authorization"].startswith("Bearer ")
        ):
            client_api_key = raw_headers["authorization"][7:]

        if client_api_key is None:
            return '"Client API key not found in headers"'

        # exchange (同步，但加 timeout? LiteLLM 可处理)
        response = KeyPairLoader.exchange(
            api_key=client_api_key, app_token=TokenRotator.token()
        )
        if response is None:
            return '"Internal Error: Key exchange failed"'

        # Update data
        data["api_base"] = response["url"]
        data["api_key"] = response["key"]
        data["model"] = response["mid"]

        # Update counter (异步安全)
        StatusReporter.update()

        return None  # 成功返回 None (LiteLLM 修改 data)


# 全局实例 (但 LiteLLM 可能创建新，OK)
proxy_handler_instance = FlexiProxyCustomHandler()


# 全局 shutdown (atexit 已注册，但额外)
def shutdown():
    OptimizedScheduler.stop()
    KeyPairLoader.unload()
    TokenRotator.clear()


atexit.register(shutdown)
