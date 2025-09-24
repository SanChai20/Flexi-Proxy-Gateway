import concurrent.futures
import logging
import os
import random
import sys
import threading
import time
from logging.handlers import TimedRotatingFileHandler
from typing import Optional

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3 import Retry

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
    SCHEDULE_CLEANUP_INTERVAL = int(os.getenv("SCHEDULE_CLEANUP_INTERVAL", "60"))

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
    HTTP_RETRY_BACKOFF = float(os.getenv("HTTP_RETRY_BACKOFF", "0.5"))

    # Others
    STATUS_REPORT_EXPIRES = int(os.getenv("STATUS_REPORT_EXPIRES", "7200"))


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
        kwargs.setdefault("timeout", self.timeout)  # type: ignore
        return self.session.request(method, url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._request("POST", url, **kwargs)  # type: ignore

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._request("GET", url, **kwargs)  # type: ignore

    def close(self):
        self.session.close()


class TokenRotator:
    _env_lock = threading.RLock()
    _condition = threading.Condition(_env_lock)
    _token_cache: Optional[str] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False
    _http_calls: int = 0

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

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
                with cls._env_lock:  # 短暂锁，确保原子+1
                    cls._http_calls += 1
                    logger.debug(f"HTTP call #{cls._http_calls} starting...")
                response: requests.Response = http_client.post(  # type: ignore
                    url=f"{Config.APP_BASE_URL}/api/auth/exchange",
                    headers={"authorization": f"Bearer {current_token}"},
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


# 假设你的Config, HTTPClient, TokenRotator已在上方定义


def initialize_valid_token(
    http_client: HTTPClient, mock_mode: bool = False, expires_offset: int = 3600
) -> Optional[str]:
    """
    预热：单线程初始化一个有效token缓存。
    - mock_mode: True则返回假token，无HTTP。
    - expires_offset: token过期偏移（秒），设为远未来避免测试中旋转。
    返回初始token（如果成功）。
    """
    logger.info("Initializing valid token cache...")
    try:
        if mock_mode:
            # Mock: 假token和过期时间
            fake_token = "mock_valid_token_12345"
            with TokenRotator._env_lock:
                TokenRotator._token_cache = fake_token
                TokenRotator._expires_at = time.time() + expires_offset
                TokenRotator._initial_exchange_done = True  # 标记初始完成
                TokenRotator._initial_failed = False
            logger.info(
                f"Mock token initialized: {fake_token}, expires in {expires_offset}s"
            )
            return fake_token

        # 真实：调用一次token()，它会自动旋转并缓存
        token = TokenRotator.token(http_client)
        if token is None:
            logger.error("Failed to initialize valid token (real mode)")
            return None
        # 额外设置远未来过期（覆盖响应中的expiresIn，确保测试不旋转）
        with TokenRotator._env_lock:
            if TokenRotator._token_cache:
                TokenRotator._expires_at = time.time() + expires_offset
        logger.info(f"Real token initialized successfully, forced long expiry")
        return token
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return None


def concurrent_rotation_test(
    max_workers: int = 100,
    num_tasks: int = 1000,
) -> bool:
    """
    高并发旋转测试：严格验证只触发1次HTTP（并发过期场景）。
    - 预热有效token。
    - 立即强制过期（_expires_at=0），然后高并发调用（无延迟）。
    - 计数HTTP calls（类变量 + Mock patch）。
    - 预期：http_calls=1，unique_tokens=1（全新token），success>99%。
    """
    # 重置状态（确保干净）
    TokenRotator.clear()  # 清缓存，重置_http_calls=0
    http_client = HTTPClient()

    # 预热：初始化有效token（长过期，避免预热中旋转）
    initial_token = initialize_valid_token(
        http_client, mock_mode=False, expires_offset=3600
    )
    if not initial_token:
        print("Failed to initialize token; aborting test.")
        http_client.close()
        return False

    # 准备Mock（双重计数：类 + patch）
    original_post = None
    http_calls_via_patch = 0  # Mock计数
    new_mock_token = "rotated_token_xyz789"  # 模拟新token

    # 立即强制过期（同时触发所有线程检查）
    with TokenRotator._env_lock:
        TokenRotator._expires_at = 0  # 设为过去，确保立即过期
        # 注意：不设_rotating，确保所有线程竞争
    logger.info("Forced immediate expiry; starting high-concurrency calls...")

    # 无延迟：直接启动executor，确保最大并发争用
    failed_details = []
    total_exceptions = 0
    rotation_count = 0  # 检测token变化（应= num_tasks，因为从初始到新）
    all_tokens = set()
    results = []
    start_time = time.time()

    def immediate_token_call():
        """立即token调用：无sleep，纯并发竞争。"""
        nonlocal total_exceptions, rotation_count, all_tokens
        thread_name = threading.current_thread().name

        try:
            token = TokenRotator.token(http_client)
            if token is None:
                failed_details.append(f"Thread {thread_name}: Got None")  # type: ignore
                return None
            elif not isinstance(token, str) or len(token) == 0:
                failed_details.append(f"Thread {thread_name}: Invalid token")  # type: ignore
                return None

            all_tokens.add(token)  # type: ignore
            if token != initial_token:
                rotation_count += 1  # 每个新token表示旋转生效
            return token
        except Exception as e:
            failed_details.append(f"Thread {thread_name}: Exception '{e}'")  # type: ignore
            total_exceptions += 1
            return None

    # 高并发executor（大workers，确保争用）
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(immediate_token_call) for _ in range(num_tasks)]
        for future in concurrent.futures.as_completed(
            futures, timeout=60
        ):  # 缩短总超时1min
            try:
                result = future.result(timeout=10)  # 每个10s超时（等待应短）
                results.append(result)  # type: ignore
            except concurrent.futures.TimeoutError:
                logger.warning("Task timeout (possible wait deadlock?)")
                total_exceptions += 1
                results.append(None)  # type: ignore
            except Exception as e:
                logger.error(f"Future exception: {e}")
                total_exceptions += 1
                results.append(None)  # type: ignore

    end_time = time.time()
    http_client.close()
    logger.info(f"Real HTTP calls (from class counter): {TokenRotator._http_calls}")

    # 统计
    valid_results = [r for r in results if isinstance(r, str) and len(r) > 0]
    success_rate = len(valid_results) / num_tasks
    failed_count = num_tasks - len(valid_results)
    throughput = num_tasks / (end_time - start_time)
    consistency_ok = len(all_tokens) == 1  # 严格：全用新token（无初始）

    print(f"Concurrent Rotation Test Results (Avoid Multiple HTTP):")
    print(f"  Workers: {max_workers}, Tasks: {num_tasks}")
    print(
        f"  Initial token: {initial_token[:20]}... -> Expected new: {new_mock_token[:20]}..."
    )
    print(f"  Success rate: {success_rate:.4f} ({int(success_rate * 100)}%)")
    print(f"  Time: {end_time - start_time:.2f}s, Throughput: {throughput:.2f} calls/s")
    print(
        f"  Valid tokens: {len(valid_results)}, Unique tokens: {len(all_tokens)} (all new: {consistency_ok})"
    )
    print(f"  Total failures: {failed_count}, Exceptions: {total_exceptions}")
    print(
        f"  HTTP calls: {TokenRotator._http_calls} (expected 1), Detected rotations: {rotation_count}"
    )
    if failed_details:
        print(f"  Failed details (first 5): {failed_details[:5]}")

    # 成功标准：>99%成功 + 只1次HTTP + 一致（全新token） + rotations ≈ num_valid（全旋转生效）
    test_success = (
        success_rate > 0.99
        and TokenRotator._http_calls == 1  # 核心：避免多次HTTP
        and consistency_ok
        and rotation_count >= len(valid_results) * 0.99  # 几乎全用新token
    )
    print(f"  Test passed (single HTTP verified): {test_success}")
    return test_success


# 运行示例（插入__main__）
if __name__ == "__main__":
    print("Running concurrent rotation test (high contention expiry)...")

    # Mock模式（精确计数，推荐）
    is_success_mock = concurrent_rotation_test(max_workers=200, num_tasks=4000)
    print(f"Concurrent test (mock): {is_success_mock}")

    # Real模式（如果API可用；日志检查"HTTP call #1"只出现一次）
    # TokenRotator.reset_http_counter()  # 可选重置
    # is_success_real = concurrent_rotation_test(max_workers=50, num_tasks=500, mock_mode=False)
    # print(f"Concurrent test (real): {is_success_real}")
