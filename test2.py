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


def edge_expiry_test(
    max_workers: int = 50,
    num_tasks: int = 500,
    mock_mode: bool = True,
    expires_offset: int = 10,  # 初始过期偏移（秒），用于预热
    expiry_delay: float = 1.1,  # 过期后等待时间
) -> bool:
    """
    边缘测试：轻微过期触发旋转。
    - 预热有效token（短过期）。
    - 设置_expires_at刚好过期，然后高并发调用。
    - Mock模式：模拟HTTP返回新token。
    - 预期：1次旋转，所有最终用新token，一致性高。
    """
    http_client = HTTPClient()
    initial_token = initialize_valid_token(http_client, mock_mode, expires_offset)
    if not initial_token:
        print("Failed to initialize token; aborting test.")
        http_client.close()
        return False

    # 准备mock旋转（如果mock_mode）
    original_post = None
    new_mock_token = "new_mock_token_67890"  # 模拟新token
    if mock_mode:
        # Patch http_client.post：模拟/exchange成功
        original_post = http_client.post  # type: ignore

        def mock_post(url, **kwargs):
            if "/api/auth/exchange" in url:
                # 模拟200响应，带新token和过期时间
                import json

                fake_response = type(
                    "Response",
                    (),
                    {
                        "status_code": 200,
                        "json": lambda: {"token": new_mock_token, "expiresIn": 7200},
                    },
                )()
                logger.info("Mock rotation: returning new token")
                return fake_response
            return original_post(url, **kwargs)  # 其他调用用原方法

        http_client.post = mock_post

    # 触发轻微过期
    with TokenRotator._env_lock:
        TokenRotator._expires_at = time.time() + 1  # 1s后过期
    logger.info("Set near expiry; starting test...")

    time.sleep(expiry_delay)  # 确保过期（可调为1.1s）

    # 初始化统计变量
    failed_details = []
    total_exceptions = 0
    rotation_count = 0  # 计数不一致（表示旋转发生）
    all_tokens = set()  # 收集所有返回token
    results = []
    start_time = time.time()

    def simple_token_call():
        """简单token调用：收集token，检查是否旋转（token变化）。"""
        nonlocal total_exceptions, rotation_count, all_tokens  # 新增all_tokens到nonlocal（如果在except中用）
        thread_name = threading.current_thread().name

        try:
            token = TokenRotator.token(http_client)
            if token is None:
                failed_details.append(f"Thread {thread_name}: Got None")  # type: ignore
                return None
            elif not isinstance(token, str) or len(token) == 0:
                failed_details.append(f"Thread {thread_name}: Invalid token '{token[:20]}...'")  # type: ignore
                return None

            all_tokens.add(token)  # 收集用于一致性检查# type: ignore
            # 检查是否与初始不一致（表示旋转）
            if token != initial_token:
                rotation_count += 1
                logger.debug(
                    f"Thread {thread_name}: Detected rotation (new token: {token[:10]}...)"
                )
            return token
        except Exception as e:
            failed_details.append(f"Thread {thread_name}: Exception '{e}'")  # type: ignore
            total_exceptions += 1
            return None

    # 运行executor
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(simple_token_call) for _ in range(num_tasks)]
        for future in concurrent.futures.as_completed(
            futures, timeout=300
        ):  # 总超时5min
            try:
                result = future.result(timeout=30)  # 每个30s超时
                results.append(result)  # type: ignore
            except concurrent.futures.TimeoutError:
                logger.warning("Task timeout")
                total_exceptions += 1
                results.append(None)  # type: ignore
            except Exception as e:
                logger.error(f"Future exception: {e}")
                total_exceptions += 1
                results.append(None)  # type: ignore

    end_time = time.time()

    # 恢复原post（如果mock）
    if mock_mode and original_post:
        http_client.post = original_post

    http_client.close()

    # 统计
    valid_results = [r for r in results if isinstance(r, str) and len(r) > 0]
    success_rate = len(valid_results) / num_tasks
    failed_count = num_tasks - len(valid_results)
    throughput = num_tasks / (end_time - start_time)
    consistency_ok = len(all_tokens) <= 2  # 允许初始 + 新token

    print(f"Edge Expiry Test Results:")
    print(f"  Workers: {max_workers}, Tasks: {num_tasks}, Mock: {mock_mode}")
    print(f"  Initial token: {initial_token[:20]}... (length: {len(initial_token)})")
    print(f"  Success rate: {success_rate:.4f} ({int(success_rate * 100)}%)")
    print(f"  Time: {end_time - start_time:.2f}s, Throughput: {throughput:.2f} calls/s")
    print(
        f"  Valid tokens: {len(valid_results)}, Unique tokens: {len(all_tokens)} (consistent: {consistency_ok})"
    )
    print(
        f"  Total failures: {failed_count}, Exceptions: {total_exceptions}, Detected rotations: {rotation_count}"
    )
    if failed_details:
        print(f"  Failed details (first 5): {failed_details[:5]}")

    # 成功标准：>95%成功 + 一致性（<=2 unique） + rotations ≈1（至少有旋转，但不多）
    # 修复：用max_workers替换num_workers
    test_success = (
        success_rate > 0.95 and consistency_ok and 0 < rotation_count <= max_workers
    )  # 允许最多workers次，但预期1
    print(f"  Test passed: {test_success}")
    return test_success


def high_concurrency_token_test(
    max_workers: int = 50,
    num_tasks: int = 1000,
    mock_mode: bool = False,  # 新增：mock避免HTTP
    # 移除add_variance和rotation_interval_secs，因为焦点是“无旋转”
) -> bool:
    """
    修改版：高并发测试正常token返回（预设有效缓存，无旋转触发）。
    - 焦点：所有调用返回相同有效token，无异常/旋转。
    - 先初始化缓存，然后高并发读取。
    - mock_mode: True用假token（无HTTP，纯锁测试）。
    - 成功标准：>99%成功 + 所有token一致 + 旋转次数=0。
    """
    http_client = HTTPClient()
    initial_token = initialize_valid_token(http_client, mock_mode=mock_mode)
    if initial_token is None:
        print("Failed to initialize token; aborting test.")
        http_client.close()
        return False

    failed_details = []
    total_exceptions = 0
    rotation_count = 0  # 假设无旋转；实际用日志计数，如果>0则警告
    all_tokens = set()  # 检查一致性
    start_time = time.time()

    def simple_token_call():
        """简单token调用：纯读取缓存，无variance/过期。"""
        nonlocal total_exceptions, rotation_count
        thread_name = threading.current_thread().name
        # 新增：模拟微延迟（0-1ms）
        time.sleep(random.uniform(0, 0.001))
        logger.debug(f"Thread {thread_name}: Entering token call with delay")

        try:
            token = TokenRotator.token(http_client)
            if token is None:
                failed_details.append(f"Thread {thread_name}: Got None")  # type: ignore
                return None
            elif not isinstance(token, str) or len(token) == 0:
                failed_details.append(f"Thread {thread_name}: Invalid token")  # type: ignore
                return None

            all_tokens.add(token)  # type: ignore # 收集用于一致性检查
            # 检查是否与初始一致（忽略mock的长度）
            if token != initial_token:
                failed_details.append(  # type: ignore
                    f"Thread {thread_name}: Token mismatch (expected {initial_token[:10]}..., got {token[:10]}...)"
                )
                rotation_count += 1  # 可能旋转导致不一致
            return token
        except Exception as e:
            failed_details.append(f"Thread {thread_name}: Exception '{e}'")  # type: ignore
            total_exceptions += 1
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(simple_token_call) for _ in range(num_tasks)]
        results = []
        for future in concurrent.futures.as_completed(futures, timeout=300):
            try:
                result = future.result(timeout=30)
                results.append(result)  # type: ignore
            except concurrent.futures.TimeoutError:
                print("Task timeout")
                total_exceptions += 1
                results.append(None)  # type: ignore
            except Exception as e:
                print(f"Future exception: {e}")
                total_exceptions += 1
                results.append(None)  # type: ignore

    end_time = time.time()
    http_client.close()

    # 统计
    valid_tokens = [r for r in results if isinstance(r, str) and len(r) > 0]
    success_rate = len(valid_tokens) / len(results)
    failed_count = len(results) - len(valid_tokens)
    throughput = num_tasks / (end_time - start_time)
    consistency_ok = len(all_tokens) <= 1  # 所有token相同（0或1个唯一值）

    # 旋转检查：理想=0；如果>0，说明有意外旋转
    # 注意：rotation_count基于不一致计数；实际可从日志grep "Starting token rotation"

    print(f"High Concurrency Token Test Results (No Rotation Focus):")
    print(f"  Workers: {max_workers}, Tasks: {num_tasks}, Mock: {mock_mode}")
    print(f"  Initial token: {initial_token[:20]}... (length: {len(initial_token)})")
    print(f"  Success rate: {success_rate:.4f} ({int(success_rate * 100)}%)")
    print(f"  Time: {end_time - start_time:.2f}s, Throughput: {throughput:.2f} calls/s")
    print(
        f"  Valid tokens: {len(valid_tokens)}, Unique tokens: {len(all_tokens)} (consistent: {consistency_ok})"
    )
    print(
        f"  Total failures: {failed_count}, Exceptions: {total_exceptions}, Estimated rotations: {rotation_count}"
    )

    if failed_details:
        print(f"  Failed details (first 5): {failed_details[:5]}")

    # 成功标准：高成功率 + 一致性 + 无旋转
    test_success = success_rate > 0.99 and consistency_ok and rotation_count == 0
    print(f"  Test passed: {test_success}")
    return test_success


# 运行示例（修改后）
if __name__ == "__main__":
    print(
        "Running modified high concurrency test (focus on normal returns, no rotation)..."
    )

    # # 小规模测试（真实HTTP，如果环境支持）
    # is_success_small = high_concurrency_token_test(
    #     max_workers=20, num_tasks=200, mock_mode=False  # False: 用真实初始交换
    # )
    # print(f"Small test (real): {is_success_small}")

    # # 高规模测试（mock模式，便于本地无服务器）
    # is_success_high = high_concurrency_token_test(
    #     max_workers=100, num_tasks=2000, mock_mode=True  # True: 纯锁/缓存测试
    # )
    # print(f"High test (mock): {is_success_high}")

    is_success_small = (
        edge_expiry_test()
    )  # high_concurrency_token_test(100, 2000, mock_mode=True)
    print(f"Small test (real): {is_success_small}")

    # 如果有真实环境，试高并发真实模式（无mock）
    # is_success_real_high = high_concurrency_token_test(100, 2000, mock_mode=False)
    # print(f"High test (real): {is_success_real_high}")
