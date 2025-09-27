import threading
import time
from typing import Optional

import requests

from .counter import ProxyRequestCounter
from .http import http_client
from .logger import LoggerManager
from .params import Config


class TokenRotator:
    _lock = threading.RLock()
    _condition = threading.Condition(_lock)
    _token_cache: Optional[str] = None
    _expires_at: float = 0
    _initial_exchange_done: bool = False
    _initial_failed: bool = False
    _rotating: bool = False

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def background_refresh(cls, interval: int = 60):
        def _refresher():
            while True:
                time.sleep(interval)
                should_refresh = False
                with cls._lock:
                    now = time.time()
                    if (
                        cls._token_cache is None or now > cls._expires_at - 600
                    ):  # 10分钟窗口
                        should_refresh = True
                if should_refresh:
                    try:
                        LoggerManager.debug(
                            "Background refresher: token nearing expiry, rotating..."
                        )
                        cls.token()
                    except Exception:
                        LoggerManager.error("Background token refresh failed")

        t = threading.Thread(target=_refresher, daemon=True)
        t.start()

    @classmethod
    def token(cls) -> Optional[str]:
        current_token: Optional[str] = None
        was_using_cache: bool = False
        is_initial: bool = False

        while True:
            with cls._lock:
                now = time.time()

                # Check if we have a valid cached token
                if cls._token_cache is not None and now < cls._expires_at:
                    return cls._token_cache

                # Early fallback for initial failure
                if not cls._initial_exchange_done and cls._initial_failed:
                    LoggerManager.warn(
                        "Initial token exchange failed previously; falling back to env token"
                    )
                    return Config.APP_TOKEN_PASS

                # If another thread is rotating, wait for it to complete
                if cls._rotating:
                    LoggerManager.debug("Token rotation in progress; waiting...")
                    cls._condition.wait()
                    continue  # Recheck conditions after wakeup

                # No valid token; start rotation
                current_token = (
                    cls._token_cache
                    if cls._token_cache is not None
                    else Config.APP_TOKEN_PASS
                )
                if current_token is None:
                    LoggerManager.error("No current token available for exchange")
                    return None

                was_using_cache = cls._token_cache is not None
                is_initial = not cls._initial_exchange_done and not was_using_cache
                cls._rotating = True
                LoggerManager.debug("Starting token rotation...")

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
                    except ValueError:
                        LoggerManager.error("Failed to parse token response JSON")
                        raise  # Treat as failure

                    new_token = data.get("token")
                    expires_in = data.get("expiresIn")

                    if new_token and expires_in is not None:
                        success_token = new_token
                        new_expires_at = (
                            time.time() + expires_in - 300
                        )  # 5-minute buffer
                        LoggerManager.info("Token rotated successfully")
                    else:
                        LoggerManager.error("Token response missing field")
                        raise  # Treat as failure
                else:
                    LoggerManager.error(f"Token rotate failed: {response.status_code}")
                    raise  # Treat as failure

            except requests.RequestException:  # Adjust exception if HTTPClient differs
                LoggerManager.error("Token rotate request failed")
            except Exception:
                LoggerManager.error("Unexpected error in token rotate")

            # Update state after exchange attempt
            with cls._lock:
                cls._rotating = False
                if success_token:
                    cls._token_cache = success_token
                    cls._expires_at = new_expires_at
                    if is_initial:
                        cls._initial_exchange_done = True
                    cls._initial_failed = False
                    cls._condition.notify_all()
                    LoggerManager.debug("Token rotation completed; notified waiters")
                    return success_token  # Rotator returns the new token directly
                else:
                    # Failure handling
                    if is_initial:
                        cls._initial_failed = True
                        LoggerManager.warn(
                            "Initial token exchange failed; will fallback to env token on future calls"
                        )
                    elif was_using_cache:
                        # For non-initial failures, clear the invalid cache
                        cls._token_cache = None
                        cls._expires_at = 0
                        LoggerManager.warn(
                            "Cleared invalid cached token after rotation failure"
                        )
                    cls._condition.notify_all()
                    LoggerManager.debug("Token rotation failed; notified waiters")

    @classmethod
    def clear(cls) -> None:
        """Clear the cached token, forcing a rotation on next token() call."""
        with cls._lock:
            cls._token_cache = None
            cls._expires_at = 0
