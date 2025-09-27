from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

import requests
from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy._types import UserAPIKeyAuth

from core import (
    Config,
    KeyPairLoader,
    LoggerManager,
    ProxyRequestCounter,
    TimestampedLRUCache,
    TokenRotator,
    http_client,
)


class PreCallResponse(Enum):
    COMPATIBILITY = "Compatibility Issue"
    AUTHORIZATION = "Authorization Issue"
    INTERNAL = "Internal Error"
    RATELIMIT = "Rate Limits Reached"


KeyPairLoader.unload()
if not KeyPairLoader.load():
    raise RuntimeError(
        "Failed to load keys. Check key.pem, public.pem and PROXY_SERVER_KEYPAIR_PWD."
    )

TokenRotator.clear()
TokenRotator.background_refresh(10)


# This file includes the custom callbacks for LiteLLM Proxy
class FlexiProxyCustomHandler(CustomLogger):
    _adp_cache: "TimestampedLRUCache"

    def __init__(self):
        super().__init__(True)  # type: ignore
        self._adp_cache = TimestampedLRUCache(maxsize=Config.LRU_MAX_CACHE_SIZE)

    #### CALL HOOKS ####

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        pass  # logger.info("Request success")

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        pass  # logger.error("Request failure")

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        pass  # logger.info("Async request success")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        pass  # logger.error("Async request failure")

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
        fp_token = user_api_key_dict.token
        if fp_token is None:
            LoggerManager.error("Api Key / Token not valid")
            return PreCallResponse.AUTHORIZATION

        adp_cache_entry: Optional[dict[str, Any]] = self._adp_cache[fp_token]
        if adp_cache_entry is None:
            fp_key = user_api_key_dict.api_key
            app_token: Optional[str] = TokenRotator.token()
            if app_token is None or fp_key is None:
                LoggerManager.error("Invalid app token / key")
                return PreCallResponse.INTERNAL
            try:
                response: requests.Response = http_client.get(
                    f"{Config.APP_BASE_URL}/api/adapters",
                    headers={
                        "authorization": f"Bearer {app_token}",
                        "X-API-Key": fp_key,
                    },
                )
                response.raise_for_status()
            except requests.RequestException:
                LoggerManager.error("Request failed")
                return PreCallResponse.INTERNAL

            try:
                response_data = response.json()
                data["api_base"] = response_data["url"]
                data["model"] = response_data["mid"]
                self._adp_cache[fp_token] = response_data
            except KeyError:
                LoggerManager.error("Missing key in response data")
                return PreCallResponse.INTERNAL
            except ValueError:
                LoggerManager.error("Failed to parse JSON response")
                return PreCallResponse.INTERNAL
            except Exception:
                LoggerManager.error("Error processing adapter response")
                return PreCallResponse.INTERNAL
        else:
            data["api_base"] = adp_cache_entry["url"]
            data["model"] = adp_cache_entry["mid"]

        ProxyRequestCounter.increment()
        return data


proxy_handler_instance = FlexiProxyCustomHandler()
