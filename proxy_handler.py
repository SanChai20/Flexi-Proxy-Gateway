from __future__ import annotations

from typing import Literal

from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy._types import UserAPIKeyAuth


# This file includes the custom callbacks for LiteLLM Proxy
class FlexiProxyCustomHandler(CustomLogger):

    def __init__(self):
        super().__init__(True)  # type: ignore

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
        if "fp_url" not in user_api_key_dict.metadata or "fp_mid" not in user_api_key_dict.metadata or "fp_key" not in user_api_key_dict.metadata:  # type: ignore
            return "Internal Error"
        data["api_key"] = user_api_key_dict.metadata.pop("fp_key")  # type: ignore
        data["api_base"] = user_api_key_dict.metadata.pop("fp_url")  # type: ignore
        data["model"] = user_api_key_dict.metadata.pop("fp_mid")  # type: ignore
        return data


proxy_handler_instance = FlexiProxyCustomHandler()
