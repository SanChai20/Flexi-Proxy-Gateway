from __future__ import annotations

import json
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
        if "fp_mid" not in user_api_key_dict.metadata or "fp_key" not in user_api_key_dict.metadata:  # type: ignore
            return "Internal Error"

        mid = user_api_key_dict.metadata.pop("fp_mid", None)  # type: ignore
        key = user_api_key_dict.metadata.pop("fp_key", None)  # type: ignore
        if not all([mid, key]):
            return "Internal Error"

        data["api_key"] = key
        data["model"] = mid

        llm = user_api_key_dict.metadata.pop("fp_llm", None)  # type: ignore
        if llm is not None and llm.strip():  # type: ignore
            try:
                llm_params = json.loads(llm)  # type: ignore
            except json.JSONDecodeError:
                return "Invalid LLM Params Format"

            if "litellm_params" not in data:
                data["litellm_params"] = llm_params
            else:
                data["litellm_params"] = {**data["litellm_params"], **llm_params}

        return data


proxy_handler_instance = FlexiProxyCustomHandler()
