# proxy_handler.py - Minimal Production Version
from __future__ import annotations

import json
from typing import Literal

from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy._types import UserAPIKeyAuth


class FlexiProxyCustomHandler(CustomLogger):
    """
    Minimal custom handler for FlexiProxy.

    Responsibilities:
    - Extract FlexiProxy metadata (fp_mid, fp_key, fp_llm)
    - Inject API key and model into request
    - Merge custom litellm_params
    """

    def __init__(self):
        super().__init__(True)  # type: ignore

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
        """
        Pre-call hook to inject FlexiProxy credentials and parameters.

        Extracts from user_api_key_dict.metadata:
        - fp_mid: Target model ID
        - fp_key: API key for the provider
        - fp_llm: Custom litellm_params (JSON string)
        """

        try:
            # Validate metadata exists
            if not hasattr(user_api_key_dict, "metadata") or user_api_key_dict.metadata is None:  # type: ignore
                raise ValueError("Internal Error: Missing metadata")

            metadata = user_api_key_dict.metadata  # type: ignore

            # Extract required credentials
            mid = metadata.pop("fp_mid", None)  # type: ignore
            key = metadata.pop("fp_key", None)  # type: ignore

            if not mid or not key:
                raise ValueError("Internal Error: Missing credentials")

            # Validate data is a dictionary
            if not isinstance(data, dict):
                raise ValueError("Internal Error: Invalid data format")

            # Inject API key and model
            data["api_key"] = key
            data["model"] = mid

            # Process custom litellm_params if provided
            llm = metadata.pop("fp_llm", None)  # type: ignore
            if llm and isinstance(llm, str) and llm.strip():
                try:
                    llm_params = json.loads(llm)

                    if isinstance(llm_params, dict):
                        # Merge litellm_params
                        if "litellm_params" not in data:
                            data["litellm_params"] = llm_params
                        else:
                            existing_params = data.get("litellm_params", {})  # type: ignore
                            if isinstance(existing_params, dict):
                                data["litellm_params"] = {
                                    **existing_params,
                                    **llm_params,
                                }
                            else:
                                data["litellm_params"] = llm_params

                except json.JSONDecodeError:
                    raise ValueError("Invalid LLM Params Format")

            # Validate required fields for specific call types
            if call_type == "completion" and "messages" not in data:
                raise ValueError("Missing required field: messages")

            # Security: Remove sensitive fields
            for field in ["fp_mid", "fp_key", "fp_llm", "user_id", "team_id"]:
                data.pop(field, None)  # type: ignore

            return data

        except ValueError:
            raise
        except Exception:
            raise ValueError("Internal Error")


proxy_handler_instance = FlexiProxyCustomHandler()
