# proxy_handler.py - Minimal Production Version
from __future__ import annotations

from typing import Literal

from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy._types import UserAPIKeyAuth


class FlexiProxyCustomHandler(CustomLogger):
    """
    Minimal custom handler for FlexiProxy.

    Responsibilities:
    - Extract FlexiProxy metadata (fp_mid)
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
        """

        try:
            # Validate metadata exists
            if not hasattr(user_api_key_dict, "metadata") or user_api_key_dict.metadata is None:  # type: ignore
                raise ValueError("Internal Error: Missing metadata")

            metadata = user_api_key_dict.metadata  # type: ignore

            # Extract required credentials
            mid = metadata.pop("fp_mid", None)  # type: ignore

            # Validate data is a dictionary
            if not isinstance(data, dict):
                raise ValueError("Internal Error: Invalid data format")

            # Inject model
            data["model"] = mid

            # Validate required fields for specific call types
            if call_type == "completion" and "messages" not in data:
                raise ValueError("Missing required field: messages")

            # Security: Remove sensitive fields
            for field in ["fp_mid", "user_id", "team_id"]:
                data.pop(field, None)  # type: ignore

            return data

        except ValueError:
            raise
        except Exception:
            raise ValueError("Internal Error")


proxy_handler_instance = FlexiProxyCustomHandler()
