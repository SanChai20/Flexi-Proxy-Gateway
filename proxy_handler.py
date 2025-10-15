from __future__ import annotations

import json
import time
from typing import Any, Dict, Literal, Optional, Protocol

from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy._types import UserAPIKeyAuth


# Define Protocol for logger to avoid import issues
class LoggerProtocol(Protocol):
    """Protocol for logger interface."""

    @staticmethod
    def info(msg: str, **kwargs) -> None: ...

    @staticmethod
    def warn(msg: str, **kwargs) -> None: ...

    @staticmethod
    def error(msg: str, exc_info: bool = False, **kwargs) -> None: ...

    @staticmethod
    def debug(msg: str, **kwargs) -> None: ...


class MetricsProtocol(Protocol):
    """Protocol for metrics collector interface."""

    @staticmethod
    def increment(metric: str, value: int = 1) -> None: ...


# Import or create fallback implementations
_logger: LoggerProtocol
_metrics: MetricsProtocol

try:
    from proxy_auth import LoggerManager as _LoggerManager
    from proxy_auth import MetricsCollector as _MetricsCollector

    _logger = _LoggerManager
    _metrics = _MetricsCollector

except ImportError:
    # Fallback implementation
    import logging

    class _FallbackLogger:
        """Fallback logger implementation."""

        @staticmethod
        def info(msg: str, **kwargs) -> None:
            logging.info(msg)

        @staticmethod
        def warn(msg: str, **kwargs) -> None:
            logging.warning(msg)

        @staticmethod
        def error(msg: str, exc_info: bool = False, **kwargs) -> None:
            logging.error(msg, exc_info=exc_info)

        @staticmethod
        def debug(msg: str, **kwargs) -> None:
            logging.debug(msg)

    class _FallbackMetrics:
        """Fallback metrics implementation."""

        @staticmethod
        def increment(metric: str, value: int = 1) -> None:
            pass

    _logger = _FallbackLogger()  # type: ignore
    _metrics = _FallbackMetrics()  # type: ignore


# This file includes the custom callbacks for LiteLLM Proxy
class FlexiProxyCustomHandler(CustomLogger):
    """
    Production-ready custom handler for FlexiProxy.

    Features:
    - Comprehensive error handling
    - Performance metrics
    - Request/response logging
    - Parameter validation
    - Security checks
    """

    # Class-level metrics
    _total_requests = 0
    _successful_requests = 0
    _failed_requests = 0
    _total_processing_time: float = 0.0

    def __init__(self):
        super().__init__(True)  # type: ignore
        _logger.info("FlexiProxyCustomHandler initialized")  # type: ignore

    #### CALL HOOKS ####

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Log synchronous success events."""
        try:
            duration = end_time - start_time
            model = kwargs.get("model", "unknown")  # type: ignore

            FlexiProxyCustomHandler._successful_requests += 1
            FlexiProxyCustomHandler._total_processing_time += duration

            _logger.info(  # type: ignore
                f"Request completed successfully - model={model}, duration={duration:.3f}s"
            )

            _metrics.increment("requests_success")

        except Exception as e:
            _logger.error(f"Error in log_success_event: {e}", exc_info=True)  # type: ignore

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Log synchronous failure events."""
        try:
            duration = end_time - start_time
            model = kwargs.get("model", "unknown")  # type: ignore
            error = str(response_obj) if response_obj else "unknown"

            FlexiProxyCustomHandler._failed_requests += 1

            _logger.error(  # type: ignore
                f"Request failed - model={model}, duration={duration:.3f}s, error={error[:200]}"
            )

            _metrics.increment("requests_failure")

        except Exception as e:
            _logger.error(f"Error in log_failure_event: {e}", exc_info=True)  # type: ignore

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Log asynchronous success events."""
        try:
            duration = end_time - start_time
            model = kwargs.get("model", "unknown")  # type: ignore

            # Extract usage metrics
            usage_info = ""
            if hasattr(response_obj, "usage"):
                usage = response_obj.usage  # type: ignore
                prompt_tokens = getattr(usage, "prompt_tokens", 0)
                completion_tokens = getattr(usage, "completion_tokens", 0)
                total_tokens = getattr(usage, "total_tokens", 0)
                usage_info = f", tokens(p={prompt_tokens}, c={completion_tokens}, t={total_tokens})"

            _logger.info(  # type: ignore
                f"Async request completed - model={model}, duration={duration:.3f}s{usage_info}"
            )

            FlexiProxyCustomHandler._successful_requests += 1
            FlexiProxyCustomHandler._total_processing_time += duration
            _metrics.increment("async_requests_success")

        except Exception as e:
            _logger.error(f"Error in async_log_success_event: {e}", exc_info=True)  # type: ignore

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Log asynchronous failure events."""
        try:
            duration = end_time - start_time
            model = kwargs.get("model", "unknown")  # type: ignore

            # Extract error details
            error_msg = "unknown"
            error_type = "unknown"

            if response_obj:
                if isinstance(response_obj, Exception):
                    error_msg = str(response_obj)
                    error_type = type(response_obj).__name__
                else:
                    error_msg = str(response_obj)

            _logger.error(  # type: ignore
                f"Async request failed - model={model}, duration={duration:.3f}s, "
                f"error_type={error_type}, error={error_msg[:200]}"
            )

            FlexiProxyCustomHandler._failed_requests += 1
            _metrics.increment("async_requests_failure")

        except Exception as e:
            _logger.error(f"Error in async_log_failure_event: {e}", exc_info=True)  # type: ignore

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
        """
        Pre-call hook to modify request data.

        This is called before every LLM API call and is responsible for:
        1. Extracting FlexiProxy metadata (mid, key, llm)
        2. Setting the correct API key and model
        3. Merging custom litellm_params
        4. Validating request data
        """

        hook_start = time.time()
        try:
            FlexiProxyCustomHandler._total_requests += 1
            # Validate metadata presence
            if (
                not hasattr(user_api_key_dict, "metadata")
                or user_api_key_dict.metadata is None  # type: ignore
            ):
                _logger.error(  # type: ignore
                    f"Missing metadata in user_api_key_dict - call_type={call_type}"
                )
                _metrics.increment("pre_call_hook_errors")
                raise ValueError("Internal Error: Missing metadata")

            # Extract required fields
            mid = user_api_key_dict.metadata.pop("fp_mid", None)  # type: ignore
            key = user_api_key_dict.metadata.pop("fp_key", None)  # type: ignore

            if not mid or not key:
                _logger.error(  # type: ignore
                    f"Missing fp_mid or fp_key in metadata - call_type={call_type}, "
                    f"has_mid={bool(mid)}, has_key={bool(key)}"
                )
                _metrics.increment("pre_call_hook_errors")
                raise ValueError("Internal Error: Missing credentials")

            # Validate data dictionary
            if not isinstance(data, dict):
                _logger.error(
                    f"Invalid data type in pre_call_hook - call_type={call_type}, "
                    f"data_type={type(data).__name__}"
                )
                _metrics.increment("pre_call_hook_errors")
                raise ValueError("Internal Error: Invalid data format")

            # Set API key and model
            original_model = data.get("model")  # type: ignore
            data["api_key"] = key
            data["model"] = mid

            _logger.debug(  # type: ignore
                f"Model mapping - call_type={call_type}, {original_model} -> {mid}"
            )

            # Handle custom LLM parameters
            llm = user_api_key_dict.metadata.pop("fp_llm", None)  # type: ignore
            if llm and isinstance(llm, str) and llm.strip():
                try:
                    llm_params = json.loads(llm)

                    # Validate llm_params is a dictionary
                    if not isinstance(llm_params, dict):
                        _logger.warn(  # type: ignore
                            f"llm_params is not a dictionary, ignoring - call_type={call_type}, "
                            f"type={type(llm_params).__name__}"
                        )
                    else:
                        # Merge litellm_params
                        if "litellm_params" not in data:
                            data["litellm_params"] = llm_params
                        else:
                            # Deep merge, prefer incoming llm_params
                            existing_params = data["litellm_params"]
                            if isinstance(existing_params, dict):
                                data["litellm_params"] = {
                                    **existing_params,
                                    **llm_params,
                                }
                            else:
                                data["litellm_params"] = llm_params

                        _logger.debug(  # type: ignore
                            f"Applied custom litellm_params - call_type={call_type}, "
                            f"params={list(llm_params.keys())}"
                        )

                except json.JSONDecodeError as e:
                    _logger.error(  # type: ignore
                        f"Failed to parse llm_params JSON - call_type={call_type}, "
                        f"error={str(e)}, llm_value={llm[:100]}"
                    )
                    _metrics.increment("pre_call_hook_errors")
                    raise ValueError("Invalid LLM Params Format")

                except Exception as e:
                    _logger.error(  # type: ignore
                        f"Error processing llm_params - call_type={call_type}, error={str(e)}",
                        exc_info=True,
                    )
                    _metrics.increment("pre_call_hook_errors")
                    raise ValueError("Error processing LLM parameters")

            # Additional validation for specific call types
            if call_type == "completion":
                if "messages" not in data:
                    _logger.error(  # type: ignore
                        f"Missing 'messages' in completion request - call_type={call_type}"
                    )
                    _metrics.increment("pre_call_hook_errors")
                    raise ValueError("Missing required field: messages")

            # Security: Remove any sensitive fields that shouldn't be forwarded
            sensitive_fields = ["fp_mid", "fp_key", "fp_llm", "user_id", "team_id"]
            for field in sensitive_fields:
                data.pop(field, None)  # type: ignore

            hook_duration = time.time() - hook_start

            _logger.debug(  # type: ignore
                f"Pre-call hook completed - call_type={call_type}, model={mid}, "
                f"duration={hook_duration:.3f}s"
            )

            _metrics.increment("pre_call_hook_success")

            return data

        except ValueError:
            # Expected validation errors - already logged
            hook_duration = time.time() - hook_start
            _logger.debug(  # type: ignore
                f"Pre-call hook validation failed - duration={hook_duration:.3f}s"
            )
            raise

        except Exception as e:
            # Unexpected errors
            hook_duration = time.time() - hook_start
            _logger.error(  # type: ignore
                f"Unexpected error in pre_call_hook - call_type={call_type}, "
                f"error={str(e)}, duration={hook_duration:.3f}s",
                exc_info=True,
            )
            _metrics.increment("pre_call_hook_errors")
            raise ValueError("Internal Error")

    #### POST CALL HOOKS ####
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        """
        Post-call success hook for additional processing.

        Can be used for:
        - Custom billing
        - Usage tracking
        - Response modification
        - Audit logging
        """
        try:
            model = data.get("model", "unknown")  # type: ignore

            # Extract response metadata
            metadata_parts = []
            if hasattr(response, "usage"):
                usage = response.usage  # type: ignore
                prompt_tokens = getattr(usage, "prompt_tokens", 0)
                completion_tokens = getattr(usage, "completion_tokens", 0)
                total_tokens = getattr(usage, "total_tokens", 0)
                metadata_parts.append(  # type: ignore
                    f"tokens(p={prompt_tokens}, c={completion_tokens}, t={total_tokens})"
                )

            metadata_str = (
                ", ".join(metadata_parts) if metadata_parts else "no_usage_info"
            )

            _logger.debug(f"Post-call success hook - model={model}, {metadata_str}")  # type: ignore

        except Exception as e:
            _logger.error(f"Error in post_call_success_hook: {e}", exc_info=True)  # type: ignore

    async def async_post_call_failure_hook(
        self,
        request_data: dict,
        original_exception: Exception,
        user_api_key_dict: UserAPIKeyAuth,
        traceback_str: Optional[str] = None,
    ):
        """
        Post-call failure hook for error handling.
        """
        try:
            model = request_data.get("model", "unknown")  # type: ignore
            error_type = type(original_exception).__name__
            error_msg = str(original_exception)

            traceback_preview = traceback_str[:500] if traceback_str else "no_traceback"

            _logger.error(  # type: ignore
                f"Post-call failure hook - model={model}, error_type={error_type}, "
                f"error={error_msg[:200]}, traceback={traceback_preview}"
            )

        except Exception as e:
            _logger.error(f"Error in post_call_failure_hook: {e}", exc_info=True)  # type: ignore

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: str,
    ):
        """Hook for streaming response chunks."""
        try:
            # Avoid logging every chunk in production
            pass
        except Exception as e:
            _logger.error(f"Error in post_call_streaming_hook: {e}", exc_info=True)  # type: ignore

    #### UTILITY METHODS ####
    @classmethod
    def get_metrics(cls) -> Dict[str, Any]:
        """Get handler metrics for monitoring."""
        avg_processing_time = (
            cls._total_processing_time / cls._successful_requests
            if cls._successful_requests > 0
            else 0
        )

        success_rate = (
            cls._successful_requests / cls._total_requests
            if cls._total_requests > 0
            else 0
        )

        return {
            "total_requests": cls._total_requests,
            "successful_requests": cls._successful_requests,
            "failed_requests": cls._failed_requests,
            "success_rate": success_rate,
            "avg_processing_time": avg_processing_time,
        }

    @classmethod
    def reset_metrics(cls) -> None:
        """Reset handler metrics."""
        cls._total_requests = 0
        cls._successful_requests = 0
        cls._failed_requests = 0
        cls._total_processing_time = 0.0
        _logger.info("Handler metrics reset")  # type: ignore


proxy_handler_instance = FlexiProxyCustomHandler()
