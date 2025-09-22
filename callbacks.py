import os
from pathlib import Path
import threading
import requests
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth
from litellm.caching.dual_cache import DualCache
from litellm.types.utils import ModelResponseStream
from typing import Any, AsyncGenerator, Optional, Literal
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

load_dotenv()

class TokenRotator:
    _env_lock = threading.Lock()
    _token_cache: Optional[str] = None

    @classmethod
    def token(cls) -> str:
        """
        Get the current token from cache or environment.
        """
        with cls._env_lock:
            if cls._token_cache is not None:
                return cls._token_cache
            else:
                return os.getenv("TOKEN_PASS", "")

    @classmethod
    def clear(cls) -> None:
        """
        Clear token cache
        """
        with cls._env_lock:
            cls._token_cache = None

    @classmethod
    def rotate(cls) -> None:
        """
        Rotate the token by exchanging it with the target service.
        Returns True if successful, False otherwise. Trigger per 25 minutes ( < 30min Token expiration)
        """
        target_url = os.getenv("TARGET_URL")
        if not target_url:
            print("Missing TARGET_URL environment variable")
            return

        # Get current token for exchange
        current_token = (
            cls._token_cache
            if cls._token_cache is not None
            else os.getenv("TOKEN_PASS", "")
        )

        if not current_token:
            print("No current token available for exchange")
            return

        headers = {"authorization": f"Bearer {current_token}"}
        try:
            response = requests.post(
                f"{target_url}/api/auth/exchange", headers=headers, timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                new_token = data["token"]

                if new_token:
                    with cls._env_lock:
                        cls._token_cache = new_token

                    expires_in = data["expiresIn"]
                    print(
                        f"Token exchanged successfully, expires in {expires_in} seconds."
                    )
                else:
                    print("Token exchange response missing token")
            else:
                print(f"Token exchange failed with status {response.status_code}")
                # Clear cache on failure
                with cls._env_lock:
                    cls._token_cache = None
        except requests.RequestException:
            print("Token exchange request failed")
            # Clear cache on failure
            with cls._env_lock:
                cls._token_cache = None
        except Exception:
            print("Unexpected error during token rotation")
            # Clear cache on failure
            with cls._env_lock:
                cls._token_cache = None


class KeyPairLoader:
    _private_key: None | rsa.RSAPrivateKey = None
    _public_key: None | str = None

    @classmethod
    def load(cls) -> None:
        if cls._private_key is not None and cls._public_key is not None:
            print("Keys already Loaded")
            return

        private_pem_bytes = Path("key.pem").read_bytes()
        public_pem_bytes = Path("public.pem").read_bytes()
        password = os.getenv("KEYPAIR_PWD", "").encode("ascii")

        try:
            private_key = serialization.load_pem_private_key(
                private_pem_bytes,
                password=password,
            )
            if isinstance(private_key, rsa.RSAPrivateKey):
                cls._private_key = private_key
            else:
                raise TypeError(
                    "Expected RSAPrivateKey, got {}".format(type(private_key))
                )

            cls._public_key = public_pem_bytes.decode("utf-8")
            print("Keys Correctly Loaded")
        except ValueError:
            print("Incorrect Password")

    @classmethod
    def request(cls, api_key: str, token_pass: str) -> None | dict:
        target_url = os.getenv("TARGET_URL")
        if not target_url:
            print("Missing TARGET_URL environment variable")
            return None
        if cls._public_key is None or cls._private_key is None:
            print("Keys not Loaded")
            return None
        headers = {
            "authorization": f"Bearer {token_pass}",
            "X-Public-Key": cls._public_key,
            "X-API-Key": api_key,
        }
        response = requests.get(
            f"{target_url}/api/adapters", headers=headers, timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            result: dict[str, str] = {}
            result["uid"] = data["uid"]
            result["url"] = data["url"]
            result["mid"] = data["mid"]
            message: str = data["enc"]
            message_decrypted: bytes = cls._private_key.decrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            result["key"] = message_decrypted.decode("utf-8")
            return result
        return None

    @classmethod
    def unload(cls):
        cls._private_key = None
        cls._public_key = None


# This file includes the custom callbacks for LiteLLM Proxy
# Once defined, these can be passed in proxy_config.yaml
class FlexiProxyCustomHandler(CustomLogger): # https://docs.litellm.ai/docs/observability/custom_callback#callback-class
    # Class variables or attributes
    def __init__(self):
        self._key_pair_loader = KeyPairLoader()
        self._key_pair_loader.unload()
        self._key_pair_loader.load()
        self._token_rotator_instance = TokenRotator()
        pass

    #### CALL HOOKS - proxy only #### 

    async def async_pre_call_hook(self, user_api_key_dict: UserAPIKeyAuth, cache: DualCache, data: dict, call_type: Literal[
            "completion",
            "text_completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
            "pass_through_endpoint",
            "rerank",
            "mcp_call",
        ]): 
        print("AAAAAAAAAAAAAAAAAAAAAAAAAA1")
        # data["model"] = "my-new-model"
        return data 

    async def async_post_call_failure_hook(
        self, 
        request_data: dict,
        original_exception: Exception, 
        user_api_key_dict: UserAPIKeyAuth,
        traceback_str: Optional[str] = None,
    ):
        print("AAAAAAAAAAAAAAAAAAAAAAAAAA2")
        pass

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        print("AAAAAAAAAAAAAAAAAAAAAAAAAA3")
        pass

    async def async_moderation_hook( # call made in parallel to llm api call
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        call_type: Literal[            
            "completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
            "responses",
            "mcp_call",],
    ):
        print("AAAAAAAAAAAAAAAAAAAAAAAAAA4")
        pass

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: str,
    ):
        print("AAAAAAAAAAAAAAAAAAAAAAAAAA5")
        pass

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[ModelResponseStream, None]:
        """
        Passes the entire stream to the guardrail

        This is useful for plugins that need to see the entire stream.
        """
        async for item in response:
            yield item

proxy_handler_instance = FlexiProxyCustomHandler()