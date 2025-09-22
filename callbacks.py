import base64
import os
import threading
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Literal, Optional

import requests
import schedule
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv
from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth
from litellm.types.utils import ModelResponseStream

load_dotenv()

APP_TOKEN_PASS = os.getenv("APP_TOKEN_PASS", None)
APP_BASE_URL = os.getenv("APP_BASE_URL", None)
APP_PROVIDER_SUBDOMAIN_URL = os.getenv("APP_PROVIDER_SUBDOMAIN_URL", None)
APP_PROVIDER_ID = os.getenv("APP_PROVIDER_ID", None)
KEYPAIR_PWD = os.getenv("KEYPAIR_PWD", None)


class TokenRotator:
    _env_lock = threading.Lock()
    _token_cache: Optional[str] = None

    @classmethod
    def token(cls) -> str | None:
        """
        Get the current token from cache or environment.
        """
        with cls._env_lock:
            if cls._token_cache is not None:
                return cls._token_cache
            else:
                return APP_TOKEN_PASS

    @classmethod
    def clear(cls) -> None:
        """
        Clear token cache
        """
        with cls._env_lock:
            cls._token_cache = None

    @classmethod
    def rotate(cls) -> bool:
        """
        Rotate the token by exchanging it with the target service.
        Returns True if successful, False otherwise. Trigger per 10 minutes ( < 2h Token expiration)
        """

        if APP_BASE_URL is None:
            print("Missing APP_BASE_URL environment variable")
            return False

        # Get current token for exchange
        current_token = (
            cls._token_cache if cls._token_cache is not None else APP_TOKEN_PASS
        )

        if current_token is None:
            print("No current token available for exchange")
            return False

        headers = {"authorization": f"Bearer {current_token}"}
        try:
            response = requests.post(
                f"{APP_BASE_URL}/api/auth/exchange", headers=headers, timeout=120
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
                    return True
                else:
                    print("Token exchange response missing token")
                    return False
            else:
                print(f"Token exchange failed with status {response.status_code}")
                # Clear cache on failure
                with cls._env_lock:
                    cls._token_cache = None
                return False
        except requests.RequestException:
            print("Token exchange request failed")
            # Clear cache on failure
            with cls._env_lock:
                cls._token_cache = None
            return False
        except Exception:
            print("Unexpected error during token rotation")
            # Clear cache on failure
            with cls._env_lock:
                cls._token_cache = None
            return False


class KeyPairLoader:
    _private_key: None | rsa.RSAPrivateKey = None
    _public_key: None | str = None

    @classmethod
    def load(cls) -> None:
        if cls._private_key is not None and cls._public_key is not None:
            print("Keys already Loaded")
            return

        # Use absolute paths for key files to prevent path traversal vulnerabilities
        key_file_path = Path.cwd() / "key.pem"
        public_file_path = Path.cwd() / "public.pem"

        # Validate that key files exist before attempting to read
        if not key_file_path.exists():
            print("Private key file not found")
            return
        if not public_file_path.exists():
            print("Public key file not found")
            return

        private_pem_bytes = key_file_path.read_bytes()
        public_pem_bytes = public_file_path.read_bytes()
        if KEYPAIR_PWD is None:
            print("keys password is invalid")
            return
        password = KEYPAIR_PWD.encode("ascii")

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
    def request(
        cls, api_key: str | None, app_token: str | None
    ) -> None | dict[str, str]:
        if APP_BASE_URL is None:
            print("Missing APP_BASE_URL environment variable")
            return None
        if cls._public_key is None or cls._private_key is None:
            print("Keys not Loaded")
            return None
        if api_key is None or app_token is None:
            print("API Key or APP Token invalid")
            return None
        headers = {
            "authorization": f"Bearer {app_token}",
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }
        data = {"public_key": cls._public_key}
        try:
            response = requests.post(
                f"{APP_BASE_URL}/api/adapters", headers=headers, json=data, timeout=180
            )
            response.raise_for_status()  # Raise an exception for bad status codes
        except requests.RequestException as e:
            print(f"Adapter request failed: {e}")
            return None

        try:
            response_data = response.json()
        except ValueError as e:
            print(f"Failed to parse JSON response: {e}")
            return None

        result: dict[str, str] = {}
        try:
            result["uid"] = response_data["uid"]
            result["url"] = response_data["url"]
            result["mid"] = response_data["mid"]
            message: str = response_data["enc"]
            message_bytes = base64.b64decode(message)
            try:
                message_decrypted: bytes = cls._private_key.decrypt(
                    message_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except ValueError as e:
                print(f"Decryption failed: {e}")
                return None
            result["key"] = message_decrypted.decode("utf-8")
            return result
        except KeyError as e:
            print(f"Missing key in response data: {e}")
            return None
        except Exception as e:
            print(f"Error processing adapter response: {e}")
            return None

    @classmethod
    def unload(cls):
        cls._private_key = None
        cls._public_key = None


class StatusReporter:
    _request_counter: int = 0
    _lock = threading.Lock()

    @classmethod
    def upload(cls, app_token: str | None) -> bool:
        """
        Trigger per 30 minutes (< 4 hour expiration)
        Returns True if successful, False otherwise.
        """
        with cls._lock:
            if (
                APP_BASE_URL is None
                or APP_PROVIDER_SUBDOMAIN_URL is None
                or APP_PROVIDER_ID is None
            ):
                print(
                    "Missing required environment variables: APP_BASE_URL, APP_PROVIDER_ID, or APP_PROVIDER_SUBDOMAIN_URL"
                )
                return False
            if app_token is None:
                print("Missing app token")
                return False
            request_count = cls._request_counter
            if request_count < 100:
                status: Literal["unavailable", "spare", "busy", "full"] = "spare"
            elif request_count < 500:
                status = "busy"
            else:
                status = "full"
            data = {
                "url": APP_PROVIDER_SUBDOMAIN_URL,
                "status": status,
                "ex": 14400,  # seconds = 4 hour
                "adv": False,
            }
            headers = {
                "Authorization": f"Bearer {app_token}",
                "Content-Type": "application/json",
            }
            try:
                response = requests.post(
                    f"{APP_BASE_URL}/api/providers/{APP_PROVIDER_ID}",
                    json=data,
                    headers=headers,
                    timeout=120,
                )
                response.raise_for_status()  # Raise an exception for bad status codes
                print("Status update succeed.")
                cls._request_counter = 0
                return True
            except requests.RequestException as e:
                print(f"Status update failed: {e}")
                cls._request_counter = 0
                return False

    @classmethod
    def update(cls):
        """
        Trigger per request
        """
        with cls._lock:
            cls._request_counter = cls._request_counter + 1


# This file includes the custom callbacks for LiteLLM Proxy
# Once defined, these can be passed in proxy_config.yaml
class FlexiProxyCustomHandler(
    CustomLogger
):  # https://docs.litellm.ai/docs/observability/custom_callback#callback-class
    # Class variables or attributes

    _key_pair_loader: KeyPairLoader | None = None
    _token_rotator: TokenRotator | None = None
    _status_reporter: StatusReporter | None = None

    def __init__(self):
        self._key_pair_loader = KeyPairLoader()
        self._key_pair_loader.unload()
        self._key_pair_loader.load()
        self._token_rotator = TokenRotator()
        self._status_reporter = StatusReporter()
        self._status_reporter.upload(self._token_rotator.token())
        self._scheduler_thread = threading.Thread(
            target=self.start_scheduler, daemon=True
        )
        self._scheduler_thread.start()

    def __del__(self):
        if self._key_pair_loader is not None:
            self._key_pair_loader.unload()
        if self._token_rotator is not None:
            self._token_rotator.clear()

    def start_scheduler(self):
        if self._status_reporter is None or self._token_rotator is None:
            print("Scheduler components not initialized")
            return

        # Schedule token rotation every 10 minutes
        schedule.every(10).minutes.do(self._token_rotator.rotate)  # type: ignore

        # Schedule status reporting every 30 minutes
        schedule.every(30).minutes.do(  # type: ignore
            self._status_reporter.upload, self._token_rotator.token()
        )

        # Run scheduler
        while True:
            schedule.run_pending()
            time.sleep(1)  # Check for scheduled tasks every second

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
        # Validate required components
        if (
            self._key_pair_loader is None
            or self._status_reporter is None
            or self._token_rotator is None
        ):
            return "Internal Error"

        # Validate data structure
        if "secret_fields" not in data:
            return "[secret_fields] field not found in data"

        if "raw_headers" not in data["secret_fields"]:
            return '[raw_headers] field not found in data["secret_fields"]'

        raw_headers: dict | None = data["secret_fields"]["raw_headers"]
        if raw_headers is None:
            return "[raw_headers] field is invalid"

        # Extract client API key from headers
        client_api_key = None
        if "x-api-key" in raw_headers:
            client_api_key = raw_headers["x-api-key"]
        elif (
            "authorization" in raw_headers
            and isinstance(raw_headers["authorization"], str)
            and str(raw_headers["authorization"]).startswith("Bearer ")
        ):
            client_api_key = str(raw_headers["authorization"]).replace("Bearer ", "")

        # Validate client API key
        if client_api_key is None:
            return "Client API key not found in headers"

        # Request key pair information
        response = self._key_pair_loader.request(
            api_key=client_api_key, app_token=self._token_rotator.token()
        )
        if response is None:
            return "Internal Error"

        # Update data with response information
        data["api_base"] = response["url"]
        data["api_key"] = response["key"]
        data["model"] = response["mid"]

        # Update request counter
        self._status_reporter.update()
        return data


proxy_handler_instance = FlexiProxyCustomHandler()
