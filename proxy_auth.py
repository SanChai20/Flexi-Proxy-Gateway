# str - bytes
import base64
from typing import Optional

import requests
from cryptography.fernet import Fernet
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth

from core import Config, KeyPairLoader, TimestampedLRUCache, TokenRotator, http_client

_key_cache: "TimestampedLRUCache" = TimestampedLRUCache(
    maxsize=Config.LRU_MAX_CACHE_SIZE
)
_fernet_cipher: Optional[Fernet] = None


def get_fernet_cipher() -> Fernet:
    global _fernet_cipher
    if _fernet_cipher is None:
        if Config.PROXY_SERVER_FERNET_KEY is None:
            raise Exception("Internal Error: Fernet key not configured")
        _fernet_cipher = Fernet(Config.PROXY_SERVER_FERNET_KEY)
    return _fernet_cipher


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    global _key_cache
    import hashlib

    hashed_token = hashlib.sha256(api_key.encode()).hexdigest()
    cache_entry: Optional[bytes] = _key_cache[hashed_token]
    if cache_entry is not None:
        return UserAPIKeyAuth(
            api_key=get_fernet_cipher().decrypt(cache_entry).decode(),
            user_role=LitellmUserRoles.CUSTOMER,
        )

    app_token = TokenRotator.token()
    if app_token is None:
        raise Exception("Internal Error")
    try:
        response = http_client.get(
            f"{Config.APP_BASE_URL}/api/auth/validate",
            headers={
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
            },
        )
        response.raise_for_status()
        response = http_client.post(
            f"{Config.APP_BASE_URL}/api/auth/validate",
            headers={
                "authorization": f"Bearer {app_token}",
                "X-API-Key": api_key,
            },
            data={"public_key": KeyPairLoader.public_key()},
        )
        response.raise_for_status()
    except requests.RequestException:
        raise Exception("Authentication validation failed")

    try:
        response_data = response.json()
        message_bytes = base64.b64decode(response_data["enc"])
        message_decrypted: Optional[str] = KeyPairLoader.decrypt(message_bytes)
        if message_decrypted is None:
            raise Exception("Decryption failed")

        _key_cache[hashed_token] = get_fernet_cipher().encrypt(
            message_decrypted.encode()
        )
        return UserAPIKeyAuth(
            api_key=message_decrypted, user_role=LitellmUserRoles.CUSTOMER
        )
    except ValueError:
        raise Exception("Decryption failed")
    except KeyError:
        raise Exception("Missing key in response data")
    except Exception:
        raise Exception
