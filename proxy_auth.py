# str - bytes
import base64
from typing import Optional

import requests
from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth

from core import Config, HybridCrypto, TimestampedLRUCache, TokenRotator, http_client

# str - dict
_key_cache: "TimestampedLRUCache" = TimestampedLRUCache(
    maxsize=Config.LRU_MAX_CACHE_SIZE
)

HybridCrypto.unload()
if not HybridCrypto.load():
    raise RuntimeError(
        "Failed to load keys. Check key.pem, public.pem and PROXY_SERVER_KEYPAIR_PWD."
    )

TokenRotator.clear()
TokenRotator.background_refresh(10)


async def user_api_key_auth(request: requests.Request, api_key: str) -> UserAPIKeyAuth:
    global _key_cache
    import hashlib

    hashed_token = hashlib.sha256(api_key.encode()).hexdigest()
    cache_entry: Optional[dict[str, str]] = _key_cache[hashed_token]
    if cache_entry is not None:
        return UserAPIKeyAuth(
            metadata={
                "fp_enc": cache_entry["enc"],
                "fp_url": cache_entry["url"],
                "fp_mid": cache_entry["mid"],
            },
            api_key=api_key,
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
            data={"public_key": HybridCrypto.asymmetric_public_key()},
        )
        response.raise_for_status()
    except requests.RequestException:
        raise Exception("Authentication validation failed")

    try:
        response_data = response.json()
        message_bytes = base64.b64decode(response_data["enc"])
        message_decrypted: Optional[str] = HybridCrypto.asymmetric_decrypt(
            message_bytes
        )
        if message_decrypted is None:
            raise Exception("Decryption failed")
        entry = {
            "enc": HybridCrypto.symmetric_encrypt(message_decrypted).decode(),
            "url": response_data["url"],
            "mid": response_data["mid"],
        }
        _key_cache[hashed_token] = entry
        return UserAPIKeyAuth(
            metadata={
                "fp_enc": entry["enc"],
                "fp_url": entry["url"],
                "fp_mid": entry["mid"],
            },
            api_key=api_key,
            user_role=LitellmUserRoles.CUSTOMER,
        )
    except ValueError:
        raise Exception("Decryption failed")
    except KeyError:
        raise Exception("Missing key in response data")
    except Exception:
        raise Exception
