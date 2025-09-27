import os

# Dev [TODO...Remove]
from dotenv import load_dotenv

load_dotenv()


class Config:
    # App
    FP_APP_TOKEN_PASS = os.getenv("FP_APP_TOKEN_PASS", None)
    FP_APP_BASE_URL = os.getenv("FP_APP_BASE_URL", None)

    # Proxy Server
    FP_PROXY_SERVER_URL = os.getenv("FP_PROXY_SERVER_URL", None)
    FP_PROXY_SERVER_ID = os.getenv("FP_PROXY_SERVER_ID", None)
    FP_PROXY_SERVER_ADVANCED = int(os.getenv("FP_PROXY_SERVER_ADVANCED", "0"))
    FP_PROXY_SERVER_KEYPAIR_PWD = os.getenv("FP_PROXY_SERVER_KEYPAIR_PWD", None)
    FP_PROXY_SERVER_FERNET_KEY = os.getenv("FP_PROXY_SERVER_FERNET_KEY", None)

    # LRU Cache
    FP_LRU_MAX_CACHE_SIZE = int(os.getenv("FP_LRU_MAX_CACHE_SIZE", "500"))

    # Http
    FP_HTTP_MAX_POOL_CONNECTIONS_COUNT = int(
        os.getenv("FP_HTTP_MAX_POOL_CONNECTIONS_COUNT", "10")
    )
    FP_HTTP_CONNECT_TIMEOUT_LIMIT = int(os.getenv("FP_HTTP_CONNECT_TIMEOUT_LIMIT", "8"))
    FP_HTTP_READ_TIMEOUT_LIMIT = int(os.getenv("FP_HTTP_READ_TIMEOUT_LIMIT", "120"))
    FP_HTTP_MAX_RETRY_COUNT = int(os.getenv("FP_HTTP_MAX_RETRY_COUNT", "3"))
    FP_HTTP_RETRY_BACKOFF = float(os.getenv("FP_HTTP_RETRY_BACKOFF", "0.5"))
    FP_HTTP_POOL_MAX_SIZE = int(os.getenv("FP_HTTP_POOL_MAX_SIZE", "30"))
