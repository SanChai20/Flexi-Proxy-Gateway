import os

# Dev [TODO...Remove]
from dotenv import load_dotenv

load_dotenv()


class Config:
    # App
    APP_TOKEN_PASS = os.getenv("APP_TOKEN_PASS", None)
    APP_BASE_URL = os.getenv("APP_BASE_URL", None)

    # Proxy Server
    PROXY_SERVER_URL = os.getenv("PROXY_SERVER_URL", None)
    PROXY_SERVER_ID = os.getenv("PROXY_SERVER_ID", None)
    PROXY_SERVER_ADVANCED = int(os.getenv("PROXY_SERVER_ADVANCED", "0"))
    PROXY_SERVER_KEYPAIR_PWD = os.getenv("PROXY_SERVER_KEYPAIR_PWD", None)
    PROXY_SERVER_FERNET_KEY = os.getenv("PROXY_SERVER_FERNET_KEY", None)

    # LRU Cache
    LRU_MAX_CACHE_SIZE = int(os.getenv("LRU_MAX_CACHE_SIZE", "500"))

    # Http
    HTTP_MAX_POOL_CONNECTIONS_COUNT = int(
        os.getenv("HTTP_MAX_POOL_CONNECTIONS_COUNT", "10")
    )
    HTTP_CONNECT_TIMEOUT_LIMIT = int(os.getenv("HTTP_CONNECT_TIMEOUT_LIMIT", "8"))
    HTTP_READ_TIMEOUT_LIMIT = int(os.getenv("HTTP_READ_TIMEOUT_LIMIT", "120"))
    HTTP_MAX_RETRY_COUNT = int(os.getenv("HTTP_MAX_RETRY_COUNT", "3"))
    HTTP_RETRY_BACKOFF = float(os.getenv("HTTP_RETRY_BACKOFF", "0.5"))
    HTTP_POOL_MAX_SIZE = int(os.getenv("HTTP_POOL_MAX_SIZE", "30"))
