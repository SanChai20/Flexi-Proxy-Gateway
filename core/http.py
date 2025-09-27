from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .params import Config


class HTTPClient:
    """HTTP Client Wrapper, Support retry & connection pool"""

    def __init__(
        self,
    ):
        self.timeout = (
            Config.HTTP_CONNECT_TIMEOUT_LIMIT,
            Config.HTTP_READ_TIMEOUT_LIMIT,
        )
        self.session = requests.Session()

        retry_strategy = Retry(
            total=Config.HTTP_MAX_RETRY_COUNT,
            backoff_factor=Config.HTTP_RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=Config.HTTP_MAX_POOL_CONNECTIONS_COUNT,
            pool_maxsize=Config.HTTP_POOL_MAX_SIZE,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _request(
        self, method: str, url: str, headers: Any, data: Any
    ) -> requests.Response:
        return self.session.request(
            method, url, timeout=self.timeout, headers=headers, json=data
        )

    def post(self, url: str, headers: Any, data: Any) -> requests.Response:
        return self._request("POST", url, headers, data)

    def get(self, url: str, headers: Any) -> requests.Response:
        return self._request("GET", url, headers, None)

    def close(self):
        self.session.close()


print("AAAAAAAAAAA - http_client")
http_client = HTTPClient()
