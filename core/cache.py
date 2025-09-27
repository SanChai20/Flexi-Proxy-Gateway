import time
from typing import Any

from cachetools import LRUCache


class TimestampedLRUCache(LRUCache[str, Any]):
    _last_used: dict[str, float] = {}

    def __init__(self, maxsize, getsizeof=None):
        super().__init__(maxsize, getsizeof)
        self._last_used = {}

    def __getitem__(self, key):
        try:
            value = super().__getitem__(key)
            self._last_used[key] = time.time()
            return value
        except Exception:
            return None

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._last_used[key] = time.time()

    def popitem(self):
        lru_key = min(self._last_used, key=lambda k: self._last_used[k])
        lru_value = super().__getitem__(lru_key)
        del self._last_used[lru_key]
        super().pop(lru_key, None)
        return lru_key, lru_value
