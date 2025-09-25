import random
import threading
import time
import unittest
from typing import Any, Optional

from cachetools import LRUCache  # pip install cachetools==5.5.0


class TimestampedLRUCache(LRUCache[str, dict[str, str]]):
    _last_used: dict[str, float] = {}  # key - timestamp

    def __init__(self, maxsize=128, getsizeof=None):
        super().__init__(maxsize, getsizeof)
        self._last_used = {}

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self._last_used[key] = time.time()
        return value

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._last_used[key] = time.time()

    def popitem(self):
        lru_key = min(self._last_used, key=lambda k: self._last_used[k])
        lru_value = super().__getitem__(lru_key)
        del self._last_used[lru_key]
        super().pop(lru_key, None)
        return lru_key, lru_value


class Config:
    """模拟配置"""

    LRU_MAX_CACHE_SIZE = 20  # 默认 maxsize


class TestThreadSafeTimestampedLRUCache(unittest.TestCase):
    def test_thread_safety(self):
        cache = TimestampedLRUCache(maxsize=10)
        errors = []
        lock = threading.Lock()

        def worker(thread_id, num_operations):
            try:
                for i in range(num_operations):
                    key = f"key{thread_id}_{i % 5}"  # 有限的键集增加竞争

                    # 随机选择操作
                    import random

                    op = random.choice(["set", "get", "pop"])

                    if op == "set":
                        cache[key] = {"value": f"thread{thread_id}_value{i}"}
                    elif op == "get":
                        value = cache.get(key)
                        if value is not None:
                            # 验证值格式
                            self.assertIsInstance(value, dict)
                    else:  # pop
                        if cache:  # 非空时才pop
                            try:
                                k, v = cache.popitem()
                                self.assertIsInstance(k, str)
                                self.assertIsInstance(v, dict)
                            except KeyError:
                                pass  # 空缓存是正常的

                    # 验证大小不超过限制
                    self.assertLessEqual(len(cache), 10)

            except Exception as e:
                with lock:
                    errors.append(f"Thread {thread_id}: {e}")  # type: ignore

        # 启动多个线程
        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(i, 100))
            threads.append(t)  # type: ignore
            t.start()

        # 等待所有线程完成
        for t in threads:
            t.join(timeout=30)  # type: ignore

        # 检查错误
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")

        # 最终一致性检查
        self.assertLessEqual(len(cache), 10)
        for key in list(cache.keys()):
            self.assertIn(key, cache._last_used)


if __name__ == "__main__":
    unittest.main()
