import time

from cachetools import LRUCache


class TimestampedLRUCache(LRUCache[str, dict[str, str]]):
    _last_used: dict[str, float] = {}  # key - timestamp

    def __init__(self, maxsize=128, getsizeof=None):
        super().__init__(maxsize, getsizeof)
        self._last_used = {}

    def __getitem__(self, key):
        try:
            value = super().__getitem__(key)
            self._last_used[key] = time.time()
            return value
        except Exception as e:
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


# 创建一个容量为 3 的 LRUCache
cache = TimestampedLRUCache(maxsize=3)
# 插入数据
cache["a"] = {"a": "1"}
cache["b"] = {"b": "2"}
cache["c"] = {"c": "3"}
# 访问 'a' -> 'a' 会被移动到“最新”
print(cache["b"])
print(cache["b"])
print(cache["d"])
# 插入 'c' -> 容量满了 -> 淘汰最久未使用的 'b'
cache["d"] = {"d": "4"}
print(cache)  # LRUCache([('a', 1), ('c', 3)], maxsize=2, currsize=2)
# import random
# import threading
# import time

# from cachetools import LRUCache


# class ThreadSafeCounter:
#     """Thread-safe counter"""

#     def __init__(self):
#         self._value = 0
#         self._lock = threading.Lock()

#     def increment(self) -> int:
#         with self._lock:
#             self._value += 1
#             return self._value

#     def get_and_report(
#         self,
#     ) -> int:
#         with self._lock:
#             current = self._value
#             self._value = 0
#             return current

#     def get(self) -> int:
#         with self._lock:
#             return self._value


# def worker(counter: ThreadSafeCounter, increments: int):
#     for _ in range(increments):
#         counter.increment()
#         time.sleep(random.uniform(0.001, 0.01))  # 模拟一些延迟


# def main():
#     counter = ThreadSafeCounter()
#     num_threads = 5
#     increments_per_thread = 100

#     threads = []
#     for _ in range(num_threads):
#         t = threading.Thread(target=worker, args=(counter, increments_per_thread))
#         t.start()
#         threads.append(t)  # type: ignore

#     # 周期性报告
#     for _ in range(5):
#         time.sleep(0.1)
#         current = counter.get()
#         print(f"周期计数: {current}")

#     for t in threads:
#         t.join()  # type: ignore

#     # 最终统计
#     final_current = counter.get_and_report()
#     print(f"最终周期计数: {final_current}")


# if __name__ == "__main__":
#     main()
