import random
import threading
import time
import unittest

# 假设你的原 AdapterCacheEntry 定义（如果用 mock，替换为项目版）
from collections import namedtuple  # 只为测试；实际 import 你的类
from typing import Dict, Optional  # 你的原 import，假设有

from cachetools import LRUCache as CachetoolsLRUCache

AdapterCacheEntry = namedtuple("AdapterCacheEntry", ["timestamp", "ttl", "value"])


# 你的原 Config（假设有）
class Config:
    LRU_MAX_CACHE_SIZE = 100


class LRUCache:
    """Thread-safe LRU + per-entry TTL Cache，使用 cachetools 实现高效 LRU"""

    _cache: CachetoolsLRUCache[str, "AdapterCacheEntry"]

    def __init__(self, max_size: Optional[int] = None):
        self._max_size = max_size or Config.LRU_MAX_CACHE_SIZE
        self._cache = CachetoolsLRUCache(
            maxsize=self._max_size
        )  # O(1) LRU，内部 OrderedDict
        self._lock = threading.RLock()  # 包装线程安全
        # 注意：cachetools 无内置锁，所以加 RLock

    def get(self, key: str) -> Optional[AdapterCacheEntry]:
        with self._lock:
            if key not in self._cache:
                return None
            entry = self._cache[key]
            # TTL 检查（per-entry）
            if time.time() - entry.timestamp > entry.ttl:  # type: ignore
                del self._cache[key]  # 自动触发 LRU 调整
                return None
            # LRU: 访问后移动到末尾（cachetools 自动 O(1)）
            self._cache.move_to_end(key)  # 显式，确保最近访问
            return entry

    def set(self, key: str, value: AdapterCacheEntry) -> None:
        with self._lock:
            # LRU: 如果存在，自动 move_to_end；否则检查大小
            if key in self._cache:
                self._cache.move_to_end(
                    key
                )  # 更新但不替换（如果要覆盖 value，可 self._cache[key] = value）
            else:
                # 满载：自动弹出最旧（O(1)）
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=False)  # last=False: 弹出最旧（LRU）
            # 存入：不修改 timestamp/ttl（信任调用者传入新鲜）
            self._cache[key] = value

    def clear_expired(self) -> None:
        with self._lock:
            now = time.time()
            # 全扫 O(n)，但 n小（max_size=100）
            expired = [
                k
                for k in list(self._cache)
                if now - self._cache[k].timestamp > self._cache[k].ttl  # type: ignore
            ]
            for k in expired:
                del self._cache[k]

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    # 辅助方法（测试/调试用）
    def get_order(self) -> list[str]:
        with self._lock:
            return list(self._cache.keys())  # OrderedDict 顺序: 最旧 -> 最近

    def is_consistent(self) -> bool:
        with self._lock:
            return len(self._cache) <= self._max_size

    def get_keys(self) -> list[str]:
        with self._lock:
            return list(self._cache.keys())


class TestLRURace(unittest.TestCase):
    def setUp(self):
        self.cache = LRUCache()

    def test_race_condition_hot_key(self):
        """高争用测试: 所有线程操作同一 key，暴露无锁 race (size 超限 / 不一致 / 错误)"""
        hot_key = "hot_key_123"  # 单一 key，最大冲突
        num_threads = 100  # 线程数：适中，快速 fail
        ops_per_thread = 100  # 总 ops=10k，~1-2s 运行
        print(
            f"Starting race test: {num_threads} threads, {ops_per_thread} ops/thread on 1 hot key..."
        )

        def worker(thread_id):
            """每个线程: 随机 set/get/clear hot_key"""
            random.seed(thread_id)  # 确定性随机
            for op_num in range(ops_per_thread):
                op = random.choice(["set", "get", "clear"])  # 33% 各
                if op == "set":
                    # 插入/更新 hot_key，触发 size check + LRU move
                    ttl = random.uniform(0.01, 10)  # 随机 TTL，有些易过期
                    value = f"value_from_thread_{thread_id}_op_{op_num}"
                    entry = AdapterCacheEntry(time.time(), ttl, value)
                    self.cache.set(hot_key, entry)
                elif op == "get":
                    # get: 访问 + move to end（order race）
                    retrieved = self.cache.get(hot_key)
                    if retrieved and retrieved.value.startswith(  # type: ignore
                        f"value_from"
                    ):  # 简单验证
                        pass  # OK，模拟使用
                else:  # clear
                    # clear: 扫描 + del，可能删 hot_key，与 set/get 冲突
                    self.cache.clear_expired()

                # 微 sleep: 增加切换概率，暴露 race（0-0.1ms）
                time.sleep(random.uniform(0, 0.0001))

            # 每个线程结束检查（增加 fail 机会）
            current_size = self.cache.size()
            if current_size > Config.LRU_MAX_CACHE_SIZE:
                raise AssertionError(
                    f"Size {current_size} > max {Config.LRU_MAX_CACHE_SIZE} (concurrent inserts without proper pop)"
                )
            if not self.cache.is_consistent():
                raise AssertionError(
                    f"Inconsistent: order={self.cache.get_order()}, cache_keys={list(self._cache.keys())}"  # type: ignore
                )

        # 启动线程
        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(num_threads)
        ]
        start_time = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()  # 等待所有完成
        end_time = time.time()

        # 最终验证
        final_size = self.cache.size()
        print(
            f"Race test completed in {end_time - start_time:.2f}s. Final size: {final_size}"
        )
        print(f"Order: {self.cache.get_order()}, Cache keys: {list(self.cache.keys())}")  # type: ignore

        # 断言：暴露问题
        if final_size > Config.LRU_MAX_CACHE_SIZE:
            raise AssertionError(
                f"Size exploded to {final_size} > max (race: multiple inserts skipped pop)"
            )
        if not self.cache.is_consistent():
            raise AssertionError(
                "Cache and order inconsistent (race: concurrent remove/append)"
            )

        # 额外：hot_key 应存在或一致
        if hot_key in self._cache or hot_key in self._order:  # type: ignore
            if hot_key not in self._cache or hot_key not in self._order:  # type: ignore
                raise AssertionError(
                    "Hot key partially present (race: del/add timing issue)"
                )

        print("Race test PASSED (but unlikely without lock - rerun to confirm)")


if __name__ == "__main__":
    unittest.main(verbosity=2)  # 详细输出
