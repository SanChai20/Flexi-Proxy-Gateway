import threading
from typing import Literal


class ProxyRequestCounter:

    _value: int = 0
    _lock: threading.Lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def increment(cls) -> int:
        with cls._lock:
            cls._value += 1
            return cls._value

    @classmethod
    def status(cls) -> str:
        with cls._lock:
            if cls._value < 100:
                status: Literal["unavailable", "spare", "busy", "full"] = "spare"
            elif cls._value < 500:
                status = "busy"
            else:
                status = "full"
            cls._value = 0
            return status
