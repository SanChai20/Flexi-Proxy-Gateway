import concurrent.futures
import os
import random
import threading
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dotenv import load_dotenv

load_dotenv()

encrypted_msg = b't\xdfD\x13\xb0\xf4\xc7\x9dF?\x0ex\xc4\xdf9H\tP%\xfdXaO\x1bEI\xd9\xdbQ\xa7P\xba\x11e\x0fg1\xb6\xf4\xf1\xc6I\xa7\x08:A\xdf\xe2\xc2\x9b\xb2u\x1e/\x06"\xc5P\xe1\xce\xb8<\xcf\xa7[\xc6\xfa]Gt\xc4\xc0\x87\xe0\xc2\xed\xca_=\xc9\x0c\xeb\xa2\x9f\xe9\x94o\x90\x83\xd9\xf3\x15@\xd7\\\xfd\x19\xbe1\xb9\x10\xc0v\\\xf3S\xf44\xe0Ei\xa0\xbc\x19\x10\x02=5\x0c\xea)\x01\xeev\xc2\xfa\xf0\xfc4{";y\xb4\x80!\xf8/\x818\xdd\xb5\xe7\x10\xe3-m\xadb\x99\xb3\xae\x7f\xd4\xdd\x12\x7f\xa1P\x9a\xb3.\xb2\x8ao\x017BF\xccy\xe4\xd4_\xda\x10m\xea\xef\x8a\xf63P\x9e5\xc5\xec0{2\xab\xd4\xa2\xd0z<\xfe6\xbb\x02\xe4\xc8=\xe1\xe0\xf7\x85>\xefeM\xc2\xec\\XvD:\x138\x8eL9\n\xc5\x12\x9a\x05\xba\xc1Q\xcbI}\x9a\xd8<)s^\xcb\xc1\x87f x\xad\x12\x8e\xf8"\xbd{\x1b\x84(\'\x16\x81w\xf1<\xb6\x9b\x83(jJ\x10Z(\xd0\xa2\xe7\x1cp\xa1z\x12\x0cP\xe2\x15\xc5S\xc7\xe8\x91\xb9\xcah\x81\xa1)\xa5\xfd2\xa0\xb73g^\xec\x93\x9e\xb7\xc5\x9b\x01X\xca\xbe\xcc\xca\x95\x8f\xc7\x9d\n\xc6\x19D\nS\xd6\x9bF\x87D\xda\xba\xd4(\xd4\xd2\x8c\x04\xc9\xa8\x8d\xf0\xee\xb4f\x06S\x8c\x8e \x12\x06\x8a\x19t\xd1\xbeJ1+\x08\xddv\xdb\\GQL\x997]<%\x81b$\x1d\xfa\xe8,\x17\xbe\xbc\xa4}\x81\xe2\x95\xd1\x98n\xbeQ\x9a1\xb1\n^~}\xd2\xfc\xc0AW&\xa4l#7\x1ei\xe73Pv\xb3*(\n\xd8\xb8\xd0\x04\xd9\xc8F\xd7$4x\x8a\xf8\xf8a$\x03\x90\xcb\x89\x87\x15\x06N~%G\xdd\xa5g\x15i\xc8\xf3h\xc0\x97\xcap\n-!xkR3\xb7GK\x895+\x9b\x9e\x9f5\x14\x0c\r\xec\x04nx\xf4\xda\xf6\xa4"\xf4\xb0\x10S\xa7\x1aS\xbe{\xc1\x99|\xa7\x1c\xfd,\x1c\x8a\x1c\xd6\x18\xe8\x1e\x04\xaf'
expected = "Hello world"


class KeyPairLoader:
    _private_key: Optional[rsa.RSAPrivateKey] = None
    _public_key: Optional[str] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        raise TypeError(f"{cls.__name__} may not be instantiated")

    @classmethod
    def public_key(cls) -> Optional[str]:
        return cls._public_key

    @classmethod
    def decrypt(cls, msg_bytes: bytes) -> Optional[str]:
        if cls._private_key is None:
            return None
        with cls._lock:
            try:
                message_decrypted: bytes = cls._private_key.decrypt(
                    msg_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                return message_decrypted.decode("utf-8")
            except Exception as e:
                print(f"Decrypt failed: {e}")
                return None

    @classmethod
    def load(cls) -> bool:
        key_file_path = Path.cwd() / "key.pem"
        public_file_path = Path.cwd() / "public.pem"

        if not key_file_path.exists() or not public_file_path.exists():
            print("Key files not found")
            return False

        try:
            private_pem_bytes = key_file_path.read_bytes()
            public_pem_bytes = public_file_path.read_bytes()
            password = str(os.getenv("PROXY_SERVER_KEYPAIR_PWD")).encode("ascii")

            private_key = serialization.load_pem_private_key(
                private_pem_bytes, password=password
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError(f"Expected RSAPrivateKey, got {type(private_key)}")

            cls._private_key = private_key
            cls._public_key = public_pem_bytes.decode("utf-8")
            print("Keys Correctly Loaded")
            return True

        except Exception as e:
            print(f"Key loading failed: {e}")
            return False

    @classmethod
    def unload(cls):
        cls._private_key = None
        cls._public_key = None


KeyPairLoader.load()


def extreme_concurrency_test(
    max_workers: int = 200, num_tasks: int = 20000, add_variance: bool = True
):
    """
    极高并发测试：高workers + 多任务 + 变异。
    - max_workers: 线程数（建议CPU核 x 10-20，但勿超500）。
    - num_tasks: 总解密调用（预期时间：~100-300s，视密钥大小）。
    - add_variance: 加随机延迟和干扰，增加竞争几率。
    """
    failed_details = []  # 收集失败案例（thread name + result）
    total_exceptions = 0

    def varied_decrypt():
        """变异版本：随机延迟 + 偶尔干扰"""
        if (
            add_variance and random.random() < 0.01
        ):  # 1%干扰：读public_key（无害，但混入）
            _ = KeyPairLoader.public_key()
        if add_variance:
            time.sleep(random.uniform(0.001, 0.005))  # 1-5ms延迟，延长重叠窗口

        result = KeyPairLoader.decrypt(encrypted_msg)
        if result != expected:
            failed_details.append(  # type: ignore
                f"Thread {threading.current_thread().name}: Got '{result}' (expected '{expected}')"
            )
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        start = time.time()
        futures = [executor.submit(varied_decrypt) for _ in range(num_tasks)]

        results = []
        for future in concurrent.futures.as_completed(
            futures, timeout=3000
        ):  # 5min总超时
            try:
                result = future.result(timeout=10)  # 每个任务10s超时
                results.append(result)  # type: ignore
            except concurrent.futures.TimeoutError:
                print("Task timeout!")
                total_exceptions += 1
                results.append(None)  # type: ignore
            except Exception as e:
                print(f"Future exception: {e}")
                total_exceptions += 1
                results.append(None)  # type: ignore

        end = time.time()

    success_rate = sum(1 for r in results if r == expected) / len(results)
    failed_count = len(results) - sum(1 for r in results if r == expected)
    throughput = num_tasks / (end - start)  # tasks/sec

    print(f"Extreme Test Results:")
    print(f"  Workers: {max_workers}, Tasks: {num_tasks}")
    print(f"  Success rate: {success_rate:.4f} ({int(success_rate * 100)}%)")
    print(f"  Time: {end - start:.2f}s, Throughput: {throughput:.2f} tasks/s")
    print(f"  Total failures: {failed_count}, Exceptions: {total_exceptions}")

    if failed_details:
        print(f"  Failed details (first 5): {failed_details[:5]}")

    return success_rate > 0.999  # 允许0.1%容忍（极小变异）


if __name__ == "__main__":
    print("Running extreme test...")
    is_success = extreme_concurrency_test(
        max_workers=200, num_tasks=20000, add_variance=True
    )
    print(f"All successful: {is_success}")
