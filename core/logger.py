import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Optional


class LoggerManager:
    _logger: Optional[logging.Logger] = None
    _initialized: bool = False

    @classmethod
    def init(
        cls,
        log_file: str = "app.log",
        log_dir: str = ".",
        level: int = logging.INFO,
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 7,
    ):
        if cls._initialized:
            return
        cls._initialized = True

        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.setLevel(level)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_path = Path(log_dir) / log_file
        file_handler = TimedRotatingFileHandler(
            file_path, when=when, interval=interval, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # Dev [TODO...Remove]
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        cls._logger = logging.getLogger(__name__)

    @classmethod
    def info(cls, msg: str):
        if cls._logger:
            cls._logger.info(msg)

    @classmethod
    def warn(cls, msg: str):
        if cls._logger:
            cls._logger.warning(msg)

    @classmethod
    def error(cls, msg: str):
        if cls._logger:
            cls._logger.error(msg)

    @classmethod
    def debug(cls, msg: str):
        if cls._logger:
            cls._logger.debug(msg)


LoggerManager.init()
