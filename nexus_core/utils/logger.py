import logging
import json
import sys
import os
import time
import datetime
import pathlib
from typing import Optional, Dict

# ANSI color codes
RESET = '\033[0m'
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
CYAN = '\033[36m'
MAGENTA = '\033[35m'
WHITE = '\033[37m'
DIM = '\033[2m'

class NexusJSONFormatter(logging.Formatter):
    """
    Formatter for structured JSON logging compatible with ELK Stack and Grafana Loki.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "ts": datetime.datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
            "extra": {k: v for k, v in record.__dict__.items() if k not in vars(logging.LogRecord)}
        }
        return json.dumps(log_record)

class NexusConsoleFormatter(logging.Formatter):
    """
    Formatter for colorful console logging.
    """
    def format(self, record: logging.LogRecord) -> str:
        level_color = {
            'DEBUG': DIM,
            'INFO': GREEN,
            'WARNING': YELLOW,
            'ERROR': RED,
            'CRITICAL': MAGENTA
        }.get(record.levelname, WHITE)
        formatted_time = time.strftime("%H:%M:%S", time.localtime(record.created))
        formatted_millis = f"{record.msecs:03.0f}"
        return f"{formatted_time}.{formatted_millis} [{level_color}{record.levelname}{RESET}] {CYAN}{record.name}{RESET} → {record.getMessage()}"

class NexusLogger:
    """
    Custom logger class for NEXUS with JSON and console handlers.
    """
    def __init__(self, name: str, module: str = "nexus", log_dir: Optional[str] = None, context: Optional[Dict] = None):
        self.name = name
        self.module = module
        self.context = context or {}
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(NexusConsoleFormatter())
        self.logger.addHandler(console_handler)

        if log_dir:
            log_path = pathlib.Path(log_dir) / f"{name}.log"
            file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
            file_handler.setFormatter(NexusJSONFormatter())
            self.logger.addHandler(file_handler)

    def _log(self, level: int, msg: str, **extra):
        extra_context = {**self.context, **extra}
        self.logger.log(level, msg, extra=extra_context)

    def info(self, msg: str, **extra):
        self._log(logging.INFO, msg, **extra)

    def warning(self, msg: str, **extra):
        self._log(logging.WARNING, msg, **extra)

    def error(self, msg: str, **extra):
        self._log(logging.ERROR, msg, **extra)

    def debug(self, msg: str, **extra):
        self._log(logging.DEBUG, msg, **extra)

    def critical(self, msg: str, **extra):
        self._log(logging.CRITICAL, msg, **extra)

    def set_context(self, **kwargs):
        self.context.update(kwargs)

class TimedOperation:
    """
    Context manager for timing operations and logging their duration.
    """
    def __init__(self, logger: NexusLogger, operation: str):
        self.logger = logger
        self.operation = operation
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        self.logger.info(f"Starting: {self.operation}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = time.time()
        duration_ms = (end_time - self.start_time) * 1000
        if exc_type is not None:
            self.logger.error(f"Error in {self.operation}: {exc_val}", exc_info=(exc_type, exc_val, exc_tb))
        else:
            self.logger.info(f"Completed: {self.operation} in {duration_ms:.2f}ms")


def get_logger(name: str, module: str = "nexus", **context) -> NexusLogger:
    """
    Factory function to create a configured NexusLogger instance.
    """
    log_dir = os.getenv('NEXUS_LOG_DIR', None)
    return NexusLogger(name, module, log_dir, context)

LOG_FORMAT_JSON = os.getenv('NEXUS_JSON_LOGS', '0') == '1'
