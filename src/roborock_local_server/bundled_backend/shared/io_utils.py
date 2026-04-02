"""I/O and logging helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

_FILE_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
_STREAM_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
_JSONL_STREAM_LOGGER_NAME = "real_stack.jsonl"


def _make_stream_handler() -> logging.Handler:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(_STREAM_LOG_FORMAT))
    return handler


def _jsonl_stream_logger() -> logging.Logger:
    logger = logging.getLogger(_JSONL_STREAM_LOGGER_NAME)
    logger.propagate = False
    if not logger.handlers:
        if logger.level == logging.NOTSET:
            logger.setLevel(logging.INFO)
        logger.addHandler(_make_stream_handler())
    return logger


def append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    encoded = json.dumps(entry, ensure_ascii=True, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(encoded + "\n")
    _jsonl_stream_logger().debug("[%s] %s", path.name, encoded)


def setup_file_logger(name: str, path: Path) -> logging.Logger:
    logger = logging.getLogger(f"real_stack.{name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(_FILE_LOG_FORMAT))
    logger.addHandler(handler)
    logger.addHandler(_make_stream_handler())
    return logger


def payload_preview(payload: bytes, max_chars: int = 280) -> str:
    if not payload:
        return ""
    try:
        text = payload.decode("utf-8")
        if len(text) > max_chars:
            return text[:max_chars] + "...[truncated]"
        return text
    except UnicodeDecodeError:
        hex_data = payload.hex()
        if len(hex_data) > max_chars:
            return hex_data[:max_chars] + "...[truncated]"
        return hex_data
