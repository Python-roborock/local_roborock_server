"""Bounded service logs and JSONL traces for a single server process.

Keep this outside bundled_backend: that package is also imported as ``shared``,
and both import paths must use the same per-file JSONL handlers and locks.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import threading
from collections.abc import Iterator
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import LoggingConfig


def _numbered_backups(path: Path) -> list[tuple[int, Path]]:
    backups: list[tuple[int, Path]] = []
    for candidate in path.parent.glob(f"{path.name}.*"):
        suffix = candidate.name[len(path.name) + 1:]
        if re.fullmatch(r"[1-9]\d*", suffix):
            backups.append((int(suffix), candidate))
    return sorted(backups, reverse=True)


def log_paths(path: Path) -> list[Path]:
    """Return numbered backups oldest first, then the active file.

    Discover existing backups independently of the current retention setting so
    startup recovery can run before a reduced retention setting removes them.
    """
    return [candidate for _, candidate in _numbered_backups(path)] + [path]


def iter_log_lines(path: Path) -> Iterator[str]:
    """Stream retained history in chronological order, tolerating missing files."""
    for candidate in log_paths(path):
        try:
            with candidate.open(encoding="utf-8", errors="replace") as handle:
                yield from handle
        except OSError:
            continue


def _trim_to_tail(path: Path, max_bytes: int) -> None:
    """Atomically keep recent complete lines without reading the full file."""
    if not path.exists() or path.stat().st_size <= max_bytes:
        return
    with path.open("rb") as handle:
        handle.seek(-max_bytes - 1, os.SEEK_END)
        chunk = handle.read(max_bytes + 1)
    preceding, tail = chunk[:1], chunk[1:]
    if preceding != b"\n":
        # The window starts mid-record (possibly mid UTF-8 character).
        _, _, tail = tail.partition(b"\n")
    # Never leave a partial JSON record from an interrupted write at the end.
    tail = tail[:tail.rfind(b"\n") + 1]
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(tail)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class BoundedRotatingFileHandler(RotatingFileHandler):
    """Rotate by UTF-8 byte size, including when no backups are requested.

    One record may exceed the threshold so a JSON object or traceback is never
    split during normal writes. Existing oversized files are trimmed at startup,
    after the supervisor has recovered persistent state from the original logs.
    """

    def __init__(self, path: Path, *, max_bytes: int, backup_count: int, keep_open: bool = True) -> None:
        if max_bytes <= 0 or backup_count < 0:
            raise ValueError("Log max_bytes must be positive and backup_count nonnegative")
        path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(path, maxBytes=max_bytes, backupCount=backup_count,
                         encoding="utf-8", errors="backslashreplace", delay=True)
        self.keep_open = keep_open
        for suffix_index, candidate in _numbered_backups(path):
            if suffix_index > backup_count:
                candidate.unlink(missing_ok=True)
            else:
                _trim_to_tail(candidate, max_bytes)
        _trim_to_tail(path, max_bytes)

    def _open(self):
        # Stable byte counts on Windows as well as Linux.
        return open(self.baseFilename, self.mode, encoding=self.encoding,
                    errors=self.errors, newline="\n")

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        if self.stream is None:
            self.stream = self._open()
        self.stream.seek(0, os.SEEK_END)
        size = self.stream.tell()
        encoded_size = len((self.format(record) + self.terminator).encode("utf-8", "backslashreplace"))
        return size > 0 and size + encoded_size > self.maxBytes

    def doRollover(self) -> None:
        if self.backupCount:
            super().doRollover()
        else:
            if self.stream is not None:
                self.stream.close()
                self.stream = None
            with open(self.baseFilename, "w", encoding="utf-8"):
                pass

    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        finally:
            # JSONL used to open per append. Keep that behavior to avoid holding
            # handles for arbitrary trace paths; Handler.handle still serializes
            # the complete size-check/rotation/write/close sequence.
            if not self.keep_open and self.stream is not None:
                self.stream.close()
                self.stream = None


_jsonl_handlers: dict[Path, BoundedRotatingFileHandler] = {}
_jsonl_lock = threading.Lock()


def configure_jsonl_logging(path: Path, *, max_bytes: int, backup_count: int) -> None:
    """Configure a trace before starting producers or accepting requests."""
    path = path.resolve()
    with _jsonl_lock:
        previous = _jsonl_handlers.pop(path, None)
        if previous is not None:
            previous.close()
        handler = BoundedRotatingFileHandler(
            path, max_bytes=max_bytes, backup_count=backup_count, keep_open=False,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        _jsonl_handlers[path] = handler


def append_jsonl_text(path: Path, encoded: str) -> None:
    path = path.resolve()
    with _jsonl_lock:
        handler = _jsonl_handlers.get(path)
        if handler is None:
            defaults = LoggingConfig()
            handler = BoundedRotatingFileHandler(
                path, max_bytes=defaults.max_bytes, backup_count=defaults.backup_count, keep_open=False,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            _jsonl_handlers[path] = handler
    handler.handle(logging.LogRecord("", logging.INFO, "", 0, encoded, (), None))
