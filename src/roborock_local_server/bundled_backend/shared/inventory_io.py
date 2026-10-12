from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import json
import logging
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .context import ServerContext

WEB_API_INVENTORY_FILE = "web_api_inventory.json"
_LOGGER = logging.getLogger(__name__)
_LOCKS: dict[Path, Any] = {}
_LOCKS_GUARD = threading.Lock()


@contextmanager
def inventory_transaction(path: Path):
    """Serialize inventory read/modify/write within this server process.

    Refuse to mutate corrupt existing inventory rather than replacing it with
    an empty fallback. External writers must stop the server first.
    """
    path = path.resolve()
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(path, threading.RLock())
    with lock:
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("Existing inventory must be a JSON object")
        yield


def inventory_mutation(function):
    """Protect a synchronous context-first inventory mutation."""
    @wraps(function)
    def wrapped(ctx, *args, **kwargs):
        with inventory_transaction(ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE):
            return function(ctx, *args, **kwargs)
    return wrapped


def atomic_write_inventory(path: Path, inventory: dict[str, Any]) -> None:
    """Replace only after a complete write; propagate failures to the caller."""
    payload = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_inventory(ctx: ServerContext) -> dict[str, Any]:
    path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def write_inventory(ctx: ServerContext, inventory: dict[str, Any]) -> bool:
    path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    try:
        atomic_write_inventory(path, inventory)
    except OSError:
        _LOGGER.exception("Unable to persist inventory")
        return False
    return True
