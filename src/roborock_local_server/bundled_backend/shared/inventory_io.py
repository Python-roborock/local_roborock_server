from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .context import ServerContext

WEB_API_INVENTORY_FILE = "web_api_inventory.json"


def load_inventory(ctx: ServerContext) -> dict[str, Any]:
    path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def write_inventory(ctx: ServerContext, inventory: dict[str, Any]) -> None:
    path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    try:
        path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return
