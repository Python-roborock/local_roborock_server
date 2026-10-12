"""Redacted summary view over the HTTP/MQTT/MITM protocol jsonl logs, for
the admin dashboard's Activity panel.

decompiled_http.jsonl / decompiled_mqtt.jsonl / mitm_activity.jsonl (see
AppPaths in config.py) have no rotation or size cap, and can contain
sensitive data: HTTP request headers and onboarding-adjacent bodies can
carry localKey/passwords, MQTT entries carry fully-decrypted device RPC
payloads, and mitm_activity.jsonl (populated by mitm_redirect.py's optional
--activity-sync, capturing traffic between the native Roborock app and
Roborock's real cloud) can carry actual Roborock account tokens. So by
default this module only ever returns safe metadata (method/path/topic/RPC
method name, sizes, timestamps) - never raw headers, bodies, or payloads.

Set ROBOROCK_SERVER_ACTIVITY_RAW=1 to return complete, unredacted entries
instead. This is an explicit, deployment-time operator opt-in (matching how
rethink exposes its own traffic view), not a per-view toggle in the UI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Collection, Mapping

ENV_ACTIVITY_RAW = "ROBOROCK_SERVER_ACTIVITY_RAW"
DEFAULT_LIMIT = 200
MAX_LIMIT = 500

_CHUNK_SIZE = 65536
_MAX_TAIL_BYTES = 8_000_000


def activity_raw_enabled(env: Mapping[str, str]) -> bool:
    return str(env.get(ENV_ACTIVITY_RAW, "") or "").strip().lower() in {"1", "true", "yes", "on"}


def _tail_lines(path: Path, max_lines: int) -> list[str]:
    """The last `max_lines` lines of `path`, without reading the whole file.

    These jsonl files grow unbounded, so a plain read-then-split is out.
    """
    if max_lines <= 0 or not path.exists():
        return []
    with path.open("rb") as handle:
        handle.seek(0, 2)
        position = handle.tell()
        buffer = b""
        bytes_read = 0
        while position > 0 and buffer.count(b"\n") <= max_lines and bytes_read < _MAX_TAIL_BYTES:
            read_size = min(_CHUNK_SIZE, position)
            position -= read_size
            handle.seek(position)
            buffer = handle.read(read_size) + buffer
            bytes_read += read_size
    lines = buffer.split(b"\n")
    if position > 0 and lines:
        # The first entry is a partial line, unless we reached the start of the file.
        lines = lines[1:]
    text_lines = [line.decode("utf-8", errors="replace") for line in lines if line.strip()]
    return text_lines[-max_lines:]


def _parse_jsonl_lines(lines: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
    return entries


def _summarize_http_entry(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": raw.get("time"),
        "source": "http",
        "method": raw.get("method"),
        "path": raw.get("clean_path") or raw.get("raw_path"),
        "route": raw.get("route"),
        "did": raw.get("did"),
        "pid": raw.get("pid"),
        "remote": raw.get("remote"),
        "body_len": raw.get("body_len"),
    }


def _summarize_mqtt_entry(raw: dict[str, Any]) -> dict[str, Any]:
    decoded_messages = raw.get("decoded_messages")
    rpc_methods: list[str] = []
    if isinstance(decoded_messages, list):
        for decoded in decoded_messages:
            if not isinstance(decoded, dict):
                continue
            rpc = decoded.get("rpc")
            if isinstance(rpc, dict) and rpc.get("method"):
                rpc_methods.append(str(rpc.get("method")))
    payload_hex = raw.get("payload_hex")
    payload_len = len(payload_hex) // 2 if isinstance(payload_hex, str) else None
    return {
        "time": raw.get("time"),
        "source": "mqtt",
        "direction": raw.get("direction"),
        "topic": raw.get("topic"),
        "rpc_methods": rpc_methods,
        "decoded": bool(decoded_messages),
        "payload_len": payload_len,
    }


def _summarize_mitm_entry(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": raw.get("time"),
        "source": "mitm",
        "host": raw.get("host"),
        "method": raw.get("method"),
        "path": raw.get("path"),
        "status": raw.get("status"),
        "rewritten": bool(raw.get("rewritten")),
    }


# A device-filtered view reads a deeper tail, since most of a busy log belongs
# to other devices and the newest `limit` lines may hold none of this one's.
_DEVICE_FILTER_TAIL_FACTOR = 10


def _path_segments(value: Any) -> set[str]:
    return {part for part in str(value or "").split("/") if part}


def _entry_mentions_device(entry: dict[str, Any], device_ids: frozenset[str]) -> bool:
    """True when the entry's did, path or MQTT topic names one of the device's ids.

    Matches whole path/topic segments, never substrings, so a short id can't
    pick up unrelated traffic.
    """
    if str(entry.get("did") or "") in device_ids:
        return True
    for key in ("clean_path", "raw_path", "path", "topic"):
        if _path_segments(entry.get(key)) & device_ids:
            return True
    return False


def read_recent_activity(
    *,
    http_jsonl_path: Path,
    mqtt_jsonl_path: Path,
    mitm_jsonl_path: Path | None = None,
    limit: int = DEFAULT_LIMIT,
    raw: bool = False,
    device_ids: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """Most recent `limit` HTTP+MQTT(+MITM) activity entries, newest first.

    `raw=True` returns complete, unredacted entries (see module docstring);
    the default returns metadata-only summaries with no header/body/payload
    content at all. `mitm_jsonl_path` is optional since not every deployment
    runs mitm_redirect.py with --activity-sync.

    `device_ids` keeps only entries that name one of those ids (a vacuum's
    did, duid or MQTT user). An empty collection matches nothing.
    """
    wanted = frozenset(str(item) for item in device_ids if str(item)) if device_ids is not None else None
    tail = limit * _DEVICE_FILTER_TAIL_FACTOR if device_ids is not None else limit
    http_entries = _parse_jsonl_lines(_tail_lines(http_jsonl_path, tail))
    mqtt_entries = _parse_jsonl_lines(_tail_lines(mqtt_jsonl_path, tail))
    mitm_entries = _parse_jsonl_lines(_tail_lines(mitm_jsonl_path, tail)) if mitm_jsonl_path else []
    if wanted is not None:
        http_entries = [entry for entry in http_entries if _entry_mentions_device(entry, wanted)]
        mqtt_entries = [entry for entry in mqtt_entries if _entry_mentions_device(entry, wanted)]
        mitm_entries = [entry for entry in mitm_entries if _entry_mentions_device(entry, wanted)]

    if raw:
        combined = [{"source": "http", **entry} for entry in http_entries]
        combined += [{"source": "mqtt", **entry} for entry in mqtt_entries]
        combined += [{"source": "mitm", **entry} for entry in mitm_entries]
    else:
        combined = [_summarize_http_entry(entry) for entry in http_entries]
        combined += [_summarize_mqtt_entry(entry) for entry in mqtt_entries]
        combined += [_summarize_mitm_entry(entry) for entry in mitm_entries]

    combined.sort(key=lambda entry: str(entry.get("time") or ""), reverse=True)
    return combined[:limit]
