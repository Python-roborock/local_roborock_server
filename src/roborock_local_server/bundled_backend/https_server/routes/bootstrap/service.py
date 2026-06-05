"""Shared helpers for bootstrap route handlers."""

from __future__ import annotations

from typing import Sequence

_DEVICE_ID_KEYS = ("did", "d", "duid", "device_id", "deviceId", "device_did", "deviceDid")


def _first_non_empty(values: Sequence[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


def request_host_override(query_params: dict[str, list[str]]) -> str:
    values = query_params.get("__host") or []
    for value in values:
        candidate = str(value or "").strip()
        if candidate:
            return candidate
    return ""


def extract_explicit_did(query_params: dict[str, list[str]], body_params: dict[str, list[str]]) -> str:
    values: list[str] = []
    for key in _DEVICE_ID_KEYS:
        values.extend(query_params.get(key) or [])
    for key in _DEVICE_ID_KEYS:
        values.extend(body_params.get(key) or [])
    return _first_non_empty(values)
