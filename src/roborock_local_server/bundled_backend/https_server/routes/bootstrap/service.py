"""Shared helpers for bootstrap route handlers."""

from __future__ import annotations

from typing import Sequence


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
    return _first_non_empty(
        (query_params.get("did") or [])
        + (query_params.get("d") or [])
        + (query_params.get("duid") or [])
        + (body_params.get("did") or [])
        + (body_params.get("d") or [])
        + (body_params.get("duid") or [])
    )
