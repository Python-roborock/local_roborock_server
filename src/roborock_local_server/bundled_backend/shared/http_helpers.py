"""HTTP helper functions shared by the HTTPS server."""

from __future__ import annotations

from typing import Any, Mapping


def classify_host(host: str) -> str:
    host = (host or "").split(":")[0].lower()
    if "wood-" in host:
        return "wood"
    if "iot." in host or host.startswith(("usiot", "euiot", "cniot", "ruiot")):
        return "iot"
    if host.startswith("api-") or ".api-" in host or "api-" in host:
        return "api"
    return "api" if host else "unknown"


def strip_roborock_prefix(path: str) -> str:
    prefixes = ("/.roborock.com", "/roborock.com", "/.roborock.com/")
    for prefix in prefixes:
        if path.startswith(prefix):
            remainder = path[len(prefix) :]
            if not remainder:
                return "/"
            return remainder if remainder.startswith("/") else "/" + remainder
    return path


def pick_first(values: list[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


# Route builders receive no request headers. These headers reach them as
# "__header_<name>" query pseudo-params, like "__host".
_ROUTE_HEADERS = ("v", "n", "t", "s")
_ROUTE_HEADER_PREFIX = "__header_"


def with_route_headers(query_params: dict[str, list[str]], headers: Mapping[str, str]) -> dict[str, list[str]]:
    """Return query_params with the route headers added as pseudo-params.

    A query cannot supply them: pseudo-params from the query are dropped.
    """
    params = {key: values for key, values in query_params.items() if not key.startswith(_ROUTE_HEADER_PREFIX)}
    for name in _ROUTE_HEADERS:
        value = str(headers.get(name) or "").strip()
        if value:
            params[f"{_ROUTE_HEADER_PREFIX}{name}"] = [value]
    return params


def route_header(query_params: dict[str, list[str]], name: str) -> str:
    """Return a header that with_route_headers added, or "" if it was absent."""
    values = query_params.get(f"{_ROUTE_HEADER_PREFIX}{name}") or [""]
    return values[0]


def wrap_response(data: Any) -> dict[str, Any]:
    return {
        "success": True,
        "code": 200,
        "msg": "success",
        "data": data,
        "result": data,
    }
