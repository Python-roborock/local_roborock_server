from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import extract_explicit_did


def match(path: str) -> bool:
    return "nc" in path and ("prepare" in path or path.endswith("/nc"))


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    nc_data = ctx.nc_payload(query_params, body_params)
    did = str(nc_data.get("d") or ctx.extract_did(query_params, body_params))
    explicit_did = extract_explicit_did(query_params, body_params)
    minimal_nc: dict[str, Any] = {
        "s": str(nc_data.get("s") or ""),
        "t": str(nc_data.get("t") or ""),
        "k": str(
            nc_data.get("k")
            or ctx.resolve_device_localkey(did=did, source="nc_prepare_minimal", assign_if_missing=False)
            or ctx.localkey
        ),
    }
    if did:
        minimal_nc["d"] = did
    encrypted = ctx.encrypt_bootstrap_result(explicit_did, minimal_nc) if explicit_did else None
    if encrypted is not None:
        return encrypted
    return wrap_response(minimal_nc)

