from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import build_code_send_response, build_login_submit_response, ok

_LOGIN_SIGN_KEY = "DnNAYQHCVFIdHSKx"


def match_login_key_sign(path: str) -> bool:
    return path.rstrip("/") == "/api/v3/key/sign"


def match_login_sms_code_send(path: str) -> bool:
    return path.rstrip("/") == "/api/v3/sms/sendCode"


def match_login_password_submit(path: str) -> bool:
    clean = path.rstrip("/")
    return clean in {
        "/api/v3/auth/email/login",
        "/api/v3/auth/phone/login",
        "/api/v3/auth/mobile/login",
    }


def build_login_key_sign(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"k": _LOGIN_SIGN_KEY})


build_login_sms_code_send = build_code_send_response
build_login_password_submit = build_login_submit_response
