from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from .service import (
    build_code_send_response,
    build_code_validate_response,
    build_login_submit_response,
    ok,
)


def match_login_ml_c(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/ml/c"


def match_login_email_code_send(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/sendEmailCode"


def match_login_sms_code_send(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/sendSmsCode"


def match_login_code_validate(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v1/validateEmailCode",
        "/api/v1/validateSmsCode",
    }


def match_login_code_submit(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/loginWithCode"


def match_login_password_submit(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/login"


def build_login_ml_c(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"r": False})


build_login_email_code_send = build_code_send_response
build_login_sms_code_send = build_code_send_response
build_login_code_validate = build_code_validate_response
build_login_code_submit = build_login_submit_response
build_login_password_submit = build_login_submit_response
