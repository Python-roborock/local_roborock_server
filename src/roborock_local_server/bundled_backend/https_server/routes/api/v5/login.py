from __future__ import annotations

from ...auth.service import (
    build_code_send_response,
    build_code_validate_response,
    build_login_submit_response,
    build_password_reset_response,
)


def match_login_email_code_send(path: str) -> bool:
    return path.rstrip("/") == "/api/v5/email/code/send"


def match_login_sms_code_send(path: str) -> bool:
    return path.rstrip("/") == "/api/v5/sms/code/send"


def match_login_code_validate(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v5/email/code/validate",
        "/api/v5/sms/code/validate",
    }


def match_login_code_submit(path: str) -> bool:
    clean = path.rstrip("/")
    return clean in {
        "/api/v5/auth/email/login/code",
        "/api/v5/auth/phone/login/code",
        "/api/v5/auth/mobile/login/code",
    }


def match_login_password_submit(path: str) -> bool:
    clean = path.rstrip("/")
    return clean in {
        "/api/v5/auth/email/login/pwd",
        "/api/v5/auth/phone/login/pwd",
        "/api/v5/auth/mobile/login/pwd",
    }


def match_login_password_reset(path: str) -> bool:
    return path.rstrip("/") in {
        "/api/v5/user/password/mobile/reset",
        "/api/v5/user/password/email/reset",
    }


build_login_email_code_send = build_code_send_response
build_login_sms_code_send = build_code_send_response
build_login_code_validate = build_code_validate_response
build_login_code_submit = build_login_submit_response
build_login_password_submit = build_login_submit_response
build_login_password_reset = build_password_reset_response
