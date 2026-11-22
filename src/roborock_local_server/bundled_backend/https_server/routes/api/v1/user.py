from __future__ import annotations

from typing import Any

from shared.constants import region_country
from shared.context import ServerContext
from shared.data_helpers import as_bool, get_value

from ...auth.service import load_cloud_full_snapshot
from ...auth.service import load_cloud_user_data
from ...auth.service import ok

_DEFAULT_AVATAR_URL = "https://files.roborock.com/iot/default_avatar.png"


def match_get_url_by_email(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/getUrlByEmail"


def match_user_info(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/userInfo"


def match_user_roles(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/user/roles"


def match_logout(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and path.rstrip("/") == "/api/v1/logout"


def build_get_url_by_email(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    country, countrycode = region_country(ctx.region)
    return ok(
        {
            "url": ctx.api_url(),
            "countrycode": countrycode,
            "country": country,
        }
    )


def build_user_info(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    cloud_user_data = load_cloud_user_data(ctx) or {}
    snapshot = load_cloud_full_snapshot(ctx) or {}
    meta_value = snapshot.get("meta")
    meta = meta_value if isinstance(meta_value, dict) else {}
    username = str(meta.get("username") or "").strip()
    configured_email = str(getattr(ctx, "protocol_login_email", "") or "").strip()

    email = str(get_value(cloud_user_data, "email", default="") or "").strip()
    mobile = str(get_value(cloud_user_data, "mobile", default="") or "").strip()
    if configured_email:
        email = configured_email
    elif not email and "@" in username:
        email = username
    if not mobile and username.isdigit():
        mobile = username

    default_country, default_countrycode = region_country(ctx.region)
    country = str(get_value(cloud_user_data, "country", default=default_country) or default_country)
    countrycode = str(get_value(cloud_user_data, "countrycode", default=default_countrycode) or default_countrycode)
    nickname = str(get_value(cloud_user_data, "nickname", default="Local User") or "Local User")
    avatarurl = str(get_value(cloud_user_data, "avatarurl", "avatarUrl", default="") or "")
    if not avatarurl:
        avatarurl = _DEFAULT_AVATAR_URL

    return ok(
        {
            "email": email,
            "mobile": mobile,
            "countrycode": countrycode,
            "country": country,
            "nickname": nickname,
            "hasPassword": as_bool(get_value(cloud_user_data, "hasPassword", default=True), True),
            "avatarurl": avatarurl,
        }
    )


def build_user_roles(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok([])


def build_logout(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(True)
