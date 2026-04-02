from __future__ import annotations

import base64
import gzip
import json
from typing import Any

from shared.context import ServerContext

from ...auth.service import ok

_COUNTRY_LIST_JSON = {
    "countries": [
        {
            "abbr": "US",
            "code": "1",
            "region": "US",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "CN",
            "code": "86",
            "region": "CN",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "DE",
            "code": "49",
            "region": "EU",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
        {
            "abbr": "RU",
            "code": "7",
            "region": "RU",
            "mobileCodeAuthEnabled": True,
            "mobilePwdAuthEnabled": True,
            "emailCodeAuthEnabled": True,
            "emailPwdAuthEnabled": True,
        },
    ],
    "i18n": [
        {
            "lang": "en",
            "names": [
                {"abbr": "US", "name": "United States", "spell": "unitedstates"},
                {"abbr": "CN", "name": "China", "spell": "china"},
                {"abbr": "DE", "name": "Germany", "spell": "germany"},
                {"abbr": "RU", "name": "Russia", "spell": "russia"},
            ],
        }
    ],
}
_COUNTRY_LIST_D = base64.b64encode(gzip.compress(json.dumps(_COUNTRY_LIST_JSON, separators=(",", ":")).encode())).decode()


def match_country_version(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/country/version"


def match_country_list(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/country/list"


def build_country_version(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"v": 0})


def build_country_list(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"d": _COUNTRY_LIST_D})
