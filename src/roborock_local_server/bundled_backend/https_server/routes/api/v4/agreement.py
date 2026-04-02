from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok

_AGREEMENT_LATEST_DATA = {
    "userAgreement": {
        "version": "16.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/7f65ba7da3ab4e0db1177c366a03d06e.html",
            "en": "https://files.roborock.com/iot/doc/8765be2db5dd4b87bac8ba82ba1b6878.html",
        },
        "popupText": None,
    },
    "privacyProtocol": {
        "version": "17.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/e8143aeb64544008b864e1b06cde4543.html",
            "en": "https://files.roborock.com/iot/doc/d1945f29e9794bdba80496a998298751.html",
        },
        "popupText": None,
    },
    "personalInfoCol": {
        "version": "2.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1df929732c104dcc9f0f489d5b368cc9.html",
            "en": "https://files.roborock.com/iot/doc/d24f84ac2f3d4b50a9897d64b4faacbd.html",
        },
        "popupText": None,
    },
    "thirdPartyInfoShare": {
        "version": "3.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/23f480bb58e14db593639878095249a6.html",
            "en": "https://files.roborock.com/iot/doc/dd725a4e900a47b382897a59da09aed5.html",
        },
        "popupText": None,
    },
    "improvementPlan": {
        "version": "1.0",
        "langUrl": {
            "zh-Hans": "https://files.roborock.com/iot/doc/1184a5a566c24bd1b520e4063cae1a14.html",
            "en": "https://files.roborock.com/iot/doc/3e754f53d8934487ad448a5defec6caa.html",
        },
        "popupText": None,
    },
}


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v4/app/agreement/latest"


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(_AGREEMENT_LATEST_DATA)
