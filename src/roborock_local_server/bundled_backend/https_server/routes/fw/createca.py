"""Local answer for the camera's ``POST .../fwapi/createca`` TURN request.

Background (issue #18): when the app requests a live camera preview, the robot
firmware first fetches a TURN/STUN configuration from a fwapi endpoint before it
starts the WebRTC session. The host is derived from the onboarding region string
(``region[:15] + "iot.roborock.com"``), so with a short enough region it resolves
to this server. Until this route existed the request fell through to the catchall,
the robot got no TURN config, and ``start_camera_preview`` returned
``-10012 / request turnserver failed`` with the app showing an instant timeout.

This route answers with a TURN/STUN server operated alongside the stack (for
example coturn). The robot then completes the full WebRTC handshake against it and
a go2rtc ``roborock://`` consumer receives frames, all without reaching the
Roborock cloud. The response contract is reconstructed from a Saros 10R
(``roborock.vacuum.a144``); the firmware accepts a plain-JSON body:

    { "code": 200, "msg": "success",
      "data":   { url, user, pwd, ttl, urls, username, credential, realm },
      "result": { ...same object... } }

``data`` carries the legacy ``user``/``pwd`` field names and ``result`` the
ICE-style ``username``/``credential`` names; both are populated so either parser
in the firmware is satisfied. When ``[turn].enabled`` is false (the default) the
request falls through to the catchall, so behaviour is unchanged for anyone not
running a TURN server.
"""

from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ..bootstrap.catchall import build as _build_catchall

# The firmware posts to this path on the iot/fwapi host; accept common prefixes.
_MATCH_SUFFIX = "/fwapi/createca"


def match(path: str, _method: str = "POST") -> bool:
    return path.rstrip("/").endswith(_MATCH_SUFFIX)


def build_turn_payload(
    *, host: str, port: int, username: str, password: str, realm: str, ttl: int
) -> dict[str, Any]:
    """Build the TURN/STUN credential object the firmware expects."""
    turn_url = f"turn:{host}:{port}"
    stun_url = f"stun:{host}:{port}"
    return {
        "url": turn_url,
        "user": username,
        "pwd": password,
        "ttl": ttl,
        "urls": [turn_url, stun_url],
        "username": username,
        "credential": password,
        "realm": realm or host,
    }


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    if not getattr(ctx, "turn_enabled", False) or not getattr(ctx, "turn_host", ""):
        # No TURN server configured -> keep prior behaviour (camera unavailable).
        return _build_catchall(ctx, query_params, body_params, clean_path)
    payload = build_turn_payload(
        host=ctx.turn_host,
        port=ctx.turn_port,
        username=ctx.turn_username,
        password=ctx.turn_password,
        realm=ctx.turn_realm,
        ttl=ctx.turn_ttl,
    )
    return {"code": 200, "msg": "success", "data": payload, "result": payload}
