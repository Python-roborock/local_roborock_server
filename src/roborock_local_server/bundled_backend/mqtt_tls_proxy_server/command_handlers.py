"""Command handler registry for decoded MQTT V1 RPC payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence


@dataclass(frozen=True)
class HandlerResult:
    """Result from handling one RPC request."""

    handled: dict[str, Any]
    state_updates: dict[str, Any] = field(default_factory=dict)


class RpcCommandHandler(Protocol):
    """Interface for handling decoded V1 RPC requests."""

    methods: set[str]

    def handle_request(self, request: dict[str, Any]) -> HandlerResult | None:
        """Handle a decoded RPC request payload."""


def _parse_fan_power(params: Any) -> int | None:
    if isinstance(params, int):
        return params
    if isinstance(params, dict):
        # set_clean_motor_mode sends [{"fan_power": 102, "water_box_mode": 202, ...}].
        value = params.get("fan_power")
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if isinstance(params, list) and params:
        first = params[0]
        if isinstance(first, dict):
            return _parse_fan_power(first)
        if isinstance(first, int):
            return first
        if isinstance(first, str):
            try:
                return int(first)
            except ValueError:
                return None
    return None


class FanPowerHandler:
    """Handles V1 fan-power request methods."""

    methods = {"set_custom_mode", "set_clean_motor_mode"}

    def handle_request(self, request: dict[str, Any]) -> HandlerResult | None:
        method = request.get("method")
        if method not in self.methods:
            return None
        fan_power = _parse_fan_power(request.get("params"))
        if fan_power is None:
            return None
        return HandlerResult(
            handled={"fan_power": fan_power, "method": method},
            state_updates={"fan_power": fan_power},
        )


class RpcCommandRegistry:
    """Routes decoded V1 RPC requests/responses to handlers and tracks state."""

    def __init__(self, handlers: Sequence[RpcCommandHandler] | None = None) -> None:
        self._handlers = list(handlers or [FanPowerHandler()])
        self._pending_by_id: dict[int, dict[str, Any]] = {}
        self._state: dict[str, Any] = {}

    @property
    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params")

        if isinstance(request_id, int):
            self._pending_by_id[request_id] = {
                "id": request_id,
                "method": method,
                "params": params,
            }

        if not isinstance(method, str):
            return None

        for handler in self._handlers:
            if method not in handler.methods:
                continue
            result = handler.handle_request(request)
            if result is None:
                continue
            if result.state_updates:
                self._state.update(result.state_updates)
            out = dict(result.handled)
            if result.state_updates:
                out["state_updates"] = dict(result.state_updates)
            return out
        return None

    def handle_response(self, response: dict[str, Any]) -> dict[str, Any] | None:
        request_id = response.get("id")
        if not isinstance(request_id, int):
            return None
        request = self._pending_by_id.pop(request_id, None)
        if request is None:
            return None
        return {
            "request_id": request_id,
            "request_method": request.get("method"),
            "request_params": request.get("params"),
            "result": response.get("result"),
            "error": response.get("error"),
        }
