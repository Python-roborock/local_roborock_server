from __future__ import annotations

from io import StringIO
import json
import socket
from types import SimpleNamespace

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import pytest

import onboarding_shared
from onboarding_shared import gateway_mac, ssid_pre_key
import start_onboarding
import start_onboarding_gui


@pytest.mark.parametrize(
    ("proc_arp", "arp_output", "expected"),
    [
        (None, "? (192.168.8.1) at b0:4a:39:3b:5f:1d on en0 ifscope [ethernet]\n", "b0:4a:39:3b:5f:1d"),
        (None, "Interface: 192.168.8.66 --- 0x5\n  192.168.8.1      b0-4a-39-3b-5f-1d   dynamic\n", "b0-4a-39-3b-5f-1d"),
        (None, "192.168.8.1 (192.168.8.1) -- no entry\n", ""),
        ("IP address HW type Flags HW address Mask Device\n192.168.8.1 0x1 0x2 b0:4a:39:3b:5f:1d * wlan0\n", "", "b0:4a:39:3b:5f:1d"),
    ],
)
def test_gateway_mac_reads_arp_table(
    monkeypatch: pytest.MonkeyPatch, proc_arp: str | None, arp_output: str, expected: str
) -> None:
    def fake_open(*_args: object, **_kwargs: object) -> StringIO:
        if proc_arp is None:
            raise OSError("no /proc/net/arp")
        return StringIO(proc_arp)

    monkeypatch.setattr(onboarding_shared, "open", fake_open, raising=False)
    monkeypatch.setattr(onboarding_shared.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout=arp_output))
    assert gateway_mac("192.168.8.1") == expected


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("b0:4a:39:3b:5f:1d", "uum-a10_miap5F1D"),
        ("b0:4a:39:3b:55:fa", "uum-a10_miap55FA"),
        ("b0-4a-39-3b-5-a", "uum-a10_miap050A"),  # Windows dashes, macOS-style dropped zeros
    ],
)
def test_ssid_pre_key_is_last_16_chars_of_hotspot_ssid(mac: str, expected: str) -> None:
    assert ssid_pre_key("roborock.vacuum.a10", mac) == expected


class SsidKeyOnlyVacuum:
    """Hotspot that, like some S6 MaxV units, silently drops HELLOs not encrypted with its SSID pre-key."""

    def __init__(self, *_args: object) -> None:
        self.pending: list[bytes] = []

    def sendto(self, pkt: bytes, _target: object) -> int:
        if int.from_bytes(pkt[7:9], "big") == 16:
            payload = pkt[11 : 11 + int.from_bytes(pkt[9:11], "big")]
            try:
                body = json.loads(unpad(AES.new(b"uum-a10_miap5F1D", AES.MODE_ECB).decrypt(payload), 16))
            except ValueError:
                return len(pkt)
            reply = json.dumps({"id": 1, "params": {"key": "0123456789abcdef"}}).encode()
            encrypted = PKCS1_v1_5.new(RSA.import_key(body["params"]["key"])).encrypt(reply)
            self.pending.append(start_onboarding.build_frame(encrypted, 17))
        return len(pkt)

    def settimeout(self, _timeout: float) -> None:
        pass

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if not self.pending:
            raise socket.timeout
        return self.pending.pop(0), ("192.168.8.1", 55559)

    def close(self) -> None:
        pass


@pytest.mark.parametrize("module", [start_onboarding, start_onboarding_gui])
def test_onboard_once_retries_hello_with_ssid_pre_key(monkeypatch: pytest.MonkeyPatch, module) -> None:
    fake_socket = SimpleNamespace(
        socket=SsidKeyOnlyVacuum,
        AF_INET=socket.AF_INET,
        SOCK_DGRAM=socket.SOCK_DGRAM,
        timeout=socket.timeout,
    )
    monkeypatch.setattr(module, "socket", fake_socket)
    monkeypatch.setattr(module, "gateway_mac", lambda _host: "b0:4a:39:3b:5f:1d")
    config = module.GuidedOnboardingConfig(
        api_base_url="https://api-roborock.example.com",
        stack_server="roborock.example.com/",
        admin_password="admin",
        ssid="Home",
        password="secret",
        timezone="Europe/Berlin",
        cst="CET-1CEST,M3.5.0,M10.5.0/3",
        country_domain="eu",
    )
    output = StringIO()

    assert module.onboard_once(config, output, model="roborock.vacuum.a10") is True
    assert '"key": "0123456789abcdef"' in output.getvalue()
