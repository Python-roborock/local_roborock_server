#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome>=3.20,<4"]
# ///
"""Run cfgwifi onboarding against rriot_rr."""

from __future__ import annotations

import argparse
import io
import json
import secrets
import socket
import zlib
from typing import Any

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


CFGWIFI_HOST = "192.168.8.1"
CFGWIFI_PORT = 55559
CFGWIFI_TIMEOUT_SECONDS = 2.0
CFGWIFI_PRE_KEY = "6433df70f5a3a42e"
CFGWIFI_UID = "1234567890"


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_frame(payload: bytes, cmd_id: int) -> bytes:
    buf = io.BytesIO()
    buf.write(b"1.0")
    buf.write(b"\x00\x00\x00\x01")
    buf.write(bytes([0, cmd_id]))
    buf.write(bytes([(len(payload) >> 8) & 0xFF, len(payload) & 0xFF]))
    buf.write(payload)
    csum = crc32(buf.getvalue())
    buf.write(bytes([(csum >> 24) & 0xFF, (csum >> 16) & 0xFF, (csum >> 8) & 0xFF, csum & 0xFF]))
    return buf.getvalue()


def parse_cmd(pkt: bytes) -> int:
    return (pkt[7] << 8) | pkt[8]


def parse_payload(pkt: bytes) -> bytes:
    ln = (pkt[9] << 8) | pkt[10]
    return pkt[11 : 11 + ln]


def rsa_decrypt_blocks(payload: bytes, private_key: bytes) -> bytes:
    key = RSA.import_key(private_key)
    cipher = PKCS1_v1_5.new(key)
    bs = key.size_in_bytes()
    out = bytearray()
    for i in range(0, len(payload), bs):
        out.extend(cipher.decrypt(payload[i : i + bs], sentinel=None))
    return bytes(out)


def aes_encrypt_json(data: dict[str, Any], key16: str) -> bytes:
    cipher = AES.new(key16.encode(), AES.MODE_ECB)
    plaintext = json.dumps(data, separators=(",", ":")).encode()
    return cipher.encrypt(pad(plaintext, AES.block_size))


def build_hello_packet(pre_key: str, pubkey_pem: bytes) -> bytes:
    body = {"id": 1, "method": "hello", "params": {"app_ver": 1, "key": pubkey_pem.decode()}}
    return build_frame(aes_encrypt_json(body, pre_key), 16)


def build_wifi_packet(session_key: str, body: dict[str, Any]) -> bytes:
    return build_frame(aes_encrypt_json(body, session_key), 1)


def recv_with_timeout(sock: socket.socket, timeout: float) -> bytes | None:
    sock.settimeout(timeout)
    try:
        data, _addr = sock.recvfrom(4096)
        return data
    except TimeoutError:
        return None
    except socket.timeout:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cfgwifi onboarding")
    parser.add_argument("--cst", default="EST5EDT,M3.2.0,M11.1.0")
    parser.add_argument(
        "--country-domain",
        default="us",
        help="country_domain field used by some firmware variants.",
    )
    parser.add_argument("--timezone", default="America/New_York")
    parser.add_argument(
        "--server",
        required=True,
        help="Your server that you are connecting to (don't include the api-)",
    )
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--password", required=True)
    return parser


def sanitize_server(url: str) -> str:
    """Sanitize server URL: strip scheme/api- prefix, ensure trailing slash."""
    for prefix in ("https://", "http://"):
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
    if url.lower().startswith("api-"):
        url = url[4:]
    if not url.endswith("/"):
        url += "/"
    return url


def onboard_once(args: argparse.Namespace) -> bool:
    """Run a single onboarding attempt. Returns True on success, False on failure."""
    token_s = f"S_TOKEN_{secrets.token_hex(16)}"
    token_t = f"T_TOKEN_{secrets.token_hex(16)}"

    key = RSA.generate(1024)
    priv = key.export_key()
    pub = key.publickey().export_key()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (CFGWIFI_HOST, CFGWIFI_PORT)
    try:
        hello = build_hello_packet(CFGWIFI_PRE_KEY, pub)
        s.sendto(hello, target)
        hello_resp = recv_with_timeout(s, CFGWIFI_TIMEOUT_SECONDS)
        if not hello_resp:
            print("HELLO: no response")
            return False

        cmd = parse_cmd(hello_resp)
        dec = rsa_decrypt_blocks(parse_payload(hello_resp), priv).decode(errors="replace")
        print(f"HELLO_RESP_CMD={cmd}")
        print(f"HELLO_RESP_JSON={dec}")
        parsed = json.loads(dec)
        session_key = parsed["params"]["key"]
        if not isinstance(session_key, str) or len(session_key) != 16:
            print("HELLO: session key invalid")
            return False
        print(f"SESSION_KEY={session_key}")

        body = {
            "u": CFGWIFI_UID,
            "ssid": args.ssid,
            "token": {
                "r": args.server,
                "tz": args.timezone,
                "s": token_s,
                "cst": args.cst,
                "t": token_t,
            },
            "passwd": args.password,
            "country_domain": args.country_domain,
        }
        wifi_pkt = build_wifi_packet(session_key, body)
        s.sendto(wifi_pkt, target)
        print(f"TOKEN_S={token_s}")
        print(f"TOKEN_T={token_t}")
        print(f"WIFI_BODY_SENT={json.dumps(body, separators=(',', ':'))}")

        wifi_resp = recv_with_timeout(s, CFGWIFI_TIMEOUT_SECONDS)
        if wifi_resp is None:
            print("WIFI_RESP: none")
        else:
            print(f"WIFI_RESP_CMD={parse_cmd(wifi_resp)}")
            print(f"WIFI_RESP_HEX={wifi_resp.hex()[:800]}")
        return True
    finally:
        s.close()


def main() -> int:
    args = build_parser().parse_args()
    args.server = sanitize_server(args.server)

    while True:
        print("\n--- Reset the Vacuum's Wifi and connect to its wifi network ---")
        user_input = input("Press Enter to send onboarding message (or type 'exit' to quit): ")
        if user_input.strip().lower() == "exit":
            print("Exiting.")
            return 0

        print()
        success = onboard_once(args)
        if success:
            print("\nOnboarding message sent successfully.")
        else:
            print("\nOnboarding failed. You can try again.")


if __name__ == "__main__":
    raise SystemExit(main())
