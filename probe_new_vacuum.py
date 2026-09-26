#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome>=3.20,<4"]
# ///
"""Probe a brand-new (never-on-cloud) vacuum to detect its /region version.

A vacuum that has never been added to the Roborock cloud has no inventory entry,
so the guided onboarding CLI/GUI cannot target it ("No known vacuums are available
for onboarding."). For *detection* we do not need the server-side pairing session:
we only need the vacuum to contact the local stack once.

This script reuses the proven cfgwifi sender and config handling from
``start_onboarding.py``. It:

  1. Logs into the admin API and runs the same stack preflight (TLS/services).
  2. Snapshots the current devices so we can tell which one is new.
  3. Sends the cfgwifi onboarding packet to the vacuum hotspot (192.168.8.1).
  4. Polls ``/admin/api/status`` until a device reaches ``/region``, then reports
     its region version and whether it is the unsupported v2 flow.

Run it the same way as the guided CLI, from a second machine that can switch to
the vacuum's Wi-Fi hotspot and back:

    uv run probe_new_vacuum.py --server api-roborock.example.com

Keep this file together with ``start_onboarding.py`` and ``onboarding_shared.py``.
"""

from __future__ import annotations

import sys
import time
from typing import Any, TextIO

from onboarding_shared import build_ssl_context, perform_onboarding_preflight
from start_onboarding import (
    ApiReachabilityError,
    GuidedOnboardingConfig,
    RemoteOnboardingApi,
    build_parser,
    onboard_once,
    prompt_for_config,
)

POLL_INTERVAL_SECONDS = 5.0
POLL_TIMEOUT_SECONDS = 300.0


def _device_identity(vac: dict[str, Any]) -> str:
    return str(vac.get("duid") or vac.get("did") or "").strip()


def _region_step(vac: dict[str, Any]) -> str:
    steps = vac.get("onboarding_steps")
    if isinstance(steps, dict):
        return str(steps.get("region") or "").strip()
    return ""


def _all_vacuums(status: dict[str, Any]) -> list[dict[str, Any]]:
    health = status.get("health")
    if not isinstance(health, dict):
        return []
    vacuums = health.get("all_vacuums")
    return [vac for vac in vacuums if isinstance(vac, dict)] if isinstance(vacuums, list) else []


def _region_baseline(status: dict[str, Any]) -> dict[str, str]:
    """Map device identity -> its current /region step timestamp."""
    baseline: dict[str, str] = {}
    for vac in _all_vacuums(status):
        identity = _device_identity(vac)
        if identity:
            baseline[identity] = _region_step(vac)
    return baseline


def _find_new_region_contact(
    status: dict[str, Any],
    baseline: dict[str, str],
) -> dict[str, Any] | None:
    """Return the first device that has newly reached /region since the baseline."""
    for vac in _all_vacuums(status):
        region_at = _region_step(vac)
        if not region_at:
            continue
        identity = _device_identity(vac)
        if baseline.get(identity, "") != region_at:
            return vac
    return None


def _report_device(vac: dict[str, Any], *, output: TextIO) -> bool:
    """Print the verdict for a device that reached /region. Return True if v2."""
    onboarding = dict(vac.get("onboarding") or {})
    region_version = str(vac.get("last_region_version") or "").strip().lower()
    unsupported_reason = str(onboarding.get("unsupported_reason") or "").strip().lower()
    name = str(vac.get("name") or vac.get("duid") or vac.get("did") or "Unknown vacuum")
    did = str(vac.get("did") or "").strip()
    duid = str(vac.get("duid") or "").strip()

    output.write("\n=== New vacuum reached the local stack ===\n")
    output.write(f"name: {name}\n")
    if did:
        output.write(f"did:  {did}\n")
    if duid:
        output.write(f"duid: {duid}\n")
    output.write(f"region_version header: {region_version or '(none sent)'}\n")
    output.write(f"region step at: {_region_step(vac)}\n")

    if unsupported_reason == "region_v2" or region_version == "v2":
        output.write(
            "\nVERDICT: region v2 (UNSUPPORTED).\n"
            "This vacuum uses the v2 /region onboarding flow. These models usually stop after "
            "/region and never reach NC Prepare, and are not supported without a firmware dump.\n"
        )
        return True

    output.write(
        "\nVERDICT: not region v2.\n"
        f"The vacuum reached /region with version {region_version or '(no version header, older/v1 flow)'}. "
        "This is a good sign. You can proceed to full onboarding (which needs the cloud-free "
        "onboarding path, since this vac has no inventory entry).\n"
    )
    return False


def run_probe(
    *,
    config: GuidedOnboardingConfig,
    api: RemoteOnboardingApi,
    output: TextIO = sys.stdout,
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    timeout_seconds: float = POLL_TIMEOUT_SECONDS,
) -> int:
    baseline_status = perform_onboarding_preflight(
        api=api,
        api_base_url=config.api_base_url,
        allow_insecure_tls=config.allow_insecure_tls,
        output=output,
    )
    baseline = _region_baseline(baseline_status)
    output.write(f"Baseline: {len(baseline)} device(s) already known to the stack.\n")

    output.write(
        "\nReset the vacuum's Wi-Fi (Wi-Fi reset, not factory reset), connect this machine to the "
        "vacuum's Wi-Fi hotspot, then press Enter to send the onboarding packet.\n"
    )
    input("> ")

    output.write("Sending cfgwifi onboarding packet...\n")
    if not onboard_once(config, output):
        output.write(
            "Onboarding send failed. You are probably not joined to the vacuum's hotspot yet, "
            "or it is not in pairing mode. Reset its Wi-Fi and try again.\n"
        )
        return 1

    output.write(
        "\nReconnect this machine to your normal Wi-Fi. Once the stack is reachable again, this "
        "script will poll for up to 5 minutes for the vacuum's first /region contact.\n"
    )

    deadline = time.monotonic() + timeout_seconds
    warned_unreachable = False
    while True:
        try:
            status = api.get_status()
            warned_unreachable = False
        except ApiReachabilityError as exc:
            if time.monotonic() >= deadline:
                output.write("\nTimed out before the stack became reachable again.\n")
                return 2
            if not warned_unreachable:
                output.write(f"Stack not reachable yet ({exc}); finish reconnecting to your Wi-Fi...\n")
                warned_unreachable = True
            time.sleep(poll_interval_seconds)
            continue

        vac = _find_new_region_contact(status, baseline)
        if vac is not None:
            is_v2 = _report_device(vac, output=output)
            return 0 if not is_v2 else 3

        if time.monotonic() >= deadline:
            output.write(
                "\nTimed out: no new vacuum reached /region within 5 minutes.\n"
                "Check that the vacuum can resolve your api- hostname on the LAN and trusts the "
                "stack's TLS certificate, then retry.\n"
            )
            return 2
        output.write("Waiting for the vacuum's first /region contact...\n")
        time.sleep(poll_interval_seconds)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = prompt_for_config(args)
    ssl_context = build_ssl_context(allow_insecure_tls=config.allow_insecure_tls)
    api = RemoteOnboardingApi(
        base_url=config.api_base_url,
        admin_password=config.admin_password,
        ssl_context=ssl_context,
    )
    try:
        if config.allow_insecure_tls:
            print("TLS certificate verification is DISABLED. Preflight will only test reachability.")
        return run_probe(config=config, api=api)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
