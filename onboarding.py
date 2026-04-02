#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome>=3.20,<4"]
# ///
"""Compatibility wrapper for the guided remote onboarding CLI."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
src_str = str(SRC)
if src_str not in sys.path:
    sys.path.insert(0, src_str)

from roborock_local_server.onboarding_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
