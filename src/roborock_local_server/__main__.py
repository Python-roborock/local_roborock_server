"""CLI entrypoint for the release stack."""

from __future__ import annotations

import asyncio
from getpass import getpass
from pathlib import Path
import secrets
import sys

from .configure import run_configure
from .security import hash_password
from .server import build_arg_parser, repair_runtime_identities, run_server


def main() -> int:
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "hash-password":
        password = args.password or getpass("Admin password: ")
        print(hash_password(password))
        return 0

    if args.command == "generate-secret":
        if args.bytes < 16:
            raise SystemExit("--bytes must be at least 16")
        print(secrets.token_urlsafe(args.bytes))
        return 0

    if args.command == "configure":
        try:
            result = run_configure(config_file=Path(args.config), force=bool(args.force))
        except (FileExistsError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        print(f"Wrote config: {result.config_file}")
        if result.cloudflare_token_file is not None:
            print(f"Wrote Cloudflare token file: {result.cloudflare_token_file}")
        if result.actalis_eab_kid_file is not None:
            print(f"Wrote Actalis EAB KID file: {result.actalis_eab_kid_file}")
        if result.actalis_eab_hmac_key_file is not None:
            print(f"Wrote Actalis EAB HMAC key file: {result.actalis_eab_hmac_key_file}")
        if result.broker_template_needs_edit:
            print("Fill in broker.host before starting the stack.")
        return 0

    if args.command == "serve":
        return asyncio.run(
            run_server(
                config_file=Path(args.config),
                enable_standalone_admin=not bool(getattr(args, "core_only", False)),
            )
        )

    if args.command == "repair-identities":
        return repair_runtime_identities(config_file=Path(args.config), links=list(args.link))

    parser.error(f"Unhandled command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
