"""Certificate provisioning and renewal helpers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
from typing import Iterable, Iterator

from cryptography import x509

from .config import AppConfig, AppPaths


LOG = logging.getLogger("roborock_local_server.certs")
ACME_SH_PATH = Path("/opt/acme.sh/acme.sh")
ACME_RENEW_SKIP_RETURN_CODE = 2


@dataclass(frozen=True)
class CertificatePaths:
    cert_file: Path
    key_file: Path


# (st_ino, st_mtime_ns, st_size) for the cert file and the key file.
_FilesSignature = tuple[tuple[int, int, int], tuple[int, int, int]]


def validate_certificate_pair(cert_file: Path, key_file: Path) -> None:
    """Raise if the key does not belong to the certificate or either file cannot be parsed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Same security level as the listeners, so a cert they accept is not rejected here.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.load_cert_chain(str(cert_file), str(key_file))


class CertificateManager:
    """Owns certificate provisioning for the release stack."""

    def __init__(self, *, config: AppConfig, paths: AppPaths) -> None:
        self.config = config
        self.paths = paths
        # Signature of the provided cert/key the listeners are serving, and of a change
        # reported by ensure_certificate() that has not been applied yet.
        self._applied_signature: _FilesSignature | None = None
        self._pending_signature: _FilesSignature | None = None

    @property
    def certificate_paths(self) -> CertificatePaths:
        return CertificatePaths(cert_file=self.paths.cert_file, key_file=self.paths.key_file)

    def ensure_certificate(self) -> bool:
        if self.config.tls.mode == "provided":
            if not self.paths.cert_file.exists():
                raise FileNotFoundError(f"Provided TLS cert not found: {self.paths.cert_file}")
            if not self.paths.key_file.exists():
                raise FileNotFoundError(f"Provided TLS key not found: {self.paths.key_file}")
            return self._provided_files_changed()
        if not self._needs_refresh():
            return False
        self._provision_or_renew()
        return True

    def _provided_files_signature(self) -> _FilesSignature:
        cert_stat = self.paths.cert_file.stat()
        key_stat = self.paths.key_file.stat()
        return (
            (cert_stat.st_ino, cert_stat.st_mtime_ns, cert_stat.st_size),
            (key_stat.st_ino, key_stat.st_mtime_ns, key_stat.st_size),
        )

    def _provided_files_changed(self) -> bool:
        """Return True when externally managed cert/key files differ from the ones being served.

        The first call only records a baseline, so startup never reports a change. A reported
        change is only recorded as served once mark_certificate_applied() is called, so a
        half-written or mismatched pair is reported again on the next check.
        """
        signature = self._provided_files_signature()
        if self._applied_signature is None:
            self._applied_signature = signature
            return False
        if signature == self._applied_signature:
            self._pending_signature = None
            return False
        self._pending_signature = signature
        return True

    def mark_certificate_applied(self) -> None:
        """Record the change last reported by ensure_certificate() as served by the listeners."""
        if self._pending_signature is not None:
            self._applied_signature = self._pending_signature
            self._pending_signature = None

    @contextmanager
    def certificate_snapshot(self) -> Iterator[CertificatePaths]:
        """Yield private copies of the current cert/key after checking that they form a valid pair.

        Loading every listener from the same copies means a file replaced on disk mid-reload
        cannot leave the listeners with different, or mismatched, certificates.
        """
        cert_bytes = self.paths.cert_file.read_bytes()
        key_bytes = self.paths.key_file.read_bytes()
        with tempfile.TemporaryDirectory(prefix="tls-reload-") as tmp:
            snapshot = CertificatePaths(cert_file=Path(tmp) / "cert.pem", key_file=Path(tmp) / "key.pem")
            snapshot.cert_file.write_bytes(cert_bytes)
            fd = os.open(snapshot.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(key_bytes)
            validate_certificate_pair(snapshot.cert_file, snapshot.key_file)
            yield snapshot

    def _needs_refresh(self) -> bool:
        if not self.paths.cert_file.exists() or not self.paths.key_file.exists():
            return True
        try:
            cert = x509.load_pem_x509_certificate(self.paths.cert_file.read_bytes())
        except Exception:
            return True
        deadline = datetime.now(timezone.utc) + timedelta(days=self.config.tls.renew_days_before)
        if cert.not_valid_after_utc <= deadline:
            return True
        return not self._certificate_matches_configuration(cert)

    def _read_cloudflare_token(self) -> str:
        token = self.paths.cloudflare_token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError(f"Cloudflare token file is empty: {self.paths.cloudflare_token_file}")
        return token

    @staticmethod
    def _read_optional_secret_file(path: Path) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8").strip()

    def _load_eab_credentials(self) -> tuple[str, str]:
        kid = self.config.tls.acme_eab_kid or self._read_optional_secret_file(self.paths.acme_eab_kid_file)
        hmac_key = self.config.tls.acme_eab_hmac_key or self._read_optional_secret_file(self.paths.acme_eab_hmac_key_file)
        if bool(kid) != bool(hmac_key):
            raise RuntimeError("ACME EAB credentials are incomplete; both KID and HMAC key are required")
        if self.config.tls.acme_server == "actalis" and not kid:
            raise RuntimeError(
                "Actalis ACME requires EAB credentials. "
                f"Checked inline config plus {self.paths.acme_eab_kid_file} and {self.paths.acme_eab_hmac_key_file}."
            )
        return kid, hmac_key

    @staticmethod
    def _redact_command(command: list[str]) -> str:
        redacted: list[str] = []
        redact_next = False
        for part in command:
            if redact_next:
                redacted.append("<redacted>")
                redact_next = False
                continue
            redacted.append(part)
            if part in {"--eab-kid", "--eab-hmac-key"}:
                redact_next = True
        return " ".join(redacted)

    @staticmethod
    def _redact_text(text: str, sensitive_values: Iterable[str]) -> str:
        redacted = text
        for value in sorted({item for item in sensitive_values if item}, key=len, reverse=True):
            redacted = redacted.replace(value, "<redacted>")
        return redacted

    @staticmethod
    def _sensitive_values(command: list[str], env: dict[str, str]) -> list[str]:
        sensitive_values: list[str] = []
        for index, part in enumerate(command[:-1]):
            if part in {"--eab-kid", "--eab-hmac-key"}:
                sensitive_values.append(command[index + 1])
        cloudflare_token = env.get("CF_Token", "").strip()
        if cloudflare_token:
            sensitive_values.append(cloudflare_token)
        return sensitive_values

    def _certificate_matches_configuration(self, cert: x509.Certificate) -> bool:
        try:
            san_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName
            )
        except x509.ExtensionNotFound:
            return False
        actual_domains = {name.strip().lower() for name in san_names if name.strip()}
        _primary_domain, issue_domains = self._certificate_domains()
        expected_domains = {domain.strip().lower() for domain in issue_domains if domain.strip()}
        return actual_domains == expected_domains

    def _run_acme(self, args: Iterable[str]) -> None:
        self.paths.acme_dir.mkdir(parents=True, exist_ok=True)
        if not ACME_SH_PATH.exists():
            raise FileNotFoundError(f"acme.sh not found in image at {ACME_SH_PATH}")
        env = dict(os.environ)
        env["CF_Token"] = self._read_cloudflare_token()
        command = [
            str(ACME_SH_PATH),
            *args,
            "--home",
            str(self.paths.acme_dir),
            "--server",
            self.config.tls.acme_server,
        ]
        display_command = self._redact_command(command)
        sensitive_values = self._sensitive_values(command, env)
        LOG.info("Running ACME command: %s", display_command)
        result = subprocess.run(
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if result.stdout.strip():
            LOG.info("ACME output:\n%s", self._redact_text(result.stdout.strip(), sensitive_values))
        if result.returncode == ACME_RENEW_SKIP_RETURN_CODE:
            LOG.info("ACME command skipped because certificate renewal is not due: %s", display_command)
            return
        if result.returncode != 0:
            raise RuntimeError(f"ACME command failed ({result.returncode}): {display_command}")

    def _provision_or_renew(self) -> None:
        self.paths.certs_dir.mkdir(parents=True, exist_ok=True)
        primary_domain, issue_domains = self._certificate_domains()
        register_args = ["--register-account", "-m", self.config.tls.email]
        eab_kid, eab_hmac_key = self._load_eab_credentials()
        if eab_kid and eab_hmac_key:
            register_args.extend(
                [
                    "--eab-kid",
                    eab_kid,
                    "--eab-hmac-key",
                    eab_hmac_key,
                ]
            )
        self._run_acme(register_args)
        issue_args = ["--issue", "--dns", "dns_cf"]
        for domain in issue_domains:
            issue_args.extend(["-d", domain])
        issue_args.extend(["--keylength", "2048"])
        self._run_acme(
            issue_args
        )
        self._run_acme(
            [
                "--install-cert",
                "-d",
                primary_domain,
                "--fullchain-file",
                str(self.paths.cert_file),
                "--key-file",
                str(self.paths.key_file),
            ]
        )
        if not self.paths.cert_file.exists() or not self.paths.key_file.exists():
            raise RuntimeError("ACME completed without writing certificate files")

    def _certificate_domains(self) -> tuple[str, list[str]]:
        if self.config.tls.acme_server == "actalis":
            stack_fqdn = self.config.network.stack_fqdn
            return stack_fqdn, [stack_fqdn]
        base_domain = self.config.tls.base_domain
        return base_domain, [base_domain, f"*.{base_domain}"]
