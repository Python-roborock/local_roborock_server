"""Manage the optional coturn relay shipped with the container."""

from __future__ import annotations

from pathlib import Path
import logging
import socket
import subprocess
import time

from .config import TurnConfig


LOG = logging.getLogger(__name__)

RELAY_PORT_MIN = 49160
RELAY_PORT_MAX = 49179


class EmbeddedTurnRelay:
    def __init__(self, config: TurnConfig, state_dir: Path) -> None:
        self.config = config
        self.state_dir = state_dir
        self.process: subprocess.Popen[bytes] | None = None
        self._exit_warned = False

    @property
    def running(self) -> bool:
        if self.process is None:
            return False
        code = self.process.poll()
        if code is not None and not self._exit_warned:
            LOG.warning("coturn stopped with exit code %s; see container stdout", code)
            self._exit_warned = True
        return code is None

    def start(self) -> None:
        if self.config.mode != "provided":
            return
        addresses = socket.getaddrinfo(self.config.host, self.config.port, socket.AF_INET, socket.SOCK_DGRAM)
        external_ip = addresses[0][4][0]
        LOG.info("TURN advertised IPv4 address resolved from %s: %s", self.config.host, external_ip)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.state_dir / "turnserver.conf"
        config_path.write_text("\n".join([
            f"listening-port={self.config.port}",
            f"external-ip={external_ip}",
            f"min-port={RELAY_PORT_MIN}",
            f"max-port={RELAY_PORT_MAX}",
            "lt-cred-mech",
            f"realm={self.config.realm}",
            f"user={self.config.username}:{self.config.password}",
            "fingerprint",
            "no-tcp",
            "no-tls",
            "no-dtls",
            "no-multicast-peers",
            "no-cli",
            "no-rfc5780",
            "simple-log",
            "log-file=stdout",
            "",
        ]), encoding="utf-8")
        config_path.chmod(0o600)
        self.process = subprocess.Popen(
            ["turnserver", "-c", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=subprocess.STDOUT,
        )
        self._exit_warned = False
        time.sleep(0.3)
        if self.process.poll() is not None:
            self.stop()
            raise RuntimeError(f"coturn exited during startup; see container stdout")

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
