"""Reloading an externally provided (tls.mode = "provided") certificate into running listeners."""

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from conftest import write_release_config
from roborock_local_server.certs import CertificateManager
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


def _make_pair(common_name: str = "api-roborock.example.com") -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _der(cert_pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _served_cert(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with _client_context().wrap_socket(raw) as tls:
            return tls.getpeercert(binary_form=True)


def _replace(path: Path, content: bytes) -> None:
    """Overwrite in place, like cp, but force a new mtime so the change is always visible."""
    path.write_bytes(content)
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


def _provided_setup(tmp_path: Path, **config_kwargs):
    config_file = write_release_config(tmp_path, **config_kwargs)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    cert_a, key_a = _make_pair()
    paths.cert_file.write_bytes(cert_a)
    paths.key_file.write_bytes(key_a)
    return config, paths, (cert_a, key_a)


def test_provided_change_is_reported_until_marked_applied(tmp_path: Path) -> None:
    config, paths, _ = _provided_setup(tmp_path)
    manager = CertificateManager(config=config, paths=paths)

    assert manager.ensure_certificate() is False  # baseline at startup
    assert manager.ensure_certificate() is False  # unchanged

    cert_b, key_b = _make_pair()
    _replace(paths.cert_file, cert_b)
    _replace(paths.key_file, key_b)

    assert manager.ensure_certificate() is True
    assert manager.ensure_certificate() is True  # not applied yet, so reported again
    manager.mark_certificate_applied()
    assert manager.ensure_certificate() is False


def test_provided_change_detects_atomic_rename_with_same_mtime_and_size(tmp_path: Path) -> None:
    config, paths, (cert_a, _) = _provided_setup(tmp_path)
    manager = CertificateManager(config=config, paths=paths)
    assert manager.ensure_certificate() is False

    before = paths.cert_file.stat()
    replacement = paths.cert_file.with_name("fullchain.pem.new")
    replacement.write_bytes(cert_a)
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, paths.cert_file)

    assert manager.ensure_certificate() is True


def test_certificate_snapshot_rejects_mismatched_pair(tmp_path: Path) -> None:
    config, paths, _ = _provided_setup(tmp_path)
    manager = CertificateManager(config=config, paths=paths)
    cert_b, _ = _make_pair()
    _replace(paths.cert_file, cert_b)  # new cert written before its key

    with pytest.raises(ssl.SSLError):
        with manager.certificate_snapshot():
            pass


def test_renew_loop_keeps_listeners_up_on_bad_pair_and_retries(tmp_path: Path) -> None:
    https_port, mqtt_port = _free_port(), _free_port()
    config, paths, (cert_a, _) = _provided_setup(tmp_path, https_port=https_port, mqtt_tls_port=mqtt_port)
    for port in (https_port, mqtt_port):
        assert port not in (443, 8883)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    cert_b, key_b = _make_pair()

    async def scenario() -> None:
        supervisor.certificate_manager.ensure_certificate()  # baseline, as in start()
        await supervisor._start_http_server()
        supervisor._start_mqtt_proxy()
        try:
            for port in (https_port, mqtt_port):
                assert await asyncio.to_thread(_served_cert, port) == _der(cert_a)

            # An established vacuum connection that must survive the reload.
            raw = await asyncio.to_thread(socket.create_connection, ("127.0.0.1", mqtt_port), 5)
            established = await asyncio.to_thread(_client_context().wrap_socket, raw)

            # Renewal writes the cert first: the pair is mismatched for a moment.
            _replace(paths.cert_file, cert_b)
            await supervisor._check_certificate()
            for port in (https_port, mqtt_port):
                assert await asyncio.to_thread(_served_cert, port) == _der(cert_a)

            # Next tick, once the key is there too, the new pair is picked up.
            _replace(paths.key_file, key_b)
            await supervisor._check_certificate()
            for port in (https_port, mqtt_port):
                assert await asyncio.to_thread(_served_cert, port) == _der(cert_b)
            assert supervisor.certificate_manager.ensure_certificate() is False

            established.settimeout(0.2)
            with pytest.raises(TimeoutError):
                established.recv(1)  # still open: no data, no EOF
            established.close()
        finally:
            supervisor._mqtt_proxy.stop()
            await supervisor._http_server.stop()

    asyncio.run(scenario())


def test_mqtt_proxy_start_raises_when_port_is_taken(tmp_path: Path) -> None:
    mqtt_port = _free_port()
    config, paths, _ = _provided_setup(tmp_path, mqtt_tls_port=mqtt_port)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    with socket.socket() as blocker:
        blocker.bind(("0.0.0.0", mqtt_port))
        blocker.listen(1)
        with pytest.raises(OSError):
            supervisor._start_mqtt_proxy()
