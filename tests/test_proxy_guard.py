"""The relay serves only the captured Chrome, never loops on itself, and never lets a 407 reach Chrome."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
from contextlib import closing
from pathlib import Path

import pytest

from chrome_logger import cli
from chrome_logger.proxy import (
    ProxyCheckError,
    ProxyRelay,
    ProxySpec,
    _connection_owner,
    _read_headers,
    check_proxy,
)


class Upstream:
    """A fake upstream proxy answering every connection with ``reply`` after reading the request head."""

    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.requests: list[bytes] = []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            with client:
                client.settimeout(5)
                try:
                    self.requests.append(_read_headers(client))
                    client.sendall(self.reply)
                except OSError:
                    pass

    def close(self) -> None:
        self.server.close()
        self.thread.join(timeout=2)


def _exchange(port: int, request: bytes) -> bytes:
    with closing(socket.create_connection(("127.0.0.1", port), timeout=5)) as client:
        client.sendall(request)
        data = bytearray()
        while True:
            try:
                chunk = client.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError):
                break
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)


@pytest.fixture
def other_process():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        yield child.pid
    finally:
        child.kill()
        child.wait(timeout=10)


def test_connection_owner_matches_both_ends_of_the_socket(other_process) -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        relay = ("127.0.0.1", server.getsockname()[1])
        with socket.create_connection(relay) as client:
            accepted, _ = server.accept()
            with accepted:
                peer = ("127.0.0.1", client.getsockname()[1])
                owned, process = _connection_owner(os.getpid(), peer, relay)
                assert owned is True and process is not None and process.pid == os.getpid()
                # The cached owner is reused, and a stale or foreign tree never matches.
                assert _connection_owner(os.getpid(), peer, relay, process)[0] is True
                assert _connection_owner(other_process, peer, relay) == (False, None)
                # Same port number, another loopback address: someone else's socket.
                assert _connection_owner(os.getpid(), ("127.0.0.2", peer[1]), relay) == (False, None)
                assert _connection_owner(os.getpid(), peer, ("127.0.0.1", relay[1] + 1)) == (False, None)
                # Chrome already gone: the check cannot be made.
                assert _connection_owner(2**22 + 12345, peer, relay) == (None, None)


def test_restricted_relay_serves_its_chrome_and_refuses_other_processes(other_process) -> None:
    upstream = Upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    request = b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
    allowed = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port), restrict_clients=True)
    refused = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port), restrict_clients=True)
    # This test process plays the captured Chrome, and is seen listening.
    allowed.set_client_process(os.getpid(), listening_port=allowed.local_port)
    refused.set_client_process(other_process)
    problems: list[str] = []
    refused.on_problem = problems.append
    allowed.start()
    refused.start()
    try:
        assert _exchange(allowed.local_port, request).endswith(b"OK")
        for _ in range(5):
            # However many attempts: nothing a foreign process does turns the check off.
            assert _exchange(refused.local_port, request) == b""
        assert any("not the captured Chrome" in problem for problem in problems)
        assert len(upstream.requests) == 1
        assert allowed.problems == {}
    finally:
        allowed.stop()
        refused.stop()
        upstream.close()


def test_check_is_off_only_when_chrome_itself_cannot_be_inspected(other_process) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        unused_port = probe.getsockname()[1]
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9), restrict_clients=True)
    # The "Chrome" process is not seen listening on its DevTools port.
    relay.set_client_process(other_process, listening_port=unused_port)
    relay.start()
    try:
        assert _exchange(relay.local_port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").startswith(b"HTTP/1.1 400")
        assert any("cannot see the sockets of the captured Chrome" in problem for problem in relay.problems)
    finally:
        relay.stop()


@pytest.mark.parametrize(
    "request_bytes",
    [b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b"GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n"],
)
def test_origin_form_requests_are_refused(request_bytes: bytes) -> None:
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.toggle()  # direct mode, where origin-form used to be served from the Host header
    relay.start()
    try:
        assert _exchange(relay.local_port, request_bytes).startswith(b"HTTP/1.1 400 Bad Request")
    finally:
        relay.stop()


def test_requests_aimed_at_the_relay_itself_are_refused() -> None:
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.toggle()
    relay.start()
    try:
        port = relay.local_port
        absolute = f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
        tunnel = f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n".encode()
        assert _exchange(port, absolute).startswith(b"HTTP/1.1 508")
        assert _exchange(port, tunnel).startswith(b"HTTP/1.1 508")
    finally:
        relay.stop()


@pytest.mark.parametrize(
    "request_bytes",
    [
        b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
        b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ],
)
def test_upstream_407_becomes_a_502_instead_of_a_login_prompt(request_bytes: bytes) -> None:
    upstream = Upstream(
        b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="x"\r\n'
        b"Content-Length: 0\r\n\r\n"
    )
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port, "alice", "wrong"))
    problems: list[str] = []
    relay.on_problem = problems.append
    relay.start()
    try:
        response = _exchange(relay.local_port, request_bytes)
        assert response.startswith(b"HTTP/1.1 502")
        assert b"407" not in response and b"Proxy-Authenticate" not in response
        assert problems == [
            f"Proxy relay: the upstream proxy {relay.upstream.label()} rejected the credentials (HTTP 407)"
        ]
    finally:
        relay.stop()
        upstream.close()


def test_unreachable_upstream_is_reported_once() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", dead_port), connect_timeout=5)
    relay.start()
    try:
        for _ in range(2):
            assert _exchange(relay.local_port, b"CONNECT a.test:443 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 502")
        assert list(relay.problems.values()) == [2]
        assert "cannot reach the upstream proxy" in next(iter(relay.problems))
    finally:
        relay.stop()


def test_proxy_check_spots_rejected_credentials_without_contacting_anyone_else() -> None:
    upstream = Upstream(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
    try:
        with pytest.raises(ProxyCheckError, match="rejected the credentials"):
            check_proxy(ProxySpec("http", "127.0.0.1", upstream.port, "alice", "wrong"))
        assert upstream.requests[0].startswith(b"CONNECT 127.0.0.1:9 HTTP/1.1")
    finally:
        upstream.close()


def test_proxy_check_accepts_a_proxy_that_refuses_the_probe_target() -> None:
    upstream = Upstream(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    try:
        check_proxy(ProxySpec("http", "127.0.0.1", upstream.port, "alice", "right"))
    finally:
        upstream.close()


def test_proxy_check_reports_an_unreachable_proxy() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    with pytest.raises(ProxyCheckError, match="Cannot reach the proxy"):
        check_proxy(ProxySpec("http", "127.0.0.1", dead_port), timeout=5)


def test_proxy_check_reports_socks5_login_refusal() -> None:
    # Method selection answers username/password, then the login is refused.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def run() -> None:
        client, _ = server.accept()
        with client:
            client.recv(16)
            client.sendall(b"\x05\x02")
            client.recv(64)
            client.sendall(b"\x01\x01")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        with pytest.raises(ProxyCheckError, match="rejected the username/password"):
            check_proxy(ProxySpec("socks5", "127.0.0.1", server.getsockname()[1], "alice", "wrong"))
    finally:
        server.close()
        thread.join(timeout=2)


def test_cli_stops_before_launching_chrome_when_the_proxy_check_fails(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "find_chrome", lambda _path: Path("fake-chrome"))
    monkeypatch.setattr(cli, "kill_profile_chrome_processes", lambda _path: 0)
    monkeypatch.setattr(cli, "profile_chrome_process_ids", lambda _path: [])
    monkeypatch.setattr(cli, "cleanup_profile_locks", lambda _path: None)
    monkeypatch.setattr(cli, "load_proxies", lambda _path: [ProxySpec("http", "127.0.0.1", 9, "a", "b")])

    def refuse(_proxy, **_kwargs):
        raise ProxyCheckError("The proxy 127.0.0.1:9 rejected the credentials (HTTP 407)")

    monkeypatch.setattr(cli, "check_proxy", refuse)
    launched: list[bool] = []
    monkeypatch.setattr(cli, "launch_chrome", lambda *_a, **_k: launched.append(True))
    arguments = ["--non-interactive", "--output-dir", str(tmp_path / "out"), "--profile-dir", str(tmp_path / "p")]
    with pytest.raises(SystemExit) as stopped:
        cli.main([*arguments, "--proxy", "1"])
    assert stopped.value.code == 2
    assert not launched
    assert cli.build_parser().parse_args(["--no-proxy-check"]).no_proxy_check is True
