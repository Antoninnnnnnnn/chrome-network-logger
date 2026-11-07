from __future__ import annotations

import os
import selectors
import socket
import threading
import time
from contextlib import closing

import pytest

from chrome_logger import proxy as proxy_module
from chrome_logger.proxy import ProxyRelay, ProxySpec, _read_headers


class OneShotServer:
    def __init__(self, handler):
        self.handler = handler
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        client, _ = self.server.accept()
        try:
            self.handler(client)
        finally:
            client.close()
            self.server.close()

    def close(self):
        try:
            self.server.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


def test_http_upstream_auth_is_injected() -> None:
    captured: list[bytes] = []

    def upstream_handler(client: socket.socket) -> None:
        request = _read_headers(client)
        captured.append(request)
        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")

    upstream = OneShotServer(upstream_handler)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port, "alice", "secret"))
    relay.start()
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=2)) as client:
            client.sendall(
                b"GET http://example.test/demo HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n"
            )
            response = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        assert b"200 OK" in response
        assert b"Proxy-Authorization: Basic YWxpY2U6c2VjcmV0" in captured[0]
        assert b"Connection: close" in captured[0]
        assert b"Proxy-Connection: close" in captured[0]
        assert b"Connection: keep-alive" not in captured[0]
    finally:
        relay.stop()
        upstream.close()


def test_toggle_off_uses_direct_connection() -> None:
    def destination_handler(client: socket.socket) -> None:
        _read_headers(client)
        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT")

    destination = OneShotServer(destination_handler)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.start()
    assert relay.toggle() is False
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=2)) as client:
            request = (
                f"GET http://127.0.0.1:{destination.port}/hello HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{destination.port}\r\nConnection: close\r\n\r\n"
            ).encode()
            client.sendall(request)
            response = bytearray()
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        assert b"DIRECT" in response
    finally:
        relay.stop()
        destination.close()


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed early")
        data.extend(chunk)
    return bytes(data)


def read_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def read_until_closed(sock: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def test_connect_forwards_bytes_the_upstream_sent_after_its_200() -> None:
    seen: list[bytes] = []

    def upstream_handler(client: socket.socket) -> None:
        client.settimeout(5)
        seen.append(_read_headers(client))
        # Server-first protocols (SMTP, SSH...) can land in the same read as the end of the 200 response.
        client.sendall(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\nSERVER-FIRST")
        seen.append(recv_exact(client, 4))
        client.sendall(b"PONG")

    upstream = OneShotServer(upstream_handler)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port, "alice", "secret"))
    relay.start()
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(b"CONNECT example.test:25 HTTP/1.1\r\nHost: example.test:25\r\n\r\n")
            assert read_until(client, b"SERVER-FIRST") == b"HTTP/1.1 200 Connection established\r\n\r\nSERVER-FIRST"
            client.sendall(b"PING")
            assert read_until_closed(client) == b"PONG"
        assert seen[0].startswith(b"CONNECT example.test:25 HTTP/1.1\r\n")
        assert b"Proxy-Authorization: Basic YWxpY2U6c2VjcmV0" in seen[0]
        assert seen[1] == b"PING"
    finally:
        relay.stop()
        upstream.close()


def test_connect_returns_502_when_upstream_cuts_its_200_short() -> None:
    def upstream_handler(client: socket.socket) -> None:
        _read_headers(client)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n")

    upstream = OneShotServer(upstream_handler)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", upstream.port))
    relay.start()
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
            assert read_until_closed(client) == b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
    finally:
        relay.stop()
        upstream.close()


def test_connect_failure_after_200_closes_without_injecting_a_502(monkeypatch) -> None:
    def wait_for_close(client: socket.socket) -> None:
        client.settimeout(5)
        client.recv(1)

    destination = OneShotServer(wait_for_close)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))

    def broken_tunnel(_left, _right) -> None:
        raise ConnectionResetError("peer reset mid-tunnel")

    monkeypatch.setattr(relay, "_tunnel", broken_tunnel)
    relay.start()
    assert relay.toggle() is False
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(f"CONNECT 127.0.0.1:{destination.port} HTTP/1.1\r\n\r\n".encode())
            assert read_until_closed(client) == b"HTTP/1.1 200 Connection established\r\n\r\n"
    finally:
        relay.stop()
        destination.close()


@pytest.fixture
def idle_relay():
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.start()
    yield relay
    relay.stop()


def run_tunnel(relay: ProxyRelay, left, right) -> tuple[threading.Thread, list[BaseException]]:
    errors: list[BaseException] = []

    def target() -> None:
        try:
            relay._tunnel(left, right)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, errors


def test_tunnel_relays_both_ways_through_a_selector_it_closes(monkeypatch, idle_relay) -> None:
    created = []

    class RecordingSelector(selectors.DefaultSelector):
        def __init__(self) -> None:
            super().__init__()
            self.closed = False
            created.append(self)

        def close(self) -> None:
            self.closed = True
            super().close()

    monkeypatch.setattr(proxy_module.selectors, "DefaultSelector", RecordingSelector)
    client, left = socket.socketpair()
    right, server = socket.socketpair()
    with client, left, right, server:
        client.settimeout(5)
        server.settimeout(5)
        thread, errors = run_tunnel(idle_relay, left, right)
        client.sendall(b"to-server")
        assert recv_exact(server, 9) == b"to-server"
        server.sendall(b"to-client")
        assert recv_exact(client, 9) == b"to-client"
        client.close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert errors == []
    assert len(created) == 1
    assert created[0].closed


def test_tunnel_drains_bytes_buffered_inside_a_tls_socket(idle_relay) -> None:
    class BufferedTLSSocket:
        """Mimics ssl.SSLSocket holding decrypted bytes that never show up on the raw descriptor."""

        def __init__(self, sock: socket.socket, buffered: bytes) -> None:
            self._sock = sock
            self._buffer = bytearray(buffered)

        def fileno(self) -> int:
            return self._sock.fileno()

        def setblocking(self, flag: bool) -> None:
            self._sock.setblocking(flag)

        def pending(self) -> int:
            return len(self._buffer)

        def recv(self, size: int) -> bytes:
            if self._buffer:
                chunk = bytes(self._buffer[:size])
                del self._buffer[:size]
                return chunk
            return self._sock.recv(size)

        def sendall(self, data: bytes) -> None:
            self._sock.sendall(data)

    upstream_peer, upstream_raw = socket.socketpair()
    client_side, client_peer = socket.socketpair()
    with upstream_peer, upstream_raw, client_side, client_peer:
        client_peer.settimeout(5)
        tls = BufferedTLSSocket(upstream_raw, b"already-decrypted")
        thread, errors = run_tunnel(idle_relay, client_side, tls)
        # Nothing is readable on any raw socket: only the pending() check can deliver these bytes.
        assert recv_exact(client_peer, 17) == b"already-decrypted"
        upstream_peer.close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert errors == []


def test_tunnel_notices_relay_stop_within_about_a_second() -> None:
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.start()
    client, left = socket.socketpair()
    right, server = socket.socketpair()
    with client, left, right, server:
        thread, errors = run_tunnel(relay, left, right)
        time.sleep(0.2)
        started = time.monotonic()
        relay.stop()  # these sockets are not tracked, so only the stop-event check can end the tunnel
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert time.monotonic() - started < 2.5
    assert errors == []


def test_toggle_promptly_closes_an_active_tunnel() -> None:
    def echo_until_closed(client: socket.socket) -> None:
        client.settimeout(5)
        while True:
            try:
                data = client.recv(4096)
            except OSError:
                return
            if not data:
                return
            client.sendall(data)

    destination = OneShotServer(echo_until_closed)
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", 9))
    relay.start()
    assert relay.toggle() is False
    try:
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(f"CONNECT 127.0.0.1:{destination.port} HTTP/1.1\r\n\r\n".encode())
            assert read_until(client, b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
            client.sendall(b"ping")
            assert recv_exact(client, 4) == b"ping"
            started = time.monotonic()
            assert relay.toggle() is True
            try:
                assert read_until_closed(client) == b""
            except ConnectionResetError:
                pass  # Windows may report the relay's close as a reset
            assert time.monotonic() - started < 2.5
    finally:
        relay.stop()
        destination.close()


@pytest.mark.skipif(os.name == "nt", reason="the select() descriptor limit only matters on POSIX")
def test_tunnel_accepts_descriptors_above_the_select_limit(idle_relay) -> None:
    resource = pytest.importorskip("resource")
    fcntl = pytest.importorskip("fcntl")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 1200
    raised = False
    if soft != resource.RLIM_INFINITY and soft < wanted:
        if hard != resource.RLIM_INFINITY and hard < wanted:
            pytest.skip("RLIMIT_NOFILE does not allow descriptors above 1024")
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
        except (OSError, ValueError) as exc:
            pytest.skip(f"cannot raise RLIMIT_NOFILE: {exc}")
        raised = True
    try:
        client, low_left = socket.socketpair()
        low_right, server = socket.socketpair()
        with low_left, low_right:
            left = socket.socket(fileno=fcntl.fcntl(low_left.fileno(), fcntl.F_DUPFD, 1100))
            right = socket.socket(fileno=fcntl.fcntl(low_right.fileno(), fcntl.F_DUPFD, 1100))
        with client, left, right, server:
            assert min(left.fileno(), right.fileno()) >= 1024
            client.settimeout(5)
            server.settimeout(5)
            thread, errors = run_tunnel(idle_relay, left, right)
            client.sendall(b"high")
            assert recv_exact(server, 4) == b"high"
            server.sendall(b"fds!")
            assert recv_exact(client, 4) == b"fds!"
            client.close()
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert errors == []
    finally:
        if raised:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
