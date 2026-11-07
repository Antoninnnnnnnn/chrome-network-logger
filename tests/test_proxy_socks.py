from __future__ import annotations

import logging
import socket
import struct
import threading
from contextlib import closing

import pytest

from chrome_logger.proxy import ProxyRelay, ProxySpec, SocksError, _read_headers, socks5_connect

IPV4_BOUND = bytes([0x01]) + bytes(4) + bytes(2)


class PeerClosed(ConnectionError):
    pass


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise PeerClosed("peer closed early")
        data.extend(chunk)
    return bytes(data)


def read_until_closed(sock: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def read_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class FakeSocks5Server:
    """Single-connection SOCKS5 server that records the negotiation, then hands the socket to ``after_connect``."""

    def __init__(
        self,
        *,
        method: int = 0x02,
        auth_status: int = 0x00,
        reply: int = 0x00,
        bound: bytes = IPV4_BOUND,
        method_answer: bytes | None = None,
        reset: bool = False,
        after_connect=None,
    ):
        self.method = method
        self.auth_status = auth_status
        self.reply = reply
        self.bound = bound
        self.method_answer = method_answer
        self.reset = reset
        self.after_connect = after_connect
        self.methods: list[int] | None = None
        self.credentials: tuple[str, str] | None = None
        self.request: tuple[int, int, int, int, str, int] | None = None
        self.errors: list[BaseException] = []
        self.peer_closed = False
        self._stopped = threading.Event()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.server.settimeout(0.2)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            while not self._stopped.is_set():
                try:
                    conn, _ = self.server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with conn:
                    conn.settimeout(5)
                    try:
                        self._negotiate(conn)
                    except PeerClosed:
                        self.peer_closed = True  # the client gave up, e.g. after rejecting our choice
                    except Exception as exc:
                        self.errors.append(exc)
                return
        finally:
            self.server.close()

    def _negotiate(self, conn: socket.socket) -> None:
        version, count = recv_exact(conn, 2)
        assert version == 0x05
        self.methods = list(recv_exact(conn, count))
        if self.reset:
            # Linger 0 turns the close into a TCP reset on every platform.
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        if self.method_answer is not None:
            conn.sendall(self.method_answer)  # not a SOCKS5 answer at all
            return
        conn.sendall(bytes([0x05, self.method]))
        if self.method == 0xFF:
            return
        if self.method == 0x02:
            auth_version, user_length = recv_exact(conn, 2)
            assert auth_version == 0x01
            user = recv_exact(conn, user_length)
            password = recv_exact(conn, recv_exact(conn, 1)[0])
            self.credentials = (user.decode(), password.decode())
            conn.sendall(bytes([0x01, self.auth_status]))
            if self.auth_status:
                return
        version, command, reserved, atyp = recv_exact(conn, 4)
        if atyp == 0x03:
            address = recv_exact(conn, recv_exact(conn, 1)[0]).decode("ascii")
        elif atyp == 0x01:
            address = socket.inet_ntop(socket.AF_INET, recv_exact(conn, 4))
        elif atyp == 0x04:
            address = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
        else:
            raise AssertionError(f"unexpected ATYP {atyp}")
        port = int.from_bytes(recv_exact(conn, 2), "big")
        self.request = (version, command, reserved, atyp, address, port)
        conn.sendall(bytes([0x05, self.reply, 0x00]) + self.bound)
        if self.reply == 0x00 and self.after_connect is not None:
            self.after_connect(conn)

    def close(self) -> None:
        self._stopped.set()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


def echo_once(conn: socket.socket) -> None:
    conn.sendall(b"echo:" + conn.recv(4096))


@pytest.fixture
def socks_server():
    servers: list[FakeSocks5Server] = []

    def make(**kwargs) -> FakeSocks5Server:
        server = FakeSocks5Server(**kwargs)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.fixture
def relay_for():
    relays: list[ProxyRelay] = []

    def make(spec: ProxySpec) -> ProxyRelay:
        relay = ProxyRelay(spec, connect_timeout=5)
        relay.start()
        relays.append(relay)
        return relay

    yield make
    for relay in relays:
        relay.stop()


def negotiate(server: FakeSocks5Server, host: str, port: int, **credentials) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    try:
        socks5_connect(sock, host, port, **credentials)
    except BaseException:
        sock.close()
        raise
    return sock


@pytest.mark.parametrize(
    "bound",
    [
        IPV4_BOUND,
        bytes([0x04]) + bytes(16) + bytes(2),
        bytes([0x03, 11]) + b"proxy.local" + bytes(2),
    ],
    ids=["ipv4", "ipv6", "domain"],
)
def test_socks5_authenticates_and_sends_domain_names_for_remote_dns(socks_server, bound: bytes) -> None:
    server = socks_server(bound=bound, after_connect=echo_once)
    with closing(negotiate(server, "example.test", 443, username="alice", password="s3cret")) as sock:
        # The reply's bound address must be consumed whatever its type, or it would leak into the tunnel.
        sock.sendall(b"ping")
        assert read_until_closed(sock) == b"echo:ping"
    server.close()
    assert not server.errors
    assert server.methods == [0x00, 0x02]
    assert server.credentials == ("alice", "s3cret")
    assert server.request == (0x05, 0x01, 0x00, 0x03, "example.test", 443)


@pytest.mark.parametrize(
    ("host", "atyp", "expected"),
    [("192.0.2.10", 0x01, "192.0.2.10"), ("2001:db8::1", 0x04, "2001:db8::1"), ("[2001:db8::1]", 0x04, "2001:db8::1")],
)
def test_socks5_ip_literals_use_their_own_address_type(socks_server, host: str, atyp: int, expected: str) -> None:
    server = socks_server(method=0x00)
    negotiate(server, host, 8080).close()
    server.close()
    assert not server.errors
    assert server.methods == [0x00]
    assert server.credentials is None
    assert server.request == (0x05, 0x01, 0x00, atyp, expected, 8080)


@pytest.mark.parametrize(
    ("server_options", "credentials", "message"),
    [
        ({"reply": 0x04}, {"username": "alice", "password": "pw"}, r"example\.test:443 failed: host unreachable"),
        ({"method": 0x00, "reply": 0x05}, {}, r"connection refused \(reply 0x05\)"),
        ({"auth_status": 0x01}, {"username": "alice", "password": "bad"}, "rejected the username/password"),
        ({"method": 0xFF}, {"username": "alice", "password": "pw"}, "none of the offered authentication methods"),
        ({"method": 0x02}, {}, "authentication method that was not offered"),
        ({"method_answer": b"HTTP/1.1 400 Bad Request\r\n\r\n"}, {}, "did not answer as a SOCKS5 proxy"),
        ({"method_answer": b"\x05"}, {}, "closed the connection during negotiation"),
        ({"reset": True}, {}, "(dropped|closed) the connection during negotiation"),
    ],
)
def test_socks5_failures_raise_clear_errors(socks_server, server_options, credentials, message: str) -> None:
    server = socks_server(**server_options)
    with pytest.raises(SocksError, match=message) as excinfo:
        negotiate(server, "example.test", 443, **credentials)
    expected_reply = server_options.get("reply")
    assert excinfo.value.reply == expected_reply
    server.close()
    assert not server.errors


def test_socks5_rejects_unencodable_destinations_before_any_io() -> None:
    with pytest.raises(ValueError, match="1-255 bytes"):
        socks5_connect(None, "a" * 256, 443)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="destination port"):
        socks5_connect(None, "example.test", 0)  # type: ignore[arg-type]


def test_relay_tunnels_connect_through_authenticated_socks5(socks_server, relay_for) -> None:
    server = socks_server(after_connect=echo_once)
    relay = relay_for(ProxySpec("socks5", "127.0.0.1", server.port, "alice", "s3cret"))
    with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
        client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        assert read_until(client, b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
        client.sendall(b"hello")
        assert read_until_closed(client) == b"echo:hello"
    server.close()
    assert not server.errors
    assert server.credentials == ("alice", "s3cret")
    assert server.request == (0x05, 0x01, 0x00, 0x03, "example.test", 443)


def test_relay_sends_origin_form_http_requests_through_socks5(socks_server, relay_for) -> None:
    captured: list[bytes] = []

    def origin(conn: socket.socket) -> None:
        captured.append(_read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nSOCKS")

    server = socks_server(after_connect=origin)
    relay = relay_for(ProxySpec("socks5", "127.0.0.1", server.port, "alice", "s3cret"))
    with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
        client.sendall(
            b"GET http://example.test:8080/path?q=1 HTTP/1.1\r\nHost: example.test:8080\r\n"
            b"Proxy-Authorization: Basic Zm9vOmJhcg==\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        response = read_until_closed(client)
    server.close()
    assert not server.errors
    assert response.endswith(b"\r\n\r\nSOCKS")
    assert server.request == (0x05, 0x01, 0x00, 0x03, "example.test", 8080)
    request = captured[0]
    assert request.startswith(b"GET /path?q=1 HTTP/1.1\r\n")
    assert b"Host: example.test:8080" in request
    assert b"Connection: close" in request
    assert b"Proxy-Authorization" not in request
    assert b"Proxy-Connection" not in request


def test_relay_returns_502_when_socks5_refuses_connect(socks_server, relay_for) -> None:
    server = socks_server(reply=0x05)
    relay = relay_for(ProxySpec("socks5", "127.0.0.1", server.port, "alice", "s3cret"))
    with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
        client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        assert read_until_closed(client).startswith(b"HTTP/1.1 502 Bad Gateway\r\n")
    server.close()
    assert server.request is not None


def test_relay_returns_502_and_warns_when_socks5_rejects_credentials(socks_server, relay_for, caplog) -> None:
    server = socks_server(auth_status=0x01)
    relay = relay_for(ProxySpec("socks5", "127.0.0.1", server.port, "alice", "wrong"))
    with caplog.at_level(logging.WARNING, logger="chrome_logger.proxy"):
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
            assert read_until_closed(client).startswith(b"HTTP/1.1 502 Bad Gateway\r\n")
    server.close()
    assert server.request is None
    messages = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert any("rejected the username/password" in message for message in messages)
    assert not any("wrong" in message for message in messages)


def test_toggle_switches_between_direct_routing_and_socks5(socks_server, relay_for) -> None:
    destination = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    destination.bind(("127.0.0.1", 0))
    destination.listen(1)
    destination.settimeout(5)
    direct_port = destination.getsockname()[1]

    def direct_echo() -> None:
        conn, _ = destination.accept()
        with conn:
            conn.settimeout(5)
            echo_once(conn)

    direct = threading.Thread(target=direct_echo, daemon=True)
    direct.start()
    server = socks_server(after_connect=echo_once)
    relay = relay_for(ProxySpec("socks5", "127.0.0.1", server.port, "alice", "s3cret"))
    try:
        assert relay.toggle() is False
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(f"CONNECT 127.0.0.1:{direct_port} HTTP/1.1\r\n\r\n".encode())
            assert read_until(client, b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
            client.sendall(b"direct")
            assert read_until_closed(client) == b"echo:direct"
        assert server.request is None

        assert relay.toggle() is True
        with closing(socket.create_connection(("127.0.0.1", relay.local_port), timeout=5)) as client:
            client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
            assert read_until(client, b"\r\n\r\n") == b"HTTP/1.1 200 Connection established\r\n\r\n"
            client.sendall(b"socks")
            assert read_until_closed(client) == b"echo:socks"
        server.close()
        assert server.request == (0x05, 0x01, 0x00, 0x03, "example.test", 443)
    finally:
        direct.join(timeout=5)
        destination.close()
