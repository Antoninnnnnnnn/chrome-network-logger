from __future__ import annotations

import socket
import threading
from contextlib import closing

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
