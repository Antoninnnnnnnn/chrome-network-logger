from __future__ import annotations

import base64
import logging
import os
import select
import socket
import ssl
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

LOG = logging.getLogger(__name__)
_ALLOWED_SCHEMES = {"http", "https", "socks4", "socks5"}


@dataclass(frozen=True, slots=True)
class ProxySpec:
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @property
    def has_auth(self) -> bool:
        return self.username is not None

    @property
    def authorization_header(self) -> str | None:
        if self.username is None:
            return None
        token = base64.b64encode(f"{self.username}:{self.password or ''}".encode()).decode("ascii")
        return f"Basic {token}"

    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        user = (self.username[:2] + "***") if self.username else "-"
        return f"{self.scheme}://{host}:{self.port} user={user}"


def _validate(scheme: str, host: str | None, port: int | None, username: str | None, password: str | None) -> ProxySpec:
    scheme = scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported proxy scheme: {scheme}")
    if not host:
        raise ValueError("Proxy host is missing")
    if port is None or not 1 <= int(port) <= 65535:
        raise ValueError(f"Invalid proxy port: {port}")
    return ProxySpec(scheme=scheme, host=host, port=int(port), username=username, password=password)


def parse_proxy_line(line: str) -> ProxySpec | None:
    """Parse URL, colon-separated and whitespace-separated proxy formats."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    if any(ch.isspace() for ch in raw) and "://" not in raw and "@" not in raw:
        parts = raw.split()
        if len(parts) == 2:
            return _validate("http", parts[0], int(parts[1]), None, None)
        if len(parts) == 4:
            return _validate("http", parts[0], int(parts[1]), parts[2], parts[3])
        raise ValueError("Expected 'host port' or 'host port user password'")

    if "://" in raw or "@" in raw:
        candidate = raw if "://" in raw else "http://" + raw
        parsed = urlsplit(candidate)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid proxy port in {raw!r}") from exc
        return _validate(
            parsed.scheme or "http",
            parsed.hostname,
            port,
            unquote(parsed.username) if parsed.username is not None else None,
            unquote(parsed.password) if parsed.password is not None else None,
        )

    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0 or closing + 2 > len(raw) or raw[closing + 1] != ":":
            raise ValueError("Invalid bracketed IPv6 proxy")
        host = raw[1:closing]
        remainder = raw[closing + 2 :]
        parts = remainder.split(":", 2)
        if len(parts) == 1:
            return _validate("http", host, int(parts[0]), None, None)
        if len(parts) == 3:
            return _validate("http", host, int(parts[0]), parts[1], parts[2])
        raise ValueError("Invalid bracketed IPv6 proxy format")

    parts = raw.split(":", 3)
    if len(parts) == 2:
        return _validate("http", parts[0], int(parts[1]), None, None)
    if len(parts) == 4:
        return _validate("http", parts[0], int(parts[1]), parts[2], parts[3])
    raise ValueError("Expected host:port or host:port:user:password")


def load_proxies(path: Path) -> list[ProxySpec]:
    if not path.exists():
        return []
    proxies: list[ProxySpec] = []
    with path.open(encoding="utf-8") as file:
        for number, line in enumerate(file, 1):
            try:
                proxy = parse_proxy_line(line)
            except (TypeError, ValueError) as exc:
                LOG.warning("Ignoring invalid proxy line %s: %s", number, exc)
                continue
            if proxy:
                proxies.append(proxy)
    return proxies


def select_proxy(proxies: list[ProxySpec], selector: str | None, prompt: bool = False) -> ProxySpec | None:
    if selector == "none":
        return None
    if not proxies:
        if prompt or selector not in {None, "none"}:
            raise ValueError("No valid proxy is available in the configured proxy file")
        return None
    if selector is None and not prompt:
        return None
    if selector in {None, "random"}:
        if selector == "random" and not prompt:
            return __import__("random").choice(proxies)
    elif selector is not None:
        try:
            index = int(selector)
        except ValueError as exc:
            raise ValueError("--proxy must be N, random or none") from exc
        if not 1 <= index <= len(proxies):
            raise ValueError(f"Proxy #{index} does not exist ({len(proxies)} available)")
        return proxies[index - 1]

    print("\nProxies available:")
    for index, proxy in enumerate(proxies, 1):
        print(f"  {index}. {proxy.label()}")
    print("  0. Direct connection")
    while True:
        answer = input(f"Choice [0-{len(proxies)}] (Enter = random): ").strip()
        if not answer:
            return __import__("random").choice(proxies)
        try:
            index = int(answer)
        except ValueError:
            print("Enter a number.")
            continue
        if index == 0:
            return None
        if 1 <= index <= len(proxies):
            return proxies[index - 1]


def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    value = authority.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError(f"Invalid IPv6 authority: {authority}")
        host = value[1:end]
        port = int(value[end + 2 :]) if value[end + 1 :].startswith(":") else default_port
        return host, port
    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text)
    if ":" in value:
        return value, default_port
    return value, default_port


def _read_headers(sock: socket.socket, limit: int = 256 * 1024) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("Proxy headers exceed safety limit")
    return bytes(data)


def _replace_headers(header_block: bytes, *, remove: Iterable[bytes], add: Iterable[bytes]) -> bytes:
    first, separator, rest = header_block.partition(b"\r\n")
    if not separator:
        raise ValueError("Malformed HTTP request")
    remove_lower = tuple(value.lower() for value in remove)
    lines = []
    for line in rest.split(b"\r\n"):
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in remove_lower):
            continue
        if line:
            lines.append(line)
    lines.extend(add)
    return first + b"\r\n" + b"\r\n".join(lines) + b"\r\n\r\n"


class ProxyRelay:
    """Local HTTP proxy that can forward through an HTTP(S) upstream or directly."""

    def __init__(
        self,
        upstream: ProxySpec,
        *,
        connect_timeout: float = 15.0,
        verify_tls: bool = True,
        max_connections: int = 512,
    ):
        if upstream.scheme not in {"http", "https"}:
            raise ValueError("ProxyRelay supports HTTP and HTTPS upstream proxies only")
        self.upstream = upstream
        self.connect_timeout = connect_timeout
        self.verify_tls = verify_tls
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        self.max_connections = max_connections
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        self._enabled = True
        self._state_lock = threading.RLock()
        self._active: set[socket.socket] = set()
        self._stop = threading.Event()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(256)
        self._server.settimeout(0.5)
        self.local_port = int(self._server.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, name="proxy-relay", daemon=True)

    @property
    def enabled(self) -> bool:
        with self._state_lock:
            return self._enabled

    def start(self) -> None:
        self._thread.start()

    def toggle(self) -> bool:
        with self._state_lock:
            self._enabled = not self._enabled
            sockets = list(self._active)
        for sock in sockets:
            self._close_socket(sock)
        return self._enabled

    def stop(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self._close_socket(self._server)
        with self._state_lock:
            sockets = list(self._active)
        for sock in sockets:
            self._close_socket(sock)
        self._thread.join(timeout=3)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            client.settimeout(self.connect_timeout)
            if not self._connection_slots.acquire(blocking=False):
                try:
                    client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                finally:
                    self._close_socket(client)
                continue
            self._track(client)
            try:
                threading.Thread(target=self._handle_guarded, args=(client,), daemon=True).start()
            except Exception:
                self._untrack(client)
                self._close_socket(client)
                self._connection_slots.release()
                raise

    def _handle_guarded(self, client: socket.socket) -> None:
        try:
            self._handle(client)
        finally:
            self._connection_slots.release()

    def _track(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._active.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._active.discard(sock)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError as exc:
            LOG.debug("Socket shutdown ignored: %s", exc)
        try:
            sock.close()
        except OSError as exc:
            LOG.debug("Socket close ignored: %s", exc)

    def _connect_upstream(self) -> socket.socket:
        raw = socket.create_connection((self.upstream.host, self.upstream.port), timeout=self.connect_timeout)
        if self.upstream.scheme == "https":
            try:
                context = ssl.create_default_context()
                if not self.verify_tls:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                return context.wrap_socket(raw, server_hostname=self.upstream.host)
            except Exception:
                self._close_socket(raw)
                raise
        return raw

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            raw = _read_headers(client)
            if b"\r\n\r\n" not in raw:
                return
            marker = raw.index(b"\r\n\r\n")
            headers, leftover = raw[:marker], raw[marker + 4 :]
            first_line = headers.split(b"\r\n", 1)[0]
            parts = first_line.split(b" ", 2)
            if len(parts) != 3:
                raise ValueError("Malformed proxy request line")
            method, target_b, version = parts
            target = target_b.decode("latin-1")
            use_upstream = self.enabled

            if method.upper() == b"CONNECT":
                if use_upstream:
                    upstream = self._connect_upstream()
                    self._track(upstream)
                    auth = self.upstream.authorization_header
                    additions = [b"Proxy-Connection: keep-alive"]
                    if auth:
                        additions.append(f"Proxy-Authorization: {auth}".encode("latin-1"))
                    request = (
                        b"CONNECT "
                        + target_b
                        + b" "
                        + version
                        + b"\r\n"
                        + f"Host: {target}\r\n".encode("latin-1")
                        + b"\r\n".join(additions)
                        + b"\r\n\r\n"
                    )
                    upstream.sendall(request)
                    response = _read_headers(upstream)
                    status_line = response.split(b"\r\n", 1)[0]
                    try:
                        status = int(status_line.split(b" ", 2)[1])
                    except Exception as exc:
                        raise ConnectionError(f"Invalid upstream CONNECT response: {status_line!r}") from exc
                    if not 200 <= status < 300:
                        client.sendall(response or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        return
                    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    host, port = _split_authority(target, 443)
                    upstream = socket.create_connection((host, port), timeout=self.connect_timeout)
                    self._track(upstream)
                    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if leftover:
                    upstream.sendall(leftover)
                self._tunnel(client, upstream)
                return

            if use_upstream:
                upstream = self._connect_upstream()
                self._track(upstream)
                auth = self.upstream.authorization_header
                additions = [b"Connection: close", b"Proxy-Connection: close"]
                if auth:
                    additions.append(f"Proxy-Authorization: {auth}".encode("latin-1"))
                request_headers = _replace_headers(
                    headers,
                    remove=(b"proxy-authorization:", b"connection:", b"proxy-connection:"),
                    add=additions,
                )
            else:
                parsed = urlsplit(target)
                if parsed.scheme and parsed.hostname:
                    host = parsed.hostname
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                else:
                    host_header = next(
                        (
                            line.split(b":", 1)[1].strip().decode("latin-1")
                            for line in headers.split(b"\r\n")[1:]
                            if line.lower().startswith(b"host:")
                        ),
                        "",
                    )
                    host, port = _split_authority(host_header, 80)
                    path = target or "/"
                upstream = socket.create_connection((host, port), timeout=self.connect_timeout)
                self._track(upstream)
                rewritten_first = method + b" " + path.encode("latin-1") + b" " + version
                _, _, rest = headers.partition(b"\r\n")
                request_headers = _replace_headers(
                    rewritten_first + b"\r\n" + rest,
                    remove=(b"proxy-authorization:", b"connection:", b"proxy-connection:"),
                    add=(b"Connection: close",),
                )
            upstream.sendall(request_headers + leftover)
            self._tunnel(client, upstream)
        except Exception as exc:
            LOG.debug("Proxy relay connection failed: %s", exc)
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError as send_exc:
                LOG.debug("Could not return proxy failure response: %s", send_exc)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    self._untrack(sock)
                    self._close_socket(sock)

    def _tunnel(self, left: socket.socket, right: socket.socket) -> None:
        for sock in (left, right):
            sock.setblocking(True)
        peers = {left: right, right: left}
        while not self._stop.is_set():
            readable, _, _ = select.select([left, right], [], [], 1.0)
            for source in readable:
                data = source.recv(64 * 1024)
                if not data:
                    return
                peers[source].sendall(data)


def build_proxy_route(proxy: ProxySpec | None, *, verify_tls: bool = True) -> tuple[list[str], ProxyRelay | None]:
    if proxy is None:
        return [], None
    if proxy.scheme in {"socks4", "socks5"}:
        if proxy.has_auth:
            raise ValueError("Authenticated SOCKS proxies are not supported by Chrome CLI; use an HTTP(S) proxy")
        host = f"[{proxy.host}]" if ":" in proxy.host else proxy.host
        return [f"--proxy-server={proxy.scheme}://{host}:{proxy.port}"], None
    relay = ProxyRelay(proxy, verify_tls=verify_tls)
    relay.start()
    return [f"--proxy-server=http://127.0.0.1:{relay.local_port}"], relay


def start_toggle_keyboard(relay: ProxyRelay, stop_event: threading.Event, on_toggle=None) -> threading.Thread | None:
    if os.name != "nt":
        return None
    try:
        import msvcrt
    except ImportError:
        return None

    def loop() -> None:
        while not stop_event.is_set():
            try:
                if msvcrt.kbhit() and msvcrt.getch() in {b"p", b"P"}:
                    enabled = relay.toggle()
                    print(f"\n[proxy] {'ON' if enabled else 'OFF — direct connection'}")
                    if on_toggle:
                        on_toggle(enabled)
            except Exception:
                LOG.exception("Proxy keyboard toggle failed")
            time.sleep(0.05)

    thread = threading.Thread(target=loop, name="proxy-keyboard", daemon=True)
    thread.start()
    return thread
