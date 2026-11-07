from __future__ import annotations

import atexit
import base64
import ipaddress
import logging
import os
import random
import re
import selectors
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import psutil

LOG = logging.getLogger(__name__)
_ALLOWED_SCHEMES = {"http", "https", "socks4", "socks5"}
_RELAY_SCHEMES = {"http", "https", "socks5"}
_CONNECTION_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
_TUNNEL_CHUNK = 64 * 1024
_TUNNEL_POLL_SECONDS = 1.0
_KEY_POLL_SECONDS = 0.1
_REJECTED_CREDENTIALS = re.compile(rb"HTTP/1\.[01] 407\b")
_LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}
_RELAY_HOST = "127.0.0.1"


def _response(status: str, message: str) -> bytes:
    body = (message + "\n").encode("utf-8")
    return (
        f"HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("latin-1") + body


def _status_code(response_head: bytes) -> int | None:
    try:
        return int(response_head.split(b"\r\n", 1)[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


class UpstreamError(ConnectionError):
    """The upstream proxy itself could not be reached or negotiated with (not a destination failure)."""


class ProxyCheckError(ValueError):
    """The selected proxy cannot be used; raised before Chrome is launched."""


def _tcp_connections(process: psutil.Process) -> list[Any]:
    listing = getattr(process, "net_connections", None) or process.connections
    return list(listing(kind="tcp"))


def _process_tree(root_pid: int) -> list[psutil.Process]:
    root = psutil.Process(root_pid)
    return [root, *root.children(recursive=True)]


def _connection_owner(
    root_pid: int,
    peer: tuple[str, int],
    relay: tuple[str, int],
    hint: psutil.Process | None = None,
) -> tuple[bool | None, psutil.Process | None]:
    """Find the process of Chrome's tree that owns the client end of a relay connection.

    The socket must match on both ends, addresses included: a process bound to
    127.0.0.2 with the same port number as one of Chrome's sockets is not Chrome.
    Returns (True, process) on a match, (False, None) when every process of the
    tree was inspected and none owns it, and (None, None) when that cannot be
    decided (Chrome is gone, or some of its processes may not be inspected).
    """
    peer_ip, peer_port = peer
    relay_ip, relay_port = relay

    def owns(process: psutil.Process) -> bool:
        for connection in _tcp_connections(process):
            local, remote = connection.laddr, connection.raddr
            if (
                local
                and remote
                and local.port == peer_port
                and local.ip == peer_ip
                and remote.port == relay_port
                and remote.ip == relay_ip
            ):
                return True
        return False

    if hint is not None:
        # Chrome's network service owns every socket: usually one call.
        # is_running() also notices a PID reused by another process.
        try:
            if hint.is_running() and owns(hint):
                return True, hint
        except psutil.Error:
            pass
    try:
        processes = _process_tree(root_pid)
    except psutil.Error:
        return None, None
    denied = False
    for process in processes:
        try:
            if owns(process):
                return True, process
        except psutil.AccessDenied:
            denied = True
        except psutil.Error:
            continue
    return (None, None) if denied else (False, None)


def _tree_is_listening(root_pid: int, port: int) -> bool:
    """Whether a process of Chrome's tree is seen listening on ``port`` (its DevTools port)."""
    try:
        processes = _process_tree(root_pid)
    except psutil.Error:
        return False
    for process in processes:
        try:
            if any(
                connection.status == psutil.CONN_LISTEN and connection.laddr and connection.laddr.port == port
                for connection in _tcp_connections(process)
            ):
                return True
        except psutil.Error:
            continue
    return False


def check_proxy(proxy: ProxySpec, *, verify_tls: bool = True, timeout: float = 10.0) -> None:
    """Fail fast, before Chrome starts, on a proxy that cannot work: unreachable, TLS or credentials refused.

    No third-party host is contacted: an HTTP(S) proxy is asked to CONNECT to its own loopback discard
    port, which a proxy refuses or fails, but answers 407 only when the credentials are wrong or missing.
    SOCKS5 stops after authentication. Anything else (403, 502, a closed connection) is not proof of a
    problem and passes.
    """
    target = f"{proxy.host}:{proxy.port}"
    try:
        raw = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError as exc:
        raise ProxyCheckError(f"Cannot reach the proxy {target}: {exc}") from exc
    sock: socket.socket = raw
    try:
        sock.settimeout(timeout)
        if proxy.scheme == "https":
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(raw, server_hostname=proxy.host)
            except ssl.SSLError as exc:
                hint = "; use --proxy-insecure-tls if it uses a self-signed certificate" if verify_tls else ""
                raise ProxyCheckError(f"TLS handshake with the proxy {target} failed: {exc}{hint}") from exc
        if proxy.scheme == "socks5":
            methods = [_SOCKS5_NO_AUTH] if proxy.username is None else [_SOCKS5_NO_AUTH, _SOCKS5_USER_PASS]
            sock.sendall(bytes([_SOCKS5_VERSION, len(methods), *methods]))
            try:
                version, method = _recv_exact(sock, 2)
                if version != _SOCKS5_VERSION:
                    raise SocksError(f"it did not answer as a SOCKS5 proxy (version byte {version:#04x})")
                if method == _SOCKS5_NO_ACCEPTABLE_METHOD:
                    raise SocksError("it requires credentials" if proxy.username is None else "it refused the login")
                if method == _SOCKS5_USER_PASS and proxy.username is not None:
                    _socks5_authenticate(sock, proxy.username, proxy.password or "")
            except SocksError as exc:
                raise ProxyCheckError(f"SOCKS5 proxy {target}: {exc}") from exc
            return
        if proxy.scheme in {"http", "https"}:
            lines = [b"CONNECT 127.0.0.1:9 HTTP/1.1", b"Host: 127.0.0.1:9"]
            if proxy.authorization_header:
                lines.append(f"Proxy-Authorization: {proxy.authorization_header}".encode("latin-1"))
            sock.sendall(b"\r\n".join(lines) + b"\r\n\r\n")
            try:
                head = _read_headers(sock)
            except OSError:
                return
            if _status_code(head) == 407:
                reason = "rejected the credentials" if proxy.has_auth else "requires credentials"
                raise ProxyCheckError(f"The proxy {target} {reason} (HTTP 407)")
    except ProxyCheckError:
        raise
    except OSError as exc:
        raise ProxyCheckError(f"The proxy {target} failed during the check: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass


_SOCKS5_VERSION = 0x05
_SOCKS5_NO_AUTH = 0x00
_SOCKS5_USER_PASS = 0x02
_SOCKS5_NO_ACCEPTABLE_METHOD = 0xFF
_SOCKS5_CONNECT = 0x01
_SOCKS5_ATYP_IPV4 = 0x01
_SOCKS5_ATYP_DOMAIN = 0x03
_SOCKS5_ATYP_IPV6 = 0x04
_SOCKS5_REPLIES = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


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

    # Only an explicit scheme or a user:pass@host authority is URL syntax; a
    # password containing "@" in the colon or space format is not.
    colon_parts = raw.split(":", 3)
    colon_format = len(colon_parts) == 4 and colon_parts[1].strip().isdigit()
    url_like = "://" in raw or (
        "@" in raw and not colon_format and not raw.startswith("[") and not any(ch.isspace() for ch in raw)
    )
    if any(ch.isspace() for ch in raw) and not url_like:
        parts = raw.split()
        if len(parts) == 2:
            return _validate("http", parts[0], int(parts[1]), None, None)
        if len(parts) == 4:
            return _validate("http", parts[0], int(parts[1]), parts[2], parts[3])
        raise ValueError("Expected 'host port' or 'host port user password'")

    if url_like:
        candidate = raw if "://" in raw else "http://" + raw
        parsed = urlsplit(candidate)
        try:
            port = parsed.port
        except ValueError as exc:
            # Never echo the line: it can carry the proxy password.
            raise ValueError("Invalid proxy port") from exc
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


def _random_proxy(proxies: list[ProxySpec]) -> ProxySpec:
    # Only spreads load across the user's proxies; nothing security-sensitive depends on this pick.
    return random.choice(proxies)  # nosec B311


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
            return _random_proxy(proxies)
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
        try:
            answer = input(f"Choice [0-{len(proxies)}] (Enter = random): ").strip()
        except EOFError as exc:
            raise ValueError("--proxy-prompt needs an interactive terminal") from exc
        if not answer:
            return _random_proxy(proxies)
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


def _origin_form_request(method: bytes, target: str, version: bytes, headers: bytes) -> tuple[str, int, bytes]:
    """Return the destination and the origin-form request for a hop that is not an HTTP proxy."""
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
    rewritten_first = method + b" " + path.encode("latin-1") + b" " + version
    _, _, rest = headers.partition(b"\r\n")
    request_headers = _replace_headers(
        rewritten_first + b"\r\n" + rest,
        remove=(b"proxy-authorization:", b"connection:", b"proxy-connection:"),
        add=(b"Connection: close",),
    )
    return host, port, request_headers


def _buffered_bytes(sock: socket.socket) -> int:
    """Decrypted bytes an ``ssl.SSLSocket`` already holds; a selector only watches the raw socket."""
    pending = getattr(sock, "pending", None)
    if pending is None:
        return 0
    try:
        return int(pending())
    except (OSError, ValueError):
        return 0


class SocksError(ConnectionError):
    """A SOCKS5 negotiation failed. ``reply`` is the server reply code when the CONNECT itself was refused."""

    def __init__(self, message: str, *, reply: int | None = None):
        super().__init__(message)
        self.reply = reply


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
        except (ConnectionResetError, ConnectionAbortedError) as exc:
            raise SocksError(f"SOCKS5 proxy dropped the connection during negotiation: {exc}") from exc
        if not chunk:
            raise SocksError("SOCKS5 proxy closed the connection during negotiation")
        data.extend(chunk)
    return bytes(data)


def _socks5_address(host: str) -> bytes:
    """Encode ATYP + DST.ADDR: IP literals keep their own type, names go as ATYP 0x03 so the proxy resolves DNS."""
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        atyp = _SOCKS5_ATYP_IPV4 if address.version == 4 else _SOCKS5_ATYP_IPV6
        return bytes([atyp]) + address.packed
    try:
        name = candidate.encode("ascii")
    except UnicodeEncodeError:
        try:
            name = candidate.encode("idna")
        except UnicodeError as exc:
            raise ValueError(f"Cannot encode host name {candidate!r} for SOCKS5") from exc
    if not 1 <= len(name) <= 255:
        raise ValueError(f"SOCKS5 host names must be 1-255 bytes long, got {len(name)}")
    return bytes([_SOCKS5_ATYP_DOMAIN, len(name)]) + name


def _socks5_authenticate(sock: socket.socket, username: str, password: str) -> None:
    user = username.encode("utf-8")
    secret = password.encode("utf-8")
    if len(user) > 255 or len(secret) > 255:
        raise SocksError("SOCKS5 username and password are limited to 255 bytes each")
    sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
    _, status = _recv_exact(sock, 2)
    if status != 0x00:
        raise SocksError(f"SOCKS5 proxy rejected the username/password (status {status:#04x})")


def socks5_connect(
    sock: socket.socket, host: str, port: int, *, username: str | None = None, password: str | None = None
) -> None:
    """Run a SOCKS5 CONNECT (RFC 1928) to ``host:port`` on a socket already connected to the proxy.

    Credentials use username/password authentication (RFC 1929). Raises ``SocksError`` when the proxy fails
    or refuses, and ``ValueError`` (before any I/O) for a destination that cannot be encoded.
    """
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid SOCKS5 destination port: {port}")
    address = _socks5_address(host)
    methods = [_SOCKS5_NO_AUTH] if username is None else [_SOCKS5_NO_AUTH, _SOCKS5_USER_PASS]
    sock.sendall(bytes([_SOCKS5_VERSION, len(methods), *methods]))
    version, method = _recv_exact(sock, 2)
    if version != _SOCKS5_VERSION:
        raise SocksError(f"Upstream did not answer as a SOCKS5 proxy (version byte {version:#04x})")
    if method == _SOCKS5_NO_ACCEPTABLE_METHOD:
        hint = "check the credentials" if username is not None else "it probably requires credentials"
        raise SocksError(f"SOCKS5 proxy accepted none of the offered authentication methods ({hint})")
    if method == _SOCKS5_USER_PASS and username is not None:
        _socks5_authenticate(sock, username, password or "")
    elif method != _SOCKS5_NO_AUTH:
        raise SocksError(f"SOCKS5 proxy chose an authentication method that was not offered ({method:#04x})")

    sock.sendall(bytes([_SOCKS5_VERSION, _SOCKS5_CONNECT, 0x00]) + address + port.to_bytes(2, "big"))
    version, reply, _, atyp = _recv_exact(sock, 4)
    if version != _SOCKS5_VERSION:
        raise SocksError(f"Invalid SOCKS5 CONNECT reply (version byte {version:#04x})")
    if reply != 0x00:
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        reason = _SOCKS5_REPLIES.get(reply, "unknown error")
        raise SocksError(f"SOCKS5 CONNECT to {authority} failed: {reason} (reply {reply:#04x})", reply=reply)
    if atyp == _SOCKS5_ATYP_IPV4:
        bound_size = 4
    elif atyp == _SOCKS5_ATYP_IPV6:
        bound_size = 16
    elif atyp == _SOCKS5_ATYP_DOMAIN:
        bound_size = _recv_exact(sock, 1)[0]
    else:
        raise SocksError(f"SOCKS5 CONNECT reply uses an unknown address type ({atyp:#04x})")
    _recv_exact(sock, bound_size + 2)  # BND.ADDR and BND.PORT: nothing to do with them


class ProxyRelay:
    """Local HTTP proxy that forwards through an HTTP(S) or SOCKS5 upstream, or directly."""

    def __init__(
        self,
        upstream: ProxySpec,
        *,
        connect_timeout: float = 15.0,
        verify_tls: bool = True,
        max_connections: int = 512,
        restrict_clients: bool = False,
    ):
        if upstream.scheme not in _RELAY_SCHEMES:
            raise ValueError("ProxyRelay supports HTTP, HTTPS and SOCKS5 upstream proxies only")
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
        self._server.bind((_RELAY_HOST, 0))
        self._server.listen(256)
        self._server.settimeout(0.5)
        self.local_port = int(self._server.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, name="proxy-relay", daemon=True)
        # The relay carries the upstream credentials: when restricted, it only
        # serves processes of the Chrome started by the logger.
        self.restrict_clients = restrict_clients
        self._client_root_pid: int | None = None
        self._client_ready = threading.Event()
        self._owner_hint: psutil.Process | None = None
        self._verification_off = False
        self._problems: dict[str, int] = {}
        self.on_problem: Callable[[str], None] | None = None

    def set_client_process(self, pid: int, *, listening_port: int | None = None) -> None:
        """Serve only connections opened by ``pid`` or one of its child processes (the launched Chrome).

        ``listening_port`` is a port Chrome is known to listen on (its DevTools
        port). If no process of the tree is seen listening there, this system
        does not let the logger inspect Chrome's sockets (sandboxed or
        namespaced browser): checking is then turned off, and said so, instead
        of refusing Chrome itself. The decision depends on Chrome alone, never
        on connections another process could open.
        """
        self._client_root_pid = int(pid)
        if listening_port is not None and not _tree_is_listening(self._client_root_pid, listening_port):
            self._verification_off = True
            self._report(
                "cannot see the sockets of the captured Chrome on this system; "
                "the relay accepts connections from any local process"
            )
        self._client_ready.set()

    @property
    def problems(self) -> dict[str, int]:
        """Distinct problems seen so far, with how many times each occurred."""
        with self._state_lock:
            return dict(self._problems)

    def _report(self, message: str) -> None:
        with self._state_lock:
            first = message not in self._problems
            self._problems[message] = self._problems.get(message, 0) + 1
        if not first:
            return
        LOG.warning("Proxy relay: %s", message)
        callback = self.on_problem
        if callback is not None:
            try:
                callback(f"Proxy relay: {message}")
            except Exception:
                LOG.debug("Proxy problem callback failed", exc_info=True)

    def _client_allowed(self, client: socket.socket) -> bool:
        if not self.restrict_clients:
            return True
        # Chrome may connect before the logger has its process id; wait for it.
        if not self._client_ready.wait(timeout=30) or self._client_root_pid is None:
            return False
        if self._verification_off:
            return True
        try:
            peer_ip, peer_port = client.getpeername()[:2]
        except OSError:
            return False
        owned, process = _connection_owner(
            self._client_root_pid, (str(peer_ip), int(peer_port)), (_RELAY_HOST, self.local_port), self._owner_hint
        )
        if owned:
            with self._state_lock:
                self._owner_hint = process
            return True
        if owned is None:
            # Undecidable because of Chrome's own processes, not because of the
            # client: refusing would break the capture.
            self._report(
                "some of Chrome's processes cannot be inspected; connections that cannot be matched are accepted"
            )
            return True
        self._report("refused connections from a local process that is not the captured Chrome")
        return False

    @staticmethod
    def _is_relay_itself(host: str, port: int, local_port: int) -> bool:
        return host.casefold() in _LOOPBACK_NAMES and port == local_port

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
            except OSError as exc:
                if self._stop.is_set() or self._server.fileno() == -1:
                    break
                # ECONNABORTED/WSAECONNRESET or a full descriptor table (EMFILE)
                # are transient. Leaving the loop would keep the port open but
                # unanswered, and every request through the relay would hang.
                LOG.warning("Proxy relay could not accept a connection: %s", exc)
                self._stop.wait(0.1)
                continue
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
        label = self.upstream.label()
        try:
            raw = socket.create_connection((self.upstream.host, self.upstream.port), timeout=self.connect_timeout)
        except OSError as exc:
            raise UpstreamError(f"cannot reach the upstream proxy {label}: {exc}") from exc
        if self.upstream.scheme == "https":
            try:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                if not self.verify_tls:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                return context.wrap_socket(raw, server_hostname=self.upstream.host)
            except ssl.SSLError as exc:
                self._close_socket(raw)
                hint = "; use --proxy-insecure-tls for a self-signed certificate" if self.verify_tls else ""
                raise UpstreamError(f"TLS handshake with the upstream proxy {label} failed: {exc}{hint}") from exc
            except Exception:
                self._close_socket(raw)
                raise
        return raw

    def _refuse_rejected_credentials(self, client: socket.socket) -> None:
        # Forwarding the 407 would make Chrome ask the user for a login it
        # cannot use: the relay sends its own credentials, again and again.
        self._report(f"the upstream proxy {self.upstream.label()} rejected the credentials (HTTP 407)")
        client.sendall(_response("502 Bad Gateway", "The upstream proxy rejected the configured credentials."))

    def _screen_rejected_credentials(self, client: socket.socket) -> Callable[[bytes], bool]:
        def screen(first_chunk: bytes) -> bool:
            if _REJECTED_CREDENTIALS.match(first_chunk):
                self._refuse_rejected_credentials(client)
                return False
            return True

        return screen

    def _connect_socks5(self, host: str, port: int) -> socket.socket:
        sock = socket.create_connection((self.upstream.host, self.upstream.port), timeout=self.connect_timeout)
        try:
            socks5_connect(sock, host, port, username=self.upstream.username, password=self.upstream.password)
        except Exception:
            self._close_socket(sock)
            raise
        return sock

    def _open_route(self, host: str, port: int, use_upstream: bool) -> socket.socket:
        """Reach ``host:port`` through the SOCKS5 upstream when it is in use, otherwise directly."""
        if use_upstream:
            return self._connect_socks5(host, port)
        return socket.create_connection((host, port), timeout=self.connect_timeout)

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        # After "200 Connection established" a 502 would be injected into the tunneled stream: just close.
        tunnel_started = False
        try:
            if not self._client_allowed(client):
                return
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
            # A SOCKS5 upstream is reached like a direct destination, only through _open_route.
            via_http_proxy = use_upstream and self.upstream.scheme != "socks5"

            if method.upper() == b"CONNECT":
                connect_host, connect_port = _split_authority(target, 443)
                if self._is_relay_itself(connect_host, connect_port, self.local_port):
                    client.sendall(_response("508 Loop Detected", "The relay does not tunnel to itself."))
                    return
                if via_http_proxy:
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
                    response_head, separator, tunnel_data = response.partition(b"\r\n\r\n")
                    status_line = response_head.split(b"\r\n", 1)[0]
                    try:
                        status = int(status_line.split(b" ", 2)[1])
                    except Exception as exc:
                        raise ConnectionError(f"Invalid upstream CONNECT response: {status_line!r}") from exc
                    if status == 407:
                        self._refuse_rejected_credentials(client)
                        return
                    if not 200 <= status < 300:
                        client.sendall(response or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        return
                    if not separator:
                        raise ConnectionError("Upstream closed before completing its CONNECT response")
                    client.sendall(_CONNECTION_ESTABLISHED)
                    tunnel_started = True
                    if tunnel_data:
                        # _read_headers can read past the blank line; those bytes already belong to the tunnel.
                        client.sendall(tunnel_data)
                else:
                    upstream = self._open_route(connect_host, connect_port, use_upstream)
                    self._track(upstream)
                    client.sendall(_CONNECTION_ESTABLISHED)
                    tunnel_started = True
                if leftover:
                    upstream.sendall(leftover)
                self._tunnel(client, upstream)
                return

            # A browser talking to a proxy sends absolute-form requests. An
            # origin-form request ("GET / HTTP/1.1") comes from something using
            # the relay as a web server, and with its Host header pointing at the
            # relay it would make the relay connect to itself over and over.
            absolute = urlsplit(target)
            if absolute.scheme.casefold() != "http" or not absolute.hostname:
                client.sendall(_response("400 Bad Request", "The relay only accepts proxy requests."))
                return
            if self._is_relay_itself(absolute.hostname, absolute.port or 80, self.local_port):
                client.sendall(_response("508 Loop Detected", "The relay does not forward to itself."))
                return
            if via_http_proxy:
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
                host, port, request_headers = _origin_form_request(method, target, version, headers)
                upstream = self._open_route(host, port, use_upstream)
                self._track(upstream)
            upstream.sendall(request_headers + leftover)
            # A 407 from the upstream must not reach Chrome. It is spotted in
            # the first bytes the upstream sends; waiting for them before
            # tunnelling would stall a request body still being uploaded.
            screen = self._screen_rejected_credentials(client) if via_http_proxy else None
            self._tunnel(client, upstream, screen=screen)
        except Exception as exc:
            if isinstance(exc, SocksError) and exc.reply is None:
                # Negotiation or authentication failure: every connection will fail the same way.
                self._report(f"SOCKS5 upstream {self.upstream.label()} failed: {exc}")
            elif isinstance(exc, UpstreamError):
                self._report(str(exc))
            else:
                LOG.debug("Proxy relay connection failed: %s", exc)
            if tunnel_started:
                return  # the finally block closes both sides
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError as send_exc:
                LOG.debug("Could not return proxy failure response: %s", send_exc)
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    self._untrack(sock)
                    self._close_socket(sock)

    def _tunnel(
        self, left: socket.socket, right: socket.socket, *, screen: Callable[[bytes], bool] | None = None
    ) -> None:
        """Relay both ways; ``screen`` sees the first chunk from ``right`` and can stop the relay."""
        for sock in (left, right):
            sock.setblocking(True)
        peers = {left: right, right: left}
        # select.select rejects descriptors >= 1024 on POSIX, and 512 relayed connections use ~1024 sockets;
        # the default selector (epoll/kqueue) has no such limit.
        with selectors.DefaultSelector() as selector:
            try:
                for sock in (left, right):
                    selector.register(sock, selectors.EVENT_READ)
            except (OSError, ValueError):
                return  # a toggle or stop already closed one side
            while not self._stop.is_set():
                # Decrypted bytes buffered in an SSL socket never wake the selector: forward them first.
                ready = [sock for sock in (left, right) if _buffered_bytes(sock)]
                if not ready:
                    if left.fileno() < 0 or right.fileno() < 0:
                        return  # closed by toggle() or stop(); some selectors would just stay silent
                    try:
                        events = selector.select(timeout=_TUNNEL_POLL_SECONDS)
                    except (OSError, ValueError):
                        return
                    ready = [key.fileobj for key, _ in events]
                for source in ready:
                    data = source.recv(_TUNNEL_CHUNK)
                    if not data:
                        return
                    if screen is not None and source is right:
                        allowed, screen = screen(data), None
                        if not allowed:
                            return
                    peers[source].sendall(data)


# Without it, WebRTC sends STUN over direct UDP and exposes the real IP address.
WEBRTC_PROXY_ONLY = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"


def build_proxy_route(
    proxy: ProxySpec | None, *, verify_tls: bool = True, restrict_clients: bool = False
) -> tuple[list[str], ProxyRelay | None]:
    """Return Chrome's proxy arguments and, when one is needed, the started loopback relay.

    HTTP(S) upstreams and authenticated SOCKS5 go through the relay, which supplies the credentials that
    Chrome's command line cannot carry. Unauthenticated SOCKS4/SOCKS5 proxies are handed to Chrome as is.
    WebRTC is kept off direct UDP so a page cannot learn the real address behind the proxy through STUN.
    """
    if proxy is None:
        return [], None
    if proxy.scheme in {"socks4", "socks5"} and not proxy.has_auth:
        host = f"[{proxy.host}]" if ":" in proxy.host else proxy.host
        return [f"--proxy-server={proxy.scheme}://{host}:{proxy.port}", WEBRTC_PROXY_ONLY], None
    if proxy.scheme == "socks4":
        raise ValueError("Authenticated SOCKS4 proxies are not supported; use SOCKS5 or an HTTP(S) proxy")
    relay = ProxyRelay(proxy, verify_tls=verify_tls, restrict_clients=restrict_clients)
    relay.start()
    return [f"--proxy-server=http://127.0.0.1:{relay.local_port}", WEBRTC_PROXY_ONLY], relay


def start_toggle_keyboard(
    relay: ProxyRelay, stop_event: threading.Event, on_toggle: Callable[[bool], None] | None = None
) -> threading.Thread | None:
    """Flip between upstream and direct routing each time P is pressed, until ``stop_event`` is set.

    Windows reads the console through ``msvcrt``. On Linux/macOS an interactive stdin is switched to cbreak
    mode (Ctrl+C still raises SIGINT) and its terminal settings are restored when the loop ends or, as a
    safety net, at interpreter exit. Returns the polling thread so the caller can join it after setting
    ``stop_event``, or None when no interactive console is available.
    """
    if os.name == "nt":
        return _start_windows_toggle(relay, stop_event, on_toggle)
    return _start_posix_toggle(relay, stop_event, on_toggle)


def _apply_toggle(relay: ProxyRelay, on_toggle: Callable[[bool], None] | None) -> None:
    enabled = relay.toggle()
    print(f"\n[proxy] {'ON' if enabled else 'OFF — direct connection'}")
    if on_toggle:
        on_toggle(enabled)


def _start_daemon(loop: Callable[[], None]) -> threading.Thread:
    thread = threading.Thread(target=loop, name="proxy-keyboard", daemon=True)
    thread.start()
    return thread


def _start_windows_toggle(
    relay: ProxyRelay, stop_event: threading.Event, on_toggle: Callable[[bool], None] | None
) -> threading.Thread | None:
    try:
        import msvcrt
    except ImportError:
        return None

    def loop() -> None:
        while not stop_event.is_set():
            try:
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in {b"\x00", b"\xe0"}:
                        msvcrt.getch()  # second byte of an arrow/function key: Down arrow is b"\xe0P", not P
                    elif key in {b"p", b"P"}:
                        _apply_toggle(relay, on_toggle)
            except Exception:
                LOG.exception("Proxy keyboard toggle failed")
            time.sleep(0.05)

    return _start_daemon(loop)


class _PosixKeyReader:
    """Wait for terminal input with a timeout so the toggle loop keeps noticing its stop event."""

    def __init__(self, fd: int):
        self._fd = fd
        # select(2) is the readiness API that handles terminals everywhere (macOS poll/kqueue have tty
        # quirks), and stdin's descriptor is far below the 1024 limit.
        self._selector = selectors.SelectSelector()
        try:
            self._selector.register(fd, selectors.EVENT_READ)
        except Exception:
            self._selector.close()
            raise

    def read(self, timeout: float) -> bytes | None:
        """Return the bytes typed so far, b"" at end of input, or None when nothing arrived in time."""
        if not self._selector.select(timeout):
            return None
        return os.read(self._fd, 64)

    def close(self) -> None:
        self._selector.close()


def _owns_terminal(fd: int) -> bool:
    """False for a background job, which would be stopped (SIGTTOU/SIGTTIN) for touching the terminal."""
    try:
        return os.tcgetpgrp(fd) == os.getpgrp()
    except (AttributeError, OSError):
        return True  # not our controlling terminal, so job control cannot stop us


def _start_posix_toggle(
    relay: ProxyRelay, stop_event: threading.Event, on_toggle: Callable[[bool], None] | None
) -> threading.Thread | None:
    try:
        import termios
        import tty
    except ImportError:
        return None
    stdin = sys.stdin
    try:
        if stdin is None or not stdin.isatty():
            return None
        fd = stdin.fileno()
        if not _owns_terminal(fd):
            return None
        original = termios.tcgetattr(fd)
    except (AttributeError, OSError, ValueError, termios.error):
        return None

    restore_lock = threading.Lock()
    restored = False

    def restore() -> None:
        nonlocal restored
        with restore_lock:
            if restored:
                return
            restored = True
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, original)
            except (OSError, ValueError, termios.error) as exc:
                LOG.debug("Could not restore the terminal settings: %s", exc)

    def release() -> None:
        restore()
        atexit.unregister(restore)

    # Safety net: a daemon thread does not run its finally block when the interpreter exits.
    atexit.register(restore)
    try:
        tty.setcbreak(fd)  # unlike raw mode, cbreak keeps ISIG so Ctrl+C still delivers SIGINT
        reader = _PosixKeyReader(fd)
    except Exception as exc:
        release()
        LOG.debug("Proxy keyboard toggle unavailable: %s", exc)
        return None

    def loop() -> None:
        try:
            while not stop_event.is_set():
                try:
                    data = reader.read(_KEY_POLL_SECONDS)
                except OSError as exc:
                    LOG.debug("Proxy keyboard toggle stopped reading the terminal: %s", exc)
                    return
                if data is None:
                    continue
                if not data:
                    return  # end of input: nothing more can be typed
                if data.startswith(b"\x1b"):
                    continue  # escape sequence such as an arrow or F1 (b"\x1bOP"), not the P key
                for _ in range(data.count(b"p") + data.count(b"P")):
                    try:
                        _apply_toggle(relay, on_toggle)
                    except Exception:
                        LOG.exception("Proxy keyboard toggle failed")
        finally:
            reader.close()
            release()

    try:
        return _start_daemon(loop)
    except Exception:
        reader.close()
        release()
        raise
