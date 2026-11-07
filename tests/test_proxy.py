from __future__ import annotations

import ssl

import pytest

from chrome_logger import proxy as proxy_module
from chrome_logger.proxy import (
    WEBRTC_PROXY_ONLY,
    ProxyRelay,
    ProxySpec,
    _split_authority,
    build_proxy_route,
    parse_proxy_line,
    select_proxy,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1:8080", ProxySpec("http", "127.0.0.1", 8080)),
        ("host.example 3128", ProxySpec("http", "host.example", 3128)),
        ("host.example:3128:user:pass", ProxySpec("http", "host.example", 3128, "user", "pass")),
        ("host.example 3128 user pass", ProxySpec("http", "host.example", 3128, "user", "pass")),
        ("user:p%40ss@host.example:8080", ProxySpec("http", "host.example", 8080, "user", "p@ss")),
        ("https://user:pass@host.example:8443", ProxySpec("https", "host.example", 8443, "user", "pass")),
        ("socks5://host.example:1080", ProxySpec("socks5", "host.example", 1080)),
        ("[2001:db8::1]:8080", ProxySpec("http", "2001:db8::1", 8080)),
        ("[2001:db8::1]:8080:user:pass", ProxySpec("http", "2001:db8::1", 8080, "user", "pass")),
    ],
)
def test_parse_proxy_line(raw: str, expected: ProxySpec) -> None:
    assert parse_proxy_line(raw) == expected


def test_parse_comments_and_empty() -> None:
    assert parse_proxy_line("") is None
    assert parse_proxy_line("# comment") is None


@pytest.mark.parametrize("raw", ["host", "host:99999", "ftp://host:21", "host port user"])
def test_invalid_proxy(raw: str) -> None:
    with pytest.raises((ValueError, TypeError)):
        parse_proxy_line(raw)


def test_split_authority_ipv4_and_ipv6() -> None:
    assert _split_authority("example.com:443", 80) == ("example.com", 443)
    assert _split_authority("[2001:db8::1]:8443", 443) == ("2001:db8::1", 8443)
    assert _split_authority("2001:db8::1", 443) == ("2001:db8::1", 443)


def test_proxy_is_never_enabled_implicitly() -> None:
    proxies = [ProxySpec("http", "one.example", 8080), ProxySpec("http", "two.example", 8080)]
    assert select_proxy(proxies, None) is None
    assert select_proxy(proxies, "none") is None


def test_explicit_proxy_request_fails_when_file_has_no_valid_entries() -> None:
    with pytest.raises(ValueError, match="No valid proxy"):
        select_proxy([], "random")
    with pytest.raises(ValueError, match="No valid proxy"):
        select_proxy([], None, prompt=True)


def test_proxy_prompt_without_an_interactive_stdin_is_a_value_error(monkeypatch) -> None:
    def closed_stdin(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", closed_stdin)
    proxies = [ProxySpec("http", "one.example", 8080)]
    with pytest.raises(ValueError, match="--proxy-prompt needs an interactive terminal"):
        select_proxy(proxies, None, prompt=True)


def test_random_proxy_choices_use_the_random_module(monkeypatch) -> None:
    proxies = [ProxySpec("http", "one.example", 8080), ProxySpec("http", "two.example", 8080)]
    monkeypatch.setattr(proxy_module.random, "choice", lambda items: items[-1])
    assert select_proxy(proxies, "random") is proxies[-1]
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")  # Enter at the prompt picks at random
    assert select_proxy(proxies, None, prompt=True) is proxies[-1]


@pytest.mark.parametrize(
    ("proxy", "argument"),
    [
        (ProxySpec("socks5", "socks.example", 1080), "--proxy-server=socks5://socks.example:1080"),
        (ProxySpec("socks4", "socks.example", 1080), "--proxy-server=socks4://socks.example:1080"),
        (ProxySpec("socks5", "2001:db8::1", 1080), "--proxy-server=socks5://[2001:db8::1]:1080"),
    ],
)
def test_unauthenticated_socks_goes_straight_to_chrome(proxy: ProxySpec, argument: str) -> None:
    assert build_proxy_route(proxy) == ([argument, WEBRTC_PROXY_ONLY], None)


def test_authenticated_socks5_is_routed_through_the_relay() -> None:
    proxy = ProxySpec("socks5", "socks.example", 1080, "alice", "secret")
    args, relay = build_proxy_route(proxy)
    assert relay is not None
    try:
        assert relay.upstream == proxy
        assert relay.enabled is True
        assert args == [f"--proxy-server=http://127.0.0.1:{relay.local_port}", WEBRTC_PROXY_ONLY]
    finally:
        relay.stop()


def test_authenticated_socks4_is_rejected_clearly() -> None:
    with pytest.raises(ValueError, match="Authenticated SOCKS4 proxies are not supported"):
        build_proxy_route(ProxySpec("socks4", "socks.example", 1080, "alice", "secret"))


def test_relay_rejects_socks4_upstreams() -> None:
    with pytest.raises(ValueError, match="HTTP, HTTPS and SOCKS5"):
        ProxyRelay(ProxySpec("socks4", "socks.example", 1080))


@pytest.mark.parametrize("verify_tls", [True, False])
def test_https_upstream_requires_tls_1_2(monkeypatch, verify_tls: bool) -> None:
    class FakeContext:
        minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, raw, *, server_hostname):
            assert server_hostname == "proxy.example"
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2
            return raw

    raw = object()
    context = FakeContext()
    monkeypatch.setattr(proxy_module.socket, "create_connection", lambda *_args, **_kwargs: raw)
    monkeypatch.setattr(proxy_module.ssl, "create_default_context", lambda: context)
    relay = ProxyRelay(ProxySpec("https", "proxy.example", 443), verify_tls=verify_tls)
    relay.start()
    try:
        assert relay._connect_upstream() is raw
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        if verify_tls:
            assert context.check_hostname is True
            assert context.verify_mode == ssl.CERT_REQUIRED
        else:
            assert context.check_hostname is False
            assert context.verify_mode == ssl.CERT_NONE
    finally:
        relay.stop()
