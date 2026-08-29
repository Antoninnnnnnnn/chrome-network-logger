from __future__ import annotations

import pytest

from chrome_logger.proxy import ProxySpec, _split_authority, parse_proxy_line, select_proxy


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
