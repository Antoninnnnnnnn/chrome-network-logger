"""Proxy, managed Chrome, redaction and injected-script hardening."""

from __future__ import annotations

import errno
import hashlib
import json
import shutil
import socket
import time
import zipfile
from pathlib import Path

import pytest
from test_managed_chrome import fake_https

from chrome_logger import managed_chrome as managed
from chrome_logger.cdp import CDPCapture
from chrome_logger.cli import build_parser
from chrome_logger.config import CaptureConfig
from chrome_logger.proxy import ProxyRelay, ProxySpec, parse_proxy_line, select_proxy
from chrome_logger.redaction import Redactor

# --- proxy ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "host", "port", "user", "password"),
    [
        ("1.2.3.4:8080:user:p@ss", "1.2.3.4", 8080, "user", "p@ss"),
        ("user:pa:ss@host:8080", "host", 8080, "user", "pa:ss"),
        ("user:pa@ss@host:8080", "host", 8080, "user", "pa@ss"),
        ("host 8080 user p@ss", "host", 8080, "user", "p@ss"),
        ("[::1]:8080:u:p@x", "::1", 8080, "u", "p@x"),
        ("u:p@[::1]:8080", "::1", 8080, "u", "p"),
    ],
)
def test_passwords_containing_at_signs_parse_in_every_format(line, host, port, user, password) -> None:
    spec = parse_proxy_line(line)
    assert spec is not None
    assert (spec.host, spec.port, spec.username, spec.password) == (host, port, user, password)


def test_invalid_proxy_line_error_never_contains_the_password() -> None:
    with pytest.raises(ValueError) as caught:
        parse_proxy_line("http://user:s3cret@host:99999")
    assert "s3cret" not in str(caught.value)


def test_proxy_prompt_prompts_when_no_proxy_is_named(monkeypatch) -> None:
    args = build_parser().parse_args(["--proxy-prompt"])
    proxies = [ProxySpec("http", "p.example", 8080)]
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    assert select_proxy(proxies, args.proxy, prompt=args.proxy_prompt) == proxies[0]
    assert select_proxy(proxies, build_parser().parse_args([]).proxy) is None


class _FlakyServer:
    """A listening socket whose first accept() calls fail like ECONNABORTED/EMFILE do."""

    def __init__(self, real: socket.socket, failures: int) -> None:
        self.real = real
        self.failures = failures

    def accept(self):
        if self.failures:
            self.failures -= 1
            raise OSError(errno.ECONNABORTED, "Software caused connection abort")
        return self.real.accept()

    def __getattr__(self, name: str):
        return getattr(self.real, name)


def _refused_port() -> int:
    """A loopback port nothing listens on: connections to it are refused at once."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_relay_keeps_accepting_after_a_transient_accept_error() -> None:
    relay = ProxyRelay(ProxySpec("http", "127.0.0.1", _refused_port()))
    flaky = _FlakyServer(relay._server, failures=2)
    relay._server = flaky  # type: ignore[assignment]
    relay.start()
    try:
        deadline = time.monotonic() + 3
        while flaky.failures and time.monotonic() < deadline:
            time.sleep(0.02)
        assert relay._thread.is_alive()
        with socket.create_connection(("127.0.0.1", relay.local_port), timeout=2) as client:
            client.sendall(b"CONNECT unreachable.invalid:443 HTTP/1.1\r\nHost: unreachable.invalid:443\r\n\r\n")
            client.settimeout(10)
            assert client.recv(64).startswith(b"HTTP/1.1 ")
    finally:
        relay.stop()


# --- managed Chrome -----------------------------------------------------------


def test_truncated_download_is_reported_as_such(monkeypatch, tmp_path: Path) -> None:
    fake_https(monkeypatch, b"x" * 60, "100")
    with pytest.raises(managed.ManagedChromeError, match="cut off \\(60 of 100 bytes\\)"):
        managed._download_https(managed._archive_url("150.0.1234.56", "win64"), tmp_path / "c.zip", maximum=1000)


def _install(monkeypatch, tmp_path: Path) -> tuple[managed.ManagedChrome, Path, Path]:
    version, platform_id = "150.0.1234.56", "win64"
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("chrome-win64/chrome.exe", b"synthetic chrome")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(managed, "chrome_for_testing_platform", lambda: platform_id)
    monkeypatch.setattr(managed, "_stable_release", lambda _p: (version, managed._archive_url(version, platform_id)))

    def fake_download(_url, destination: Path, *, maximum: int, progress=None) -> str:
        shutil.copyfile(source, destination)
        return digest

    monkeypatch.setattr(managed, "_download_https", fake_download)
    cache = tmp_path / "cache"
    return managed.ensure_managed_chrome(cache, progress=lambda _m: None), cache, source


def test_refresh_falls_back_to_the_cached_browser_when_offline(monkeypatch, tmp_path: Path) -> None:
    installed, cache, _source = _install(monkeypatch, tmp_path)

    def offline(_platform):
        raise managed.ManagedChromeError("Could not read official Chrome metadata: no network")

    monkeypatch.setattr(managed, "_stable_release", offline)
    messages: list[str] = []
    assert managed.ensure_managed_chrome(cache, refresh=True, progress=messages.append) == installed
    assert any("using cached Chrome" in message for message in messages)


def test_install_accepts_a_copy_another_run_published_meanwhile(monkeypatch, tmp_path: Path) -> None:
    version, platform_id = "150.0.1234.56", "win64"
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("chrome-win64/chrome.exe", b"synthetic chrome")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(managed, "chrome_for_testing_platform", lambda: platform_id)
    monkeypatch.setattr(managed, "_stable_release", lambda _p: (version, managed._archive_url(version, platform_id)))
    monkeypatch.setattr(
        managed, "_download_https", lambda _u, destination, **_k: shutil.copyfile(source, destination) and digest
    )
    cache = tmp_path / "cache"
    version_root = cache / platform_id / version
    real_extract = managed._extract_archive

    def extract_while_another_run_publishes(archive: Path, staging: Path) -> None:
        real_extract(archive, staging)
        # The other run finishes first and publishes the same version.
        real_extract(archive, version_root)
        (version_root / "install.json").write_text(
            json.dumps(
                {
                    "archiveSha256": digest,
                    "executableSha256": hashlib.sha256(b"synthetic chrome").hexdigest(),
                    "platform": platform_id,
                    "sourceUrl": managed._archive_url(version, platform_id),
                    "version": version,
                }
            )
        )

    monkeypatch.setattr(managed, "_extract_archive", extract_while_another_run_publishes)
    installed = managed.ensure_managed_chrome(cache, progress=lambda _m: None)
    assert installed.version == version
    assert installed.executable.read_bytes() == b"synthetic chrome"
    assert not list((cache / platform_id).glob(".*-extract-*"))


# --- redaction (safe mode) ------------------------------------------------------


def test_referer_and_location_are_redacted_as_urls() -> None:
    headers = Redactor("safe").headers(
        {"Referer": "https://a.test/cb?code=AUTHCODE", "Location": "/next?token=T0K", "Accept": "*/*"}
    )
    assert "AUTHCODE" not in headers["Referer"] and headers["Referer"].startswith("https://a.test/cb?code=")
    assert "T0K" not in headers["Location"]
    assert headers["Accept"] == "*/*"


def test_blocked_cookie_lines_and_list_shaped_headers_are_redacted() -> None:
    redactor = Redactor("safe")
    blocked = redactor.object({"blockedCookies": [{"cookieLine": "sid=SECRET; Path=/", "blockedReasons": ["x"]}]})
    assert "SECRET" not in json.dumps(blocked)
    cached = redactor.object(
        {
            "requestURL": "https://a.test/?token=OPAQUE",
            "requestHeaders": [{"name": "Authorization", "value": "Bearer OPAQUE"}, {"name": "Accept", "value": "a"}],
        }
    )
    assert "OPAQUE" not in json.dumps(cached)
    assert cached["requestHeaders"][1] == {"name": "Accept", "value": "a"}


def test_storage_values_are_redacted_by_their_storage_key() -> None:
    assert "opaque" not in str(Redactor("safe").keyed_value("access_token", "opaque"))
    assert Redactor("safe").keyed_value("theme", "dark") == "dark"
    assert Redactor("raw").keyed_value("access_token", "opaque") == "opaque"


def test_deeply_nested_json_body_falls_back_to_text_redaction() -> None:
    body = "[" * 100_000 + "]" * 100_000
    assert Redactor("safe").body_text(body, "application/json")


# --- injected interaction script -------------------------------------------------


def _script(tmp_path: Path) -> str:
    class DummyStore:
        pass

    return CDPCapture(9222, CaptureConfig(tmp_path, tmp_path / "profile"), DummyStore())._interaction_script()


def test_form_capture_never_constructs_form_data(tmp_path: Path) -> None:
    script = _script(tmp_path)
    # new FormData(form) fires a `formdata` event the page's own listeners receive.
    assert "new FormData" not in script
    assert "formEntries(form, e.submitter)" in script
    # Controls named "elements"/"action"/"method" must not shadow the form's own properties.
    assert "formControls(form)" in script and "formAction(form)" in script


def test_keydown_skips_auto_repeat_ime_and_altgr_characters(tmp_path: Path) -> None:
    script = _script(tmp_path)
    assert "e.repeat || e.isComposing" in script
    assert "getModifierState('AltGraph')" in script


def test_large_elements_are_not_serialized_per_event(tmp_path: Path) -> None:
    script = _script(tmp_path)
    assert "el.innerText" not in script
    # cloneNode() would run the constructor of the page's custom elements.
    assert "cloneNode" not in script
    assert "openingTag(el, attrs)" in script
    assert "el.isContentEditable" in script
    assert "trusted: e ? e.isTrusted : null" in script
