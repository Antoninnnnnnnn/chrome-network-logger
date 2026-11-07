"""Isolated-world page script (Shadow DOM, script-written cookies, storage-only mode) and safe-mode redaction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chrome_logger.cdp import CDPCapture
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlXzEyMw"


class Store:
    def __init__(self) -> None:
        self.redactor = Redactor("safe")
        self.writes: list[tuple[str, Any]] = []

    def write_jsonl(self, path: str, payload: Any, *, redact: bool = False) -> None:
        self.writes.append((path, payload))

    def timeline(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def add_warning(self, _warning: str) -> None:
        return None

    def check_health(self) -> None:
        return None


def make_capture(tmp_path: Path, **options: Any) -> tuple[CDPCapture, Store]:
    store = Store()
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile", **options)
    return CDPCapture(9222, config, store), store


def installed(capture: CDPCapture) -> list[str]:
    sent: list[str] = []
    capture.send = lambda method, *_args, **_kwargs: sent.append(method) or len(sent)  # type: ignore[method-assign]
    capture._enable_session("s", {"targetId": "t", "type": "page", "url": "https://a.test/"})
    return sent


# --- the page script ---------------------------------------------------------------


def test_storage_capture_alone_still_installs_the_isolated_world(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path, capture_interactions=False)
    sent = installed(capture)
    assert "Page.addScriptToEvaluateOnNewDocument" in sent and "Runtime.addBinding" in sent
    script = capture._interaction_script()
    assert "const INTERACTIONS = false;" in script and "const STORAGE = true;" in script


def test_nothing_is_injected_without_interactions_or_storage(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path, capture_interactions=False, capture_storage=False, capture_client_storage=False)
    assert "Page.addScriptToEvaluateOnNewDocument" not in installed(capture)


def test_script_follows_events_into_open_shadow_roots(tmp_path: Path) -> None:
    script = make_capture(tmp_path)[0]._interaction_script()
    assert "e.composedPath()" in script
    # change and submit do not cross shadow boundaries: roots get their own listeners.
    assert "root.addEventListener('change', onChange" in script
    assert "root.addEventListener('submit', onSubmit" in script


def test_script_reports_cookies_written_by_page_script(tmp_path: Path) -> None:
    script = make_capture(tmp_path)[0]._interaction_script()
    assert "window.cookieStore.addEventListener('change'" in script
    assert "setInterval(pollCookie, 1000)" in script


def test_cookie_hint_triggers_a_jar_read_and_is_not_an_interaction(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.is_live = lambda: True  # type: ignore[method-assign]
    capture._binding_message("s", {"payload": json.dumps({"event": "cookie_hint", "source": "cookieStore"})})
    assert capture.stats["cookieHints"] == 1
    assert "pageScript:cookieStore" in capture._cookie_sync_reasons
    assert store.writes == []


def test_interaction_messages_are_dropped_when_interactions_are_off(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path, capture_interactions=False)
    capture._binding_message("s", {"payload": json.dumps({"event": "click", "ts": 1})})
    assert store.writes == []


# --- safe-mode redaction ---------------------------------------------------------------


@pytest.mark.parametrize("name", ["authToken", "apiToken", "userSecret", "secretKey", "privateKey", "private_key"])
def test_camel_case_secret_names_are_redacted(name: str) -> None:
    assert "S3CR3T" not in json.dumps(Redactor("safe").object({name: "S3CR3T"}))


@pytest.mark.parametrize("name", ["pinned", "tokens", "secretary_count", "theme"])
def test_ordinary_names_are_kept(name: str) -> None:
    assert Redactor("safe").object({name: "visible"}) == {name: "visible"}


def test_application_session_ids_in_storage_are_redacted_but_cdp_ids_are_kept() -> None:
    clean = Redactor("safe").object(
        {"sessionId": "CDP-SESSION", "storage": {"localStorage": {"values": {"sessionId": "APP-SESSION"}}}}
    )
    assert clean["sessionId"] == "CDP-SESSION"
    assert "APP-SESSION" not in json.dumps(clean)


@pytest.mark.parametrize(
    ("value", "secret"),
    [
        ('{"token":"T1","user":"bob"}', "T1"),  # JSON stored as a string
        ('42["auth",{"token":"T2"}]', "T2"),  # Socket.IO frame
        (f"see {JWT} here", JWT),
    ],
)
def test_secrets_inside_strings_are_redacted(value: str, secret: str) -> None:
    assert secret not in json.dumps(Redactor("safe").object({"values": {"k": value}}))


def test_url_values_and_paths_are_scanned_and_untouched_parts_keep_their_text() -> None:
    redactor = Redactor("safe")
    query = redactor.url(f"https://a.test/cb?request={JWT}&x=a,b&flag")
    assert JWT not in (query or "")
    assert query is not None and query.endswith("&x=a,b&flag")
    assert JWT not in (redactor.url(f"https://a.test/magic/{JWT}/open") or "")
    form = redactor.body_text("payload=%7B%22password%22%3A%22P1%22%7D&page=2", "application/x-www-form-urlencoded")
    assert "P1" not in form and form.endswith("&page=2")


def test_url_fragment_field_keeps_its_hash_and_loses_its_code() -> None:
    clean = Redactor("safe").object({"urlFragment": "#/cb?code=FRAGCODE&tab=1"})
    assert clean["urlFragment"].startswith("#/cb?code=") and "FRAGCODE" not in clean["urlFragment"]
    assert clean["urlFragment"].endswith("&tab=1")


def test_text_multipart_parts_are_scanned_and_file_parts_kept() -> None:
    body = (
        '--B\r\nContent-Disposition: form-data; name="operations"\r\n\r\n{"variables":{"password":"P2"}}\r\n'
        '--B\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\npassword=FILEDATA\r\n--B--\r\n'
    )
    clean = Redactor("safe").body_text(body, "multipart/form-data; boundary=B")
    assert "P2" not in clean
    assert "password=FILEDATA" in clean


def test_structure_under_a_sensitive_name_is_kept() -> None:
    clean = Redactor("safe").object({"session": {"user": "bob", "remember": True, "roles": ["admin"]}})
    assert set(clean["session"]) == {"user", "remember", "roles"}
    assert clean["session"]["remember"] is True
    assert "bob" not in json.dumps(clean) and "admin" not in json.dumps(clean)


def test_basic_and_bearer_are_redacted_only_before_credentials() -> None:
    redactor = Redactor("safe")
    assert redactor.text("Choose the Basic plan or the Basic Membership") == (
        "Choose the Basic plan or the Basic Membership"
    )
    assert "dXNlcjpwYXNz" not in redactor.text("Authorization was Basic dXNlcjpwYXNzd29yZA==")
    assert "abc.def-123" not in redactor.text("Bearer abc.def-123")


# --- regressions found in review ----------------------------------------------------------


@pytest.mark.parametrize("name", ["sessionStorage", "sessionStart", "tokenType", "pageTokenCount"])
def test_names_that_merely_mention_a_secret_word_stay_readable(name: str) -> None:
    assert Redactor("safe").object({name: "visible"}) == {name: "visible"}


def test_session_storage_dumps_keep_their_values() -> None:
    flush = {"localStorage": {"values": {"theme": "dark"}}, "sessionStorage": {"values": {"step": "2"}}}
    assert Redactor("safe").object(flush) == flush


def test_deeply_nested_json_inside_a_string_never_raises() -> None:
    nested = "[" * 3000 + "]" * 3000
    assert Redactor("safe").text(nested)
    assert Redactor("safe").object({"payload": nested})


@pytest.mark.parametrize("credential", ["abc123", "YTpi", "abcdefghijklmnop", "dXNlcjpwYXNz"])
def test_short_or_alphabetic_credentials_are_still_redacted(credential: str) -> None:
    assert credential not in Redactor("safe").text(f"Authorization: none; sent Bearer {credential} later")


def test_keys_under_a_sensitive_name_that_are_secrets_themselves_are_redacted() -> None:
    clean = Redactor("safe").object({"secret": {"sk_live_ABCDEF123456": True, "expiresAt": 5}})
    assert "sk_live_ABCDEF123456" not in json.dumps(clean)
    assert "expiresAt" in clean["secret"]


def test_secrets_in_json_keys_are_redacted_and_the_json_stays_valid() -> None:
    clean = Redactor("safe").text('{"/cb?access_token=SECRETXYZ":1}')
    assert "SECRETXYZ" not in clean
    json.loads(clean)


def test_a_bare_query_piece_holding_a_token_is_redacted() -> None:
    assert JWT not in (Redactor("safe").url(f"https://a.test/cb?{JWT}") or "")


def test_fragment_parameters_whose_values_contain_a_question_mark() -> None:
    url = Redactor("safe").url("https://a.test/#access_token=SECRETTOKEN1&redirect=/x?y=1") or ""
    assert "SECRETTOKEN1" not in url and url.endswith("&redirect=/x?y=1")


def test_markers_are_never_redacted_twice() -> None:
    redactor = Redactor("safe")
    once = redactor.text("password=hunter2")
    assert redactor.text(once) == once
