from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chrome_logger.cdp import CDPCapture
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor


class FakeStore:
    def __init__(self) -> None:
        self.redactor = Redactor("raw")
        self.writes: list[tuple[str, dict[str, Any]]] = []
        self.warnings: list[str] = []

    def write_jsonl(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        self.writes.append((path, self.redactor.object(payload) if redact else payload))

    def write_json(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        self.write_jsonl(path, payload, redact=redact)

    def timeline(self, kind: str, timestamp: dict[str, Any], **payload: Any) -> None:
        return None

    def set_manifest(self, **_fields: Any) -> None:
        return None

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    def check_health(self) -> None:
        return None


class LiveSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))


def make_capture(tmp_path: Path) -> tuple[CDPCapture, FakeStore, LiveSocket]:
    store = FakeStore()
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile")
    capture = CDPCapture(9222, config, store)
    socket = LiveSocket()
    capture.ws = socket  # type: ignore[assignment]
    return capture, store, socket


def written(store: FakeStore, path: str) -> list[dict[str, Any]]:
    return [payload for name, payload in store.writes if name == path]


def cookie(name: str, value: str, domain: str = "example.test") -> dict[str, Any]:
    return {"name": name, "value": value, "domain": domain, "path": "/"}


def test_cookie_sync_requests_coalesce_into_one_read(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.request_cookie_sync("setCookieHeader")
    capture.request_cookie_sync("frameNavigated")
    capture._process_cookie_sync()
    capture._process_cookie_sync()
    methods = [message["method"] for message in socket.sent]
    assert methods == ["Storage.getCookies"]
    pending = next(iter(capture.pending.values()))
    assert pending.kind == "cookie_sync"
    assert pending.data["reasons"] == ["frameNavigated", "setCookieHeader"]


def test_cookie_sync_after_inflight_read_completes(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.request_cookie_sync("first")
    capture._process_cookie_sync()
    capture.request_cookie_sync("second")
    capture._process_cookie_sync()
    assert len(socket.sent) == 1

    capture._handle_cookie_sync({"reasons": ["first"]}, None, {"cookies": []})
    capture._cookie_sync_earliest = 0.0
    capture._process_cookie_sync()
    assert len(socket.sent) == 2


def test_cookie_diff_records_added_updated_and_removed(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._handle_cookie_sync(
        {"reasons": ["targetAttached"]},
        None,
        {"cookies": [cookie("a", "1"), cookie("b", "2")]},
    )
    capture._handle_cookie_sync(
        {"reasons": ["setCookieHeader"]},
        None,
        {"cookies": [cookie("a", "changed"), cookie("c", "3")]},
    )
    lines = written(store, "storage/cookie_changes.jsonl")
    assert lines[0]["baseline"] is True
    assert {change["change"] for change in lines[0]["changes"]} == {"added"}
    second = {change["change"]: change for change in lines[1]["changes"]}
    assert second["updated"]["cookie"]["value"] == "changed"
    assert second["updated"]["previous"]["value"] == "1"
    assert second["added"]["cookie"]["name"] == "c"
    assert second["removed"]["cookie"]["name"] == "b"
    assert capture.stats["cookieSyncs"] == 2

    capture._handle_cookie_sync(
        {"reasons": ["frameNavigated"]},
        None,
        {"cookies": [cookie("a", "changed"), cookie("c", "3")]},
    )
    assert len(written(store, "storage/cookie_changes.jsonl")) == 2


def test_set_cookie_header_triggers_a_sync_and_plain_responses_do_not(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture.note_response_cookies("s", {"content-type": "text/html"})
    assert not capture._cookie_sync_reasons
    capture.note_response_cookies("s", {"Set-Cookie": "a=1"})
    assert capture._cookie_sync_reasons == {"setCookieHeader"}


def test_dom_storage_events_rebuild_the_current_values(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.targets["s"] = {"targetId": "t", "type": "page", "url": "https://example.test/"}
    storage_id = {"storageKey": "https://example.test/", "isLocalStorage": True}
    capture._dom_storage_event(
        "s", "DOMStorage.domStorageItemAdded", {"storageId": storage_id, "key": "k", "newValue": "1"}
    )
    capture._dom_storage_event(
        "s",
        "DOMStorage.domStorageItemUpdated",
        {"storageId": storage_id, "key": "k", "oldValue": "1", "newValue": "2"},
    )
    capture._dom_storage_event(
        "s", "DOMStorage.domStorageItemAdded", {"storageId": storage_id, "key": "j", "newValue": "9"}
    )
    capture._dom_storage_event("s", "DOMStorage.domStorageItemRemoved", {"storageId": storage_id, "key": "j"})
    key = capture._dom_storage_key("https://example.test", True)
    assert capture._dom_storage[key]["values"] == {"k": "2"}
    assert capture.stats["storageChanges"] == 4
    assert len(written(store, "storage/dom_storage_events.jsonl")) == 4

    capture._dom_storage_event("s", "DOMStorage.domStorageItemsCleared", {"storageId": storage_id})
    assert capture._dom_storage[key]["values"] == {}


def test_attach_dump_seeds_the_mirror_that_events_build_on(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture._handle_snapshot_response(
        "snapshot_storage",
        {"label": "attach", "sessionId": "s"},
        None,
        {
            "result": {
                "value": {
                    "origin": "https://example.test",
                    "localStorage": {"ok": True, "values": {"seeded": "yes"}},
                    "sessionStorage": {"ok": False, "error": "denied"},
                }
            }
        },
    )
    key = capture._dom_storage_key("https://example.test", True)
    assert capture._dom_storage[key]["values"] == {"seeded": "yes"}
    assert capture._dom_storage_key("https://example.test", False) not in capture._dom_storage

    capture._dom_storage_event(
        "s",
        "DOMStorage.domStorageItemAdded",
        {
            "storageId": {"securityOrigin": "https://example.test", "isLocalStorage": True},
            "key": "later",
            "newValue": "1",
        },
    )
    assert capture._dom_storage[key]["values"] == {"seeded": "yes", "later": "1"}


def test_page_flush_is_stored_and_triggers_a_cookie_sync(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.interaction_contexts["s"] = {7}
    payload = {
        "event": "storage_state",
        "ts": 1_700_000_000_000,
        "trigger": "pagehide",
        "url": "https://example.test/page",
        "origin": "https://example.test",
        "localStorage": {"ok": True, "values": {"final": "state"}},
        "sessionStorage": {"ok": True, "values": {}},
        "cookie": {"names": ["a"], "count": 1, "length": 3},
    }
    capture._binding_message("s", {"executionContextId": 7, "payload": json.dumps(payload)})
    flushes = written(store, "storage/page_flushes.jsonl")
    assert flushes[0]["trigger"] == "pagehide"
    assert capture.stats["storageFlushes"] == 1
    assert capture._cookie_sync_reasons == {"pageFlush:pagehide"}
    key = capture._dom_storage_key("https://example.test", True)
    assert capture._dom_storage[key]["values"] == {"final": "state"}
    assert not written(store, "interactions/events.jsonl")


def test_page_flush_from_an_unknown_context_is_dropped(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    payload = {"event": "storage_state", "trigger": "pagehide", "origin": "https://example.test"}
    capture._binding_message("s", {"executionContextId": 3, "payload": json.dumps(payload)})
    assert capture.stats["droppedStorageFlushes"] == 1
    assert not written(store, "storage/page_flushes.jsonl")


def test_oversized_page_flush_is_dropped_with_a_warning(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.config.max_storage_payload_bytes = 256
    capture.interaction_contexts["s"] = {7}
    payload = {
        "event": "storage_state",
        "trigger": "pagehide",
        "origin": "https://example.test",
        "localStorage": {"ok": True, "values": {"big": "x" * 1024}},
    }
    capture._binding_message("s", {"executionContextId": 7, "payload": json.dumps(payload)})
    assert capture.stats["droppedStorageFlushes"] == 1
    assert store.warnings
    assert not written(store, "storage/page_flushes.jsonl")


def test_interaction_messages_still_reach_interaction_capture(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.interaction_contexts["s"] = {7}
    payload = {"event": "click", "ts": 1_700_000_000_000, "url": "https://example.test/", "target": None}
    capture._binding_message("s", {"executionContextId": 7, "payload": json.dumps(payload)})
    assert written(store, "interactions/events.jsonl")
    assert capture.stats["userEvents"] == 1


def test_final_state_is_written_without_a_live_browser(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._handle_cookie_sync({"reasons": ["targetAttached"]}, None, {"cookies": [cookie("a", "1")]})
    capture.seed_dom_storage(
        "https://example.test",
        {"localStorage": {"ok": True, "values": {"k": "v"}}},
        "flush:pagehide",
    )
    capture.ws = None
    capture.connection_closed.set()
    capture.write_final_state()

    cookies = written(store, "snapshots/cookies_final.json")[0]
    assert cookies["cookieCount"] == 1
    assert cookies["cookies"][0]["name"] == "a"
    storage = written(store, "snapshots/dom_storage_final.json")[0]
    assert storage["origins"][0]["values"] == {"k": "v"}
    assert storage["origins"][0]["sources"] == ["flush:pagehide"]


def test_cookie_sync_is_not_requested_once_the_browser_is_gone(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.connection_closed.set()
    capture.request_cookie_sync("frameNavigated")
    capture._process_cookie_sync()
    assert not socket.sent


def test_cookie_sync_failure_is_recorded_and_releases_the_slot(tmp_path: Path) -> None:
    capture, store, socket = make_capture(tmp_path)
    capture.request_cookie_sync("frameNavigated")
    capture._process_cookie_sync()
    capture._handle_cookie_sync({"reasons": ["frameNavigated"]}, {"code": -32000, "message": "no"}, {})
    assert capture._cookie_sync_inflight is False
    assert written(store, "browser/protocol_errors.jsonl")[0]["phase"] == "cookieSync"
    assert not capture.failure.is_set()
