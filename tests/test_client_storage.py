from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chrome_logger.cdp import CDPCapture
from chrome_logger.client_storage import storage_origin
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor

ORIGIN = "https://app.example.test"


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
    capture.targets["page-1"] = {"targetId": "t1", "type": "page", "url": f"{ORIGIN}/dashboard"}
    capture.enabled_sessions.add("page-1")
    return capture, store, socket


def drain(capture: CDPCapture) -> None:
    capture._client_storage_earliest = 1.0
    capture._process_client_storage()


def written(store: FakeStore, path: str) -> list[dict[str, Any]]:
    return [payload for name, payload in store.writes if name == path]


def sent_methods(socket: LiveSocket) -> list[str]:
    return [message["method"] for message in socket.sent]


def test_storage_origin_only_accepts_web_origins() -> None:
    assert storage_origin("https://example.test/path?x=1") == "https://example.test"
    assert storage_origin("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert storage_origin("about:blank") is None
    assert storage_origin("blob:https://example.test/uuid") is None
    assert storage_origin(None) is None


def test_tracking_starts_once_per_origin_and_queues_both_scopes(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.track_client_storage("page-1", capture.targets["page-1"])
    assert sent_methods(socket) == ["Storage.trackIndexedDBForOrigin", "Storage.trackCacheStorageForOrigin"]
    assert set(capture._client_storage_requests) == {
        (ORIGIN, "indexeddb", None, None, None),
        (ORIGIN, "cachestorage", None, None, None),
    }

    socket.sent.clear()
    capture.track_client_storage("page-1", capture.targets["page-1"])
    assert not socket.sent


def test_dumps_run_on_a_page_session_of_the_same_origin(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.request_client_storage_dump(ORIGIN, "indexeddb", reason="targetAttached")
    capture.request_client_storage_dump(ORIGIN, "cachestorage", reason="targetAttached")
    drain(capture)
    assert sent_methods(socket) == ["IndexedDB.requestDatabaseNames", "CacheStorage.requestCacheNames"]
    assert all(message["sessionId"] == "page-1" for message in socket.sent)
    assert not capture._client_storage_requests


def test_dump_is_skipped_when_no_page_of_that_origin_is_attached(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.request_client_storage_dump("https://other.example.test", "indexeddb", reason="event")
    drain(capture)
    assert not socket.sent
    assert capture.stats["clientStorageSkipped"] == 1


def test_repeated_requests_for_one_scope_collapse(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    for _ in range(5):
        capture.request_client_storage_dump(
            ORIGIN, "indexeddb", reason="indexedDBContentUpdated", database="db", store="s"
        )
    assert len(capture._client_storage_requests) == 1
    drain(capture)
    assert sent_methods(socket) == ["Runtime.evaluate"]


def test_database_names_are_stored_and_expanded(tmp_path: Path) -> None:
    capture, store, socket = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "idb_names",
        {"origin": ORIGIN, "reason": "targetAttached"},
        None,
        {"databaseNames": ["app-db", "cache-db"]},
    )
    line = written(store, "storage/indexeddb.jsonl")[0]
    assert line["kind"] == "databases"
    assert line["databases"] == ["app-db", "cache-db"]
    drain(capture)
    assert sent_methods(socket) == ["IndexedDB.requestDatabase", "IndexedDB.requestDatabase"]


def test_schema_is_stored_and_each_object_store_is_queued(tmp_path: Path) -> None:
    capture, store, socket = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "idb_database",
        {"origin": ORIGIN, "database": "app-db", "reason": "indexedDBListUpdated"},
        None,
        {
            "databaseWithObjectStores": {
                "name": "app-db",
                "version": 3,
                "objectStores": [{"name": "tokens"}, {"name": "profiles"}],
            }
        },
    )
    line = written(store, "storage/indexeddb.jsonl")[0]
    assert line["kind"] == "schema"
    assert line["database"]["version"] == 3
    assert set(capture._client_storage_requests) == {
        (ORIGIN, "indexeddb", "app-db", "tokens", None),
        (ORIGIN, "indexeddb", "app-db", "profiles", None),
    }
    drain(capture)
    assert sent_methods(socket) == ["Runtime.evaluate", "Runtime.evaluate"]


def test_object_store_records_keep_their_values(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "idb_data",
        {"origin": ORIGIN, "database": "app-db", "store": "tokens", "reason": "indexedDBContentUpdated"},
        None,
        {
            "result": {
                "value": {
                    "ok": True,
                    "truncated": True,
                    "keyPath": "id",
                    "version": 3,
                    "records": [{"key": "tok1", "value": {"id": "tok1", "scope": "read"}}],
                }
            }
        },
    )
    line = written(store, "storage/indexeddb.jsonl")[0]
    assert line["kind"] == "entries"
    assert line["objectStore"] == "tokens"
    assert line["entries"][0]["value"] == {"id": "tok1", "scope": "read"}
    assert line["hasMore"] is True
    assert line["keyPath"] == "id"
    assert capture.stats["idbEntries"] == 1


def test_failed_object_store_read_is_reported_without_entries(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "idb_data",
        {"origin": ORIGIN, "database": "app-db", "store": "tokens", "reason": "event"},
        None,
        {"result": {"value": {"ok": False, "error": "missing object store"}}},
    )
    assert not written(store, "storage/indexeddb.jsonl")
    error = written(store, "browser/protocol_errors.jsonl")[0]
    assert error["phase"] == "clientStorage"
    assert capture.stats["clientStorageErrors"] == 1
    assert capture.stats["idbEntries"] == 0


def test_indexeddb_failure_retries_once_with_the_storage_key_form(tmp_path: Path) -> None:
    capture, store, socket = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "idb_names",
        {"origin": ORIGIN, "reason": "targetAttached", "storageKey": False},
        {"code": -32000, "message": "Invalid securityOrigin"},
        {},
    )
    assert socket.sent[0]["params"] == {"storageKey": ORIGIN + "/"}
    assert capture.stats["clientStorageErrors"] == 0

    capture._handle_client_storage_response(
        "idb_names",
        {"origin": ORIGIN, "reason": "targetAttached", "storageKey": True},
        {"code": -32000, "message": "still broken"},
        {},
    )
    assert capture.stats["clientStorageErrors"] == 1
    assert written(store, "browser/protocol_errors.jsonl")[0]["method"] == "idb_names"


def test_cache_names_and_entries_are_stored(tmp_path: Path) -> None:
    capture, store, socket = make_capture(tmp_path)
    capture._handle_client_storage_response(
        "cache_names",
        {"origin": ORIGIN, "reason": "cacheStorageListUpdated"},
        None,
        {"caches": [{"cacheId": "id-1", "cacheName": "assets-v1", "securityOrigin": ORIGIN}]},
    )
    assert written(store, "storage/cache_storage.jsonl")[0]["kind"] == "caches"
    drain(capture)
    assert sent_methods(socket) == ["CacheStorage.requestEntries"]
    assert socket.sent[0]["params"]["pageSize"] == capture.config.max_cache_entries

    capture._handle_client_storage_response(
        "cache_entries",
        {"origin": ORIGIN, "cacheId": "id-1", "reason": "cacheStorageListUpdated"},
        None,
        {"cacheDataEntries": [{"requestURL": f"{ORIGIN}/app.js", "responseStatus": 200}], "returnCount": 1},
    )
    entries = written(store, "storage/cache_storage.jsonl")[1]
    assert entries["entryCount"] == 1
    assert entries["entries"][0]["requestURL"] == f"{ORIGIN}/app.js"
    assert capture.stats["cacheEntries"] == 1


def test_storage_events_queue_exactly_the_scope_that_changed(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture._storage_domain_event("page-1", "Storage.indexedDBListUpdated", {"origin": ORIGIN + "/"})
    capture._storage_domain_event(
        "page-1",
        "Storage.indexedDBContentUpdated",
        {"storageKey": ORIGIN + "/", "databaseName": "app-db", "objectStoreName": "tokens"},
    )
    capture._storage_domain_event("page-1", "Storage.cacheStorageContentUpdated", {"origin": ORIGIN})
    assert set(capture._client_storage_requests) == {
        (ORIGIN, "indexeddb", None, None, None),
        (ORIGIN, "indexeddb", "app-db", "tokens", None),
        (ORIGIN, "cachestorage", None, None, None),
    }


def test_dump_script_is_bounded_by_the_configured_limit(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture.config.max_idb_entries = 7
    script = capture._idb_dump_script("app-db", "tokens", capture.config.max_idb_entries)
    assert "const LIMIT = 7;" in script
    assert 'const DATABASE = "app-db";' in script
    assert 'const STORE = "tokens";' in script


def test_no_dump_is_queued_once_the_browser_is_gone(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    capture.connection_closed.set()
    capture.request_client_storage_dump(ORIGIN, "indexeddb", reason="event")
    drain(capture)
    assert not socket.sent
