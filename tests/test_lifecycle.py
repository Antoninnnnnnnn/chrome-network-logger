"""Target lifecycle, shutdown settling, reader robustness and storage-reading context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from chrome_logger.cdp import CDPCapture
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor
from chrome_logger.registry import RequestRegistry

ORIGIN = "https://app.example.test"


class FakeStore:
    def __init__(self, mode: str = "raw") -> None:
        self.redactor = Redactor(mode)
        self.writes: list[tuple[str, dict[str, Any]]] = []
        self.warnings: list[str] = []
        self.healthy = True

    def write_jsonl(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        self.writes.append((path, self.redactor.object(payload) if redact else payload))

    def write_json(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        self.write_jsonl(path, payload, redact=redact)

    def timeline(self, kind: str, timestamp: dict[str, Any], **payload: Any) -> None:
        return None

    def store_body(self, body: Any, **options: Any) -> dict[str, Any]:
        return {"path": "network/bodies/x.bin", "role": options.get("role")}

    def set_manifest(self, **_fields: Any) -> None:
        return None

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    def check_health(self) -> None:
        if not self.healthy:
            raise RuntimeError("writer failed")


class LiveSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))


def make_capture(tmp_path: Path, mode: str = "raw") -> tuple[CDPCapture, FakeStore, LiveSocket]:
    store = FakeStore(mode)
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile", sensitive_mode=mode)
    capture = CDPCapture(9222, config, store)  # type: ignore[arg-type]
    socket = LiveSocket()
    capture.ws = socket  # type: ignore[assignment]
    return capture, store, socket


def methods(socket: LiveSocket) -> list[str]:
    return [message["method"] for message in socket.sent]


def written(store: FakeStore, path: str) -> list[dict[str, Any]]:
    return [payload for name, payload in store.writes if name == path]


def attach_page(capture: CDPCapture, session: str = "S1", target: str = "T1", url: str = "about:blank") -> None:
    capture.handle(
        {
            "method": "Target.attachedToTarget",
            "params": {"sessionId": session, "targetInfo": {"targetId": target, "type": "page", "url": url}},
        }
    )


# --------------------------------------------------------------- navigation


def test_client_storage_starts_when_a_blank_tab_navigates_to_an_origin(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    attach_page(capture)
    assert "Storage.trackIndexedDBForOrigin" not in methods(socket)

    socket.sent.clear()
    capture.handle(
        {
            "method": "Target.targetInfoChanged",
            "params": {"targetInfo": {"targetId": "T1", "type": "page", "url": f"{ORIGIN}/home"}},
        }
    )
    sent = methods(socket)
    assert sent.count("Storage.trackIndexedDBForOrigin") == 1
    assert sent.count("Storage.trackCacheStorageForOrigin") == 1
    # A baseline Web Storage read for the new origin, through CDP only.
    assert sent.count("DOMStorage.getDOMStorageItems") == 2
    assert "Runtime.evaluate" not in sent

    socket.sent.clear()
    capture.handle(
        {
            "method": "Target.targetInfoChanged",
            "params": {"targetInfo": {"targetId": "T1", "type": "page", "url": f"{ORIGIN}/other-page"}},
        }
    )
    assert not socket.sent, "same-origin navigation must not re-track or re-dump"


def test_tracking_is_per_session_and_released_on_detach(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    attach_page(capture, "S1", "T1", f"{ORIGIN}/")
    attach_page(capture, "S2", "T2", f"{ORIGIN}/")
    assert methods(socket).count("Storage.trackIndexedDBForOrigin") == 2

    capture.handle({"method": "Target.detachedFromTarget", "params": {"sessionId": "S1"}})
    assert all(session != "S1" for session, _ in capture._client_storage_origins)


# ------------------------------------------------------------------ shutdown


def _finished_request(capture: CDPCapture, request_id: str = "r1") -> None:
    capture.targets["S1"] = {"targetId": "T1", "type": "page", "url": f"{ORIGIN}/"}
    capture.enabled_sessions.add("S1")
    capture._request_will_be_sent(
        "S1", {"requestId": request_id, "type": "Image", "request": {"url": f"{ORIGIN}/a.png", "method": "GET"}}
    )
    capture._response_received(
        "S1",
        {"requestId": request_id, "type": "Image", "hasExtraInfo": True, "response": {"status": 200, "headers": {}}},
    )
    capture._loading_finished("S1", {"requestId": request_id, "encodedDataLength": 10})


def test_shutdown_writes_finished_requests_as_complete(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    _finished_request(capture)
    capture.flush_open("keyboardInterrupt")

    record = written(store, "network/requests.jsonl")[-1]
    assert "incomplete" not in record
    assert record["extraInfoIncomplete"] is True
    assert record["finalizeReason"] == "loadingFinished"
    assert capture.stats["incompleteFlushed"] == 0


def test_shutdown_marks_only_unfinished_requests_incomplete(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._request_will_be_sent(
        "S1", {"requestId": "r2", "type": "XHR", "request": {"url": f"{ORIGIN}/api", "method": "GET"}}
    )
    capture.flush_open("keyboardInterrupt")
    record = written(store, "network/requests.jsonl")[-1]
    assert record["incomplete"] is True
    assert record["incompleteReason"] == "keyboardInterrupt"
    assert capture.stats["incompleteFlushed"] == 1


def test_finished_request_waiting_for_its_body_records_the_missing_body(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture._request_will_be_sent(
        "S1", {"requestId": "r3", "type": "XHR", "request": {"url": f"{ORIGIN}/api", "method": "GET"}}
    )
    capture._response_received("S1", {"requestId": "r3", "type": "XHR", "response": {"status": 200, "headers": {}}})
    capture._loading_finished("S1", {"requestId": "r3"})
    capture.flush_open("keyboardInterrupt")
    record = written(store, "network/requests.jsonl")[-1]
    assert "incomplete" not in record
    assert "before keyboardInterrupt" in record["responseBodyError"]["message"]
    assert capture.stats["bodyErrors"] == 1


def test_detached_target_counts_cut_off_requests_separately(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    attach_page(capture, "S1", "T1", f"{ORIGIN}/")
    capture._request_will_be_sent(
        "S1", {"requestId": "live", "type": "XHR", "request": {"url": f"{ORIGIN}/poll", "method": "GET"}}
    )
    _finished_request(capture, "done")
    capture.handle({"method": "Target.detachedFromTarget", "params": {"sessionId": "S1"}})

    records = {record["requestId"]: record for record in written(store, "network/requests.jsonl")}
    assert records["live"]["incompleteReason"] == "targetDetached"
    assert "incomplete" not in records["done"]
    assert capture.stats["incompleteDetached"] == 1
    assert capture.stats["incompleteFlushed"] == 0


# ------------------------------------------------------------------- reader


class ScriptedSocket:
    def __init__(self, messages: int) -> None:
        self.remaining = messages

    def recv(self) -> str:
        if self.remaining <= 0:
            import websocket

            raise websocket.WebSocketConnectionClosedException("done")
        self.remaining -= 1
        return json.dumps({"method": "Unknown.event", "params": {}})

    def send(self, _payload: str) -> None:
        return None


def test_a_failing_housekeeping_task_does_not_kill_the_reader(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture.ws = ScriptedSocket(5)  # type: ignore[assignment]
    calls = {"cookie": 0, "client": 0}

    def broken() -> None:
        calls["cookie"] += 1
        raise RuntimeError("synthetic")

    def healthy() -> None:
        calls["client"] += 1

    capture._process_cookie_sync = broken  # type: ignore[method-assign]
    capture._process_client_storage = healthy  # type: ignore[method-assign]
    capture.loop()
    assert calls["cookie"] == 5
    assert calls["client"] == 5, "later tasks keep running after an earlier one fails"
    assert capture.stats["eventErrors"] == 5
    assert not capture.failure.is_set()


def test_a_reader_error_with_a_dead_writer_is_fatal_not_a_disconnect(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.ws = ScriptedSocket(1)  # type: ignore[assignment]
    store.healthy = False

    def broken() -> None:
        raise RuntimeError("queue closed")

    capture._process_finalize_deadlines = broken  # type: ignore[method-assign]
    capture.loop()
    assert capture.failure.is_set()
    assert "storage failed" in str(store.warnings)


# --------------------------------------------------------- isolated context


def test_idb_reads_use_the_context_of_the_matching_origin(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture.targets["S1"] = {"targetId": "T1", "type": "page", "url": f"{ORIGIN}/"}
    for context_id, origin, frame in ((3, ORIGIN, "T1"), (9, "https://ads.example.test", "F2")):
        capture.handle(
            {
                "method": "Runtime.executionContextCreated",
                "sessionId": "S1",
                "params": {
                    "context": {
                        "id": context_id,
                        "name": capture.world_name,
                        "origin": origin,
                        "auxData": {"frameId": frame},
                    }
                },
            }
        )
    assert capture._isolated_context("S1", ORIGIN) == 3
    assert capture._isolated_context("S1", "https://ads.example.test") == 9
    assert capture._isolated_context("S1", "https://unknown.example.test") is None

    capture.handle(
        {"method": "Runtime.executionContextDestroyed", "sessionId": "S1", "params": {"executionContextId": 3}}
    )
    assert capture._isolated_context("S1", ORIGIN) is None


def test_idb_dump_script_never_creates_or_blocks_databases() -> None:
    script = CDPCapture._idb_dump_script("db", "store", 10)
    assert "indexedDB.databases()" in script
    assert "onupgradeneeded" in script and "transaction.abort()" in script
    assert "onversionchange" in script


# ---------------------------------------------------------------- web storage


def test_full_dump_replaces_the_mirror(tmp_path: Path) -> None:
    capture, _, _ = make_capture(tmp_path)
    capture.seed_dom_storage(ORIGIN, {"localStorage": {"ok": True, "values": {"a": "1", "b": "2"}}}, "dump:start")
    capture.seed_dom_storage(ORIGIN, {"localStorage": {"ok": True, "values": {"a": "1"}}}, "flush:pagehide")
    key = capture._dom_storage_key(ORIGIN, True)
    assert capture._dom_storage[key]["values"] == {"a": "1"}


def test_session_storage_stays_separate_per_tab(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path)
    capture.seed_dom_storage(ORIGIN, {"sessionStorage": {"ok": True, "values": {"tab": "one"}}}, "dump", "S1")
    capture.seed_dom_storage(ORIGIN, {"sessionStorage": {"ok": True, "values": {"tab": "two"}}}, "dump", "S2")
    capture._dom_storage_event(
        "S2",
        "DOMStorage.domStorageItemAdded",
        {"storageId": {"securityOrigin": ORIGIN, "isLocalStorage": False}, "key": "extra", "newValue": "x"},
    )
    capture.write_final_state()
    final = written(store, "snapshots/dom_storage_final.json")[0]
    by_session = {origin.get("sessionId"): origin["values"] for origin in final["origins"]}
    assert by_session == {"S1": {"tab": "one"}, "S2": {"tab": "two", "extra": "x"}}


# ------------------------------------------------------------------ realtime


def _binary_frame(capture: CDPCapture, payload: str) -> None:
    capture._websocket_frame(
        "S1", "Network.webSocketFrameReceived", {"requestId": "w", "response": {"opcode": 2, "payloadData": payload}}
    )


def test_small_binary_frames_stay_inline_in_raw_mode(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path, "raw")
    _binary_frame(capture, "aGVsbG8=")  # "hello"
    frame = written(store, "realtime/websocket_frames.jsonl")[-1]
    assert frame["payloadBase64"] == "aGVsbG8="
    assert frame["payloadText"] == "hello"
    assert "payload" not in frame

    _binary_frame(capture, "AAEC/w==")
    frame = written(store, "realtime/websocket_frames.jsonl")[-1]
    assert frame["payloadBase64"] == "AAEC/w=="
    assert "payloadText" not in frame


def test_binary_frames_still_go_through_body_storage_in_safe_mode(tmp_path: Path) -> None:
    capture, store, _ = make_capture(tmp_path, "safe")
    _binary_frame(capture, "aGVsbG8=")
    frame = written(store, "realtime/websocket_frames.jsonl")[-1]
    assert "payloadBase64" not in frame
    assert frame["payload"]["role"] == "websocket-frame"


# ------------------------------------------------------------------ registry


@pytest.mark.parametrize("total", [5, 50])
def test_finished_requests_do_not_keep_hop_counters_forever(total: int) -> None:
    registry = RequestRegistry()
    registry.max_retired_hops = 10
    for index in range(total):
        key = registry.create("s", f"r{index}", {"sessionId": "s", "requestId": f"r{index}"})
        registry.pop(key)
    assert not registry.hops
    assert len(registry.retired_hops) == min(total, 10)


def test_a_late_event_for_a_finished_request_gets_a_new_hop_id() -> None:
    registry = RequestRegistry()
    first = registry.create("s", "r", {"sessionId": "s", "requestId": "r"})
    registry.pop(first)
    second = registry.create("s", "r", {"sessionId": "s", "requestId": "r"})
    assert first.endswith("hop0") and second.endswith("hop1")


# ----------------------------------------------------------------- start URL


def test_start_url_waits_for_the_first_tab_to_be_instrumented(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    attach_page(capture)
    for message in list(socket.sent):
        if message["method"] in capture._setup_methods():
            capture._handle_command_response({"id": message["id"], "result": {"identifier": "1"}})
    socket.sent.clear()
    assert capture.open_start_url("https://app.example.test/login", timeout=1) is True
    assert socket.sent[-1]["method"] == "Page.navigate"
    assert socket.sent[-1]["sessionId"] == "S1"
    assert socket.sent[-1]["params"] == {"url": "https://app.example.test/login"}


def test_start_url_still_opens_when_setup_never_completes(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    attach_page(capture)
    socket.sent.clear()
    assert capture.open_start_url("https://app.example.test/", timeout=0.1) is False
    assert socket.sent[-1]["method"] == "Page.navigate"


def test_start_url_opens_a_new_tab_when_none_is_attached(tmp_path: Path) -> None:
    capture, _, socket = make_capture(tmp_path)
    assert capture.open_start_url("https://app.example.test/", timeout=0.1) is False
    assert socket.sent[-1]["method"] == "Target.createTarget"
    assert "sessionId" not in socket.sent[-1]
