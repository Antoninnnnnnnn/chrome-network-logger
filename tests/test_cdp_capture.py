from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from chrome_logger.cdp import CDPCapture, PendingCommand
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor


class FakeStore:
    def __init__(self) -> None:
        self.redactor = Redactor("safe")
        self.writes: list[tuple[str, dict[str, Any]]] = []
        self.timelines: list[tuple[str, dict[str, Any]]] = []
        self.bodies: list[dict[str, Any]] = []
        self.warnings: list[str] = []

    def write_jsonl(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        clean = self.redactor.object(payload) if redact else payload
        self.writes.append((path, clean))

    def write_json(self, path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        self.write_jsonl(path, payload, redact=redact)

    def timeline(self, kind: str, timestamp: dict[str, Any], **payload: Any) -> None:
        self.timelines.append((kind, {"time": timestamp, **payload}))

    def store_body(self, body: Any, **options: Any) -> dict[str, Any]:
        record = {"body": body, **options}
        self.bodies.append(record)
        return {"path": f"network/bodies/{len(self.bodies)}.bin", "role": options.get("role")}

    def set_manifest(self, **_fields: Any) -> None:
        pass

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    def check_health(self) -> None:
        return None


def make_capture(tmp_path: Path, *, body_mode: str = "api") -> tuple[CDPCapture, FakeStore]:
    store = FakeStore()
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile", body_mode=body_mode)
    return CDPCapture(9222, config, store), store


def test_runtime_and_log_timestamps_use_epoch_milliseconds(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture._console_event("s", {"timestamp": 1_700_000_000_123, "type": "log", "args": []})
    capture._exception_event("s", {"timestamp": 1_700_000_000_456, "exceptionDetails": {}})
    capture._log_entry("s", {"entry": {"timestamp": 1_700_000_000_789, "text": "x"}})

    values = {path: payload["time"]["epochMs"] for path, payload in store.writes}
    assert values["browser/console.jsonl"] == 1_700_000_000_123
    assert values["browser/exceptions.jsonl"] == 1_700_000_000_456
    assert values["browser/log.jsonl"] == 1_700_000_000_789


def test_websocket_text_is_redacted_and_control_payload_is_base64(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    key = capture._websocket_key("s", "1")
    capture.open_websockets[key] = {"sessionId": "s", "frameCount": 0}

    capture._websocket_frame(
        "s",
        "Network.webSocketFrameReceived",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "response": {"opcode": 1, "payloadData": '{"token":"secret","message":"ok"}'},
        },
    )
    text_event = store.writes[-1][1]
    assert "secret" not in text_event["payloadData"]
    assert "ok" in text_event["payloadData"]

    capture._websocket_frame(
        "s",
        "Network.webSocketFrameReceived",
        {
            "requestId": "1",
            "timestamp": 11.0,
            "response": {"opcode": 9, "payloadData": base64.b64encode(b"ping").decode()},
        },
    )
    assert store.bodies[-1]["base64_encoded"] is True
    assert store.bodies[-1]["role"] == "websocket-frame"


def test_sse_json_payload_is_redacted(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture._sse_message(
        "s",
        {"requestId": "1", "timestamp": 10.0, "eventName": "message", "data": '{"token":"secret"}'},
    )
    assert "secret" not in store.writes[-1][1]["data"]


def test_post_data_entries_are_externalized(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "Fetch",
            "request": {
                "url": "https://example.test/upload",
                "method": "POST",
                "headers": {"content-type": "multipart/form-data"},
                "postDataEntries": [{"bytes": base64.b64encode(b"file-bytes").decode()}],
            },
        },
    )
    _, entry = capture.registry.current("s", "1")
    assert entry is not None
    part = entry["request"]["postDataEntries"][0]
    assert "bytes" not in part
    assert part["body"]["role"] == "request-part-0"
    assert store.bodies[-1]["base64_encoded"] is True


def test_finalize_waits_for_pending_body_command(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    key = capture.registry.create(
        "s",
        "1",
        {
            "sessionId": "s",
            "requestId": "1",
            "started": capture.timestamps.normalize(),
            "request": {"method": "GET", "url": "https://example.test"},
            "response": {"status": 200},
            "_pendingResponseBody": True,
        },
    )
    capture.finalize_deadlines[key] = (0.0, 0.0, "loadingFinished")
    capture._process_finalize_deadlines()
    assert key in capture.registry.entries

    capture.registry.entries[key]["_pendingResponseBody"] = False
    capture.finalize_deadlines[key] = (0.0, 0.0, "loadingFinished")
    capture._process_finalize_deadlines()
    assert key not in capture.registry.entries
    assert any(path == "network/requests.jsonl" for path, _ in store.writes)


def test_missing_expected_extra_info_is_explicit(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    key = capture.registry.create(
        "s",
        "1",
        {
            "sessionId": "s",
            "requestId": "1",
            "started": capture.timestamps.normalize(),
            "request": {"method": "GET", "url": "https://example.test"},
            "response": {"status": 200},
        },
    )
    capture.registry.set_response_extra_expected(key, True)
    capture.finalize_deadlines[key] = (0.0, 0.0, "loadingFinished")
    capture._process_finalize_deadlines()
    written = next(payload for path, payload in store.writes if path == "network/requests.jsonl")
    assert written["extraInfoIncomplete"] is True


def test_attach_timeout_releases_guard_and_schedules_retry(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.attached_targets.add("target-1")
    capture.attach_attempts["target-1"] = 1
    capture.pending[1] = PendingCommand(
        "attach_target",
        {"targetId": "target-1"},
        time.monotonic() - 20,
    )
    capture._process_pending_timeouts()
    assert "target-1" not in capture.attached_targets
    assert "target-1" in capture.discovered_targets
    assert any(path == "browser/protocol_errors.jsonl" for path, _ in store.writes)


def test_body_mode_none_drops_inline_request_bodies_and_skips_post_data_lookup(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path, body_mode="none")
    sent: list[tuple[str, dict[str, Any]]] = []
    capture.send = lambda method, params=None, session_id=None, pending=None: sent.append((method, params or {})) or 1  # type: ignore[method-assign]
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "Fetch",
            "request": {
                "url": "https://example.test/api",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "postData": '{"password":"secret"}',
                "hasPostData": True,
            },
        },
    )
    _, entry = capture.registry.current("s", "1")
    assert entry is not None
    assert "postData" not in entry["request"]
    assert "body" not in entry["request"]
    assert store.bodies == []
    assert not any(method == "Network.getRequestPostData" for method, _ in sent)


def test_response_received_preserves_body_captured_earlier_by_fetch(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "Document",
            "request": {"url": "https://example.test", "method": "GET", "headers": {}},
        },
    )
    _, entry = capture.registry.current("s", "1")
    assert entry is not None
    entry["response"] = {"body": {"path": "network/bodies/1.html.gz"}}
    capture._response_received(
        "s",
        {"requestId": "1", "type": "Document", "hasExtraInfo": False, "response": {"status": 200}},
    )
    assert entry["response"]["status"] == 200
    assert entry["response"]["body"]["path"] == "network/bodies/1.html.gz"


def test_response_extra_preserves_raw_headers_text(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "Fetch",
            "request": {"url": "https://example.test", "method": "GET", "headers": {}},
        },
    )
    key, entry = capture.registry.current("s", "1")
    assert key is not None and entry is not None
    capture.registry.set_response_extra_expected(key, True)
    capture._response_extra(
        "s",
        {"requestId": "1", "statusCode": 200, "headers": {}, "headersText": "HTTP/1.1 200 OK\r\nX-Test: yes\r\n"},
    )
    assert entry["extraInfo"]["response"]["headersText"].startswith("HTTP/1.1 200")


def test_interaction_script_identifier_is_retained_for_teardown(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture.pending[7] = PendingCommand(
        "interaction_script",
        {"sessionId": "page-session"},
        time.monotonic(),
    )
    capture._handle_command_response({"id": 7, "result": {"identifier": "script-123"}})
    assert capture.interaction_script_ids["page-session"] == "script-123"


def test_quiesce_waits_for_commands_and_removes_registered_script(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture.targets["page-session"] = {"targetId": "target-1", "type": "page", "url": "https://example.test"}
    capture.interaction_script_ids["page-session"] = "script-123"
    capture.paused_fetches["fetch-1"] = ("page-session", "page-session::1::hop0")
    sent: list[tuple[str, dict[str, Any], str | None]] = []
    next_id = 0

    def immediate_send(method, params=None, session_id=None, pending=None):
        nonlocal next_id
        next_id += 1
        sent.append((method, params or {}, session_id))
        if pending:
            capture.pending[next_id] = pending
            capture._handle_command_response({"id": next_id, "result": {}})
        return next_id

    capture.send = immediate_send  # type: ignore[method-assign]
    assert capture.quiesce(0.2) is True
    assert capture._quiesce_pending == 0
    assert ("Fetch.continueResponse", {"requestId": "fetch-1"}, "page-session") in sent
    assert (
        "Page.removeScriptToEvaluateOnNewDocument",
        {"identifier": "script-123"},
        "page-session",
    ) in sent
    assert any(method == "Runtime.removeBinding" for method, _, _ in sent)


def test_body_mode_none_omits_websocket_and_sse_payloads(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path, body_mode="none")
    key = capture._websocket_key("s", "1")
    capture.open_websockets[key] = {"sessionId": "s", "frameCount": 0}
    capture._websocket_frame(
        "s",
        "Network.webSocketFrameReceived",
        {"requestId": "1", "timestamp": 10.0, "response": {"opcode": 1, "payloadData": "secret-message"}},
    )
    ws_event = store.writes[-1][1]
    assert ws_event["payloadOmitted"] is True
    assert "payloadData" not in ws_event
    assert "secret-message" not in str(ws_event)

    capture._sse_message(
        "s",
        {"requestId": "2", "timestamp": 11.0, "eventName": "message", "data": "secret-sse"},
    )
    sse_event = store.writes[-1][1]
    assert sse_event["dataOmitted"] is True
    assert "data" not in sse_event
    assert "secret-sse" not in str(sse_event)
    assert store.bodies == []


def test_realtime_payload_respects_smaller_max_body_limit(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.config.max_body_bytes = 4
    key = capture._websocket_key("s", "1")
    capture.open_websockets[key] = {"sessionId": "s", "frameCount": 0}
    capture._websocket_frame(
        "s",
        "Network.webSocketFrameReceived",
        {"requestId": "1", "timestamp": 10.0, "response": {"opcode": 1, "payloadData": "abcdefgh"}},
    )
    assert store.writes[-1][1]["payload"]["role"] == "websocket-frame"
    assert store.bodies[-1]["body"] == "abcdefgh"
    capture._sse_message(
        "s",
        {"requestId": "2", "timestamp": 11.0, "eventName": "message", "data": "abcdefgh"},
    )
    assert store.writes[-1][1]["dataBody"]["role"] == "sse-message"


def test_interaction_binding_accepts_only_the_isolated_world_and_limits_payloads(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.interaction_contexts["s"] = {7}
    payload = '{"event":"click","ts":1700000000000}'

    capture._user_event("s", {"executionContextId": 8, "payload": payload})
    assert capture.stats["droppedUserEvents"] == 1
    assert not store.writes

    capture._user_event("s", {"executionContextId": 7, "payload": payload})
    assert store.writes[-1][0] == "interactions/events.jsonl"

    capture.config.max_interaction_payload_bytes = 10
    capture._user_event("s", {"executionContextId": 7, "payload": payload})
    assert capture.stats["droppedUserEvents"] == 2
    assert store.warnings


def test_required_cdp_command_failure_marks_capture_unhealthy(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.enabled_sessions.add("s")
    capture.pending[1] = PendingCommand(
        "required_command",
        {"method": "Network.enable", "sessionId": "s"},
        time.monotonic(),
    )
    capture._handle_command_response({"id": 1, "error": {"code": -1, "message": "unsupported"}})
    assert capture.failure.is_set()
    assert capture.stats["protocolErrors"] == 1
    assert any("Required CDP command failed" in warning for warning in store.warnings)


def test_required_command_failure_on_detached_session_is_not_fatal(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.enabled_sessions.add("s")
    capture.pending[1] = PendingCommand(
        "required_command",
        {"method": "Network.enable", "sessionId": "s"},
        time.monotonic(),
    )
    capture._handle_command_response(
        {"id": 1, "error": {"code": -32001, "message": "Session with given id not found."}}
    )
    assert not capture.failure.is_set()
    assert capture.stats["detachedSessionCommands"] == 1
    assert not store.warnings
    entry = next(payload for path, payload in store.writes if path == "browser/protocol_errors.jsonl")
    assert entry["sessionDetached"] is True


def test_required_command_timeout_on_gone_session_is_not_fatal(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture.pending[1] = PendingCommand(
        "required_command",
        {"method": "Page.enable", "sessionId": "gone"},
        time.monotonic() - 60,
    )
    capture._process_pending_timeouts()
    assert not capture.failure.is_set()
    assert capture.stats["detachedSessionCommands"] == 1


def test_required_browser_command_timeout_is_fatal(tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)
    capture.pending[1] = PendingCommand(
        "required_command",
        {"method": "Target.setAutoAttach", "sessionId": None},
        time.monotonic() - 60,
    )
    capture._process_pending_timeouts()
    assert capture.failure.is_set()
    assert isinstance(capture.fatal_error, TimeoutError)


def test_connect_rejects_non_loopback_debugger_url(monkeypatch, tmp_path: Path) -> None:
    capture, _ = make_capture(tmp_path)

    def fake_fetch_json(_port: int, path: str):
        if path == "/json/version":
            return {"webSocketDebuggerUrl": "ws://attacker.example/devtools/browser/1"}
        return []

    monkeypatch.setattr("chrome_logger.cdp.fetch_json", fake_fetch_json)
    assert capture.connect() is False
    assert capture.ws is None


def test_page_session_enables_required_domains_and_isolated_world(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    sent: list[tuple[str, dict[str, Any], str | None, PendingCommand | None]] = []

    def record_send(method, params=None, session_id=None, pending=None):
        sent.append((method, params or {}, session_id, pending))
        return len(sent)

    capture.send = record_send  # type: ignore[method-assign]
    target = {"targetId": "target-1", "type": "page", "url": "https://example.test", "title": "Test"}
    capture._enable_session("session-1", target)

    methods = {method for method, _, _, _ in sent}
    assert {"Network.enable", "Runtime.enable", "Page.enable", "Fetch.enable"} <= methods
    required = {
        pending.data["method"]
        for _, _, _, pending in sent
        if pending is not None and pending.kind == "required_command"
    }
    assert {"Network.enable", "Runtime.enable", "Page.enable", "Fetch.enable", "Target.setAutoAttach"} <= required
    binding = next(item for item in sent if item[0] == "Runtime.addBinding")
    script = next(item for item in sent if item[0] == "Page.addScriptToEvaluateOnNewDocument")
    assert binding[1]["executionContextName"] == capture.world_name
    assert script[1]["worldName"] == capture.world_name
    assert script[1]["runImmediately"] is True
    assert capture.target_sessions["target-1"] == "session-1"
    assert any(path == "browser/targets.jsonl" for path, _ in store.writes)


def test_browser_storage_snapshot_lifecycle(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.targets["page"] = {"targetId": "target-1", "type": "page", "url": "https://example.test"}
    next_id = 0

    def pending_send(_method, _params=None, _session_id=None, pending=None):
        nonlocal next_id
        next_id += 1
        if pending:
            capture.pending[next_id] = pending
        return next_id

    capture.send = pending_send  # type: ignore[method-assign]
    capture.snapshot("start")
    assert capture._snapshot_pending == 2
    commands = {command.kind: message_id for message_id, command in capture.pending.items()}
    capture._handle_command_response(
        {"id": commands["snapshot_cookies"], "result": {"cookies": [{"name": "sid", "value": "secret"}]}}
    )
    capture._handle_command_response(
        {
            "id": commands["snapshot_storage"],
            "result": {"result": {"value": {"localStorage": {"ok": True, "values": {"token": "secret"}}}}},
        }
    )
    assert capture.wait_for_snapshots(0.01) is True
    assert any(path == "snapshots/cookies_start.json" for path, _ in store.writes)
    assert any(path == "snapshots/storage_start.jsonl" for path, _ in store.writes)
    assert "secret" not in str(store.writes)


def test_network_request_response_and_body_command_lifecycle(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    next_id = 0

    def pending_send(_method, _params=None, _session_id=None, pending=None):
        nonlocal next_id
        next_id += 1
        if pending:
            capture.pending[next_id] = pending
        return next_id

    capture.send = pending_send  # type: ignore[method-assign]
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "XHR",
            "request": {"url": "https://example.test/api", "method": "GET", "headers": {}},
        },
    )
    capture._request_extra("s", {"requestId": "1", "headers": {"Authorization": "Bearer secret"}})
    capture._response_received(
        "s",
        {
            "requestId": "1",
            "type": "XHR",
            "hasExtraInfo": False,
            "response": {"status": 200, "headers": {"content-type": "application/json"}},
        },
    )
    capture._response_early_hints("s", {"requestId": "1", "timestamp": 10.1, "headers": {"link": "x"}})
    capture._served_from_cache("s", {"requestId": "1"})
    capture._loading_finished("s", {"requestId": "1", "timestamp": 11.0, "encodedDataLength": 20})
    body_message_id = next(
        message_id for message_id, command in capture.pending.items() if command.kind == "response_body"
    )
    capture._handle_command_response(
        {"id": body_message_id, "result": {"body": '{"token":"secret","ok":true}', "base64Encoded": False}}
    )
    for key, (_, hard, reason) in list(capture.finalize_deadlines.items()):
        capture.finalize_deadlines[key] = (0.0, hard, reason)
    capture._process_finalize_deadlines()
    saved = next(payload for path, payload in store.writes if path == "network/requests.jsonl")
    assert saved["servedFromCache"] is True
    assert saved["response"]["body"]["role"] == "response"
    assert "secret" not in str(saved)
    assert capture.stats["bodies"] == 1


def test_fetch_response_body_and_continue_lifecycle(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    next_id = 0
    sent: list[tuple[str, dict[str, Any], str | None]] = []

    def pending_send(method, params=None, session_id=None, pending=None):
        nonlocal next_id
        next_id += 1
        sent.append((method, params or {}, session_id))
        if pending:
            capture.pending[next_id] = pending
        return next_id

    capture.send = pending_send  # type: ignore[method-assign]
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "network-1",
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": "Document",
            "request": {"url": "https://example.test", "method": "GET", "headers": {}},
        },
    )
    capture._response_received(
        "s",
        {
            "requestId": "network-1",
            "type": "Document",
            "hasExtraInfo": False,
            "response": {"status": 200, "headers": {}},
        },
    )
    capture._fetch_paused(
        "s",
        {
            "requestId": "fetch-1",
            "networkId": "network-1",
            "responseStatusCode": 200,
            "responseHeaders": [{"name": "content-type", "value": "text/html"}],
        },
    )
    body_message_id = next(
        message_id for message_id, command in capture.pending.items() if command.kind == "fetch_body"
    )
    capture._handle_command_response(
        {"id": body_message_id, "result": {"body": "<html>ok</html>", "base64Encoded": False}}
    )
    assert ("Fetch.continueResponse", {"requestId": "fetch-1"}, "s") in sent
    assert store.bodies[-1]["content_type"] == "text/html"
    assert not capture.paused_fetches


def test_websocket_and_webtransport_lifecycles(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.targets["s"] = {"targetId": "target-1", "type": "page", "url": "https://example.test"}
    capture._websocket_created(
        "s", {"requestId": "ws-1", "url": "wss://example.test/socket", "timestamp": 10.0, "initiator": {}}
    )
    capture._websocket_handshake_request("s", {"requestId": "ws-1", "request": {"headers": {"x": "1"}}})
    capture._websocket_handshake_response("s", {"requestId": "ws-1", "response": {"status": 101, "headers": {}}})
    capture._websocket_error("s", {"requestId": "ws-1", "timestamp": 10.5, "errorMessage": "synthetic"})
    capture._websocket_closed("s", {"requestId": "ws-1", "timestamp": 11.0})
    assert not capture.open_websockets
    assert any(path == "realtime/websocket_connections.jsonl" for path, _ in store.writes)
    assert any(path == "network/requests.jsonl" for path, _ in store.writes)

    capture._webtransport_created(
        "s", {"transportId": "wt-1", "url": "https://example.test/transport", "timestamp": 12.0}
    )
    capture._webtransport_established("s", {"transportId": "wt-1", "timestamp": 12.5})
    capture._webtransport_closed("s", {"transportId": "wt-1", "timestamp": 13.0})
    assert not capture.webtransports
    assert any(path == "realtime/webtransport.jsonl" for path, _ in store.writes)
    assert capture.stats["webTransports"] == 1
