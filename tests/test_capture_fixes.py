"""Regression tests for capture fixes: paused responses, redirects, streams, failures, crashes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_cdp_capture import FakeStore, make_capture

from chrome_logger.cdp import CDPCapture, PendingCommand


def _recording_send(capture: CDPCapture) -> list[tuple[str, dict[str, Any], str | None]]:
    sent: list[tuple[str, dict[str, Any], str | None]] = []
    next_id = 0

    def send(method, params=None, session_id=None, pending=None):
        nonlocal next_id
        next_id += 1
        sent.append((method, params or {}, session_id))
        if pending:
            capture.pending[next_id] = pending
        return next_id

    capture.send = send  # type: ignore[method-assign]
    return sent


def _start(capture: CDPCapture, request_id: str, resource_type: str = "XHR", url: str = "https://a.test/api") -> None:
    capture._request_will_be_sent(
        "s",
        {
            "requestId": request_id,
            "timestamp": 10.0,
            "wallTime": 1_700_000_000.0,
            "type": resource_type,
            "hasUserGesture": True,
            "request": {"url": url, "method": "GET", "headers": {}},
        },
    )


def _pause(capture: CDPCapture, request_id: str, headers: list[dict[str, str]], status: int = 200) -> None:
    capture._fetch_paused(
        "s",
        {
            "requestId": f"fetch-{request_id}",
            "networkId": request_id,
            "responseStatusCode": status,
            "responseHeaders": headers,
        },
    )


def _flush_deadlines(capture: CDPCapture) -> None:
    for key, (_soft, _hard, reason) in list(capture.finalize_deadlines.items()):
        capture.finalize_deadlines[key] = (0.0, 0.0, reason)
    capture._process_finalize_deadlines()


def _saved(store: FakeStore) -> list[dict[str, Any]]:
    return [payload for path, payload in store.writes if path == "network/requests.jsonl"]


def test_paused_response_is_continued_even_when_storing_its_body_fails(tmp_path: Path) -> None:
    capture, _store = make_capture(tmp_path)
    sent = _recording_send(capture)
    _start(capture, "1", "Document", "https://a.test/")
    _pause(capture, "1", [{"name": "content-type", "value": "text/html"}, {"name": "content-length", "value": "5"}])
    message_id = next(mid for mid, command in capture.pending.items() if command.kind == "fetch_body")

    def broken_store(*_args: Any, **_kwargs: Any) -> None:
        raise RecursionError("too deep")

    capture._store_response_body = broken_store  # type: ignore[method-assign]
    with pytest.raises(RecursionError):
        capture._handle_command_response({"id": message_id, "result": {"body": "x", "base64Encoded": False}})
    assert ("Fetch.continueResponse", {"requestId": "fetch-1"}, "s") in sent
    assert not capture.paused_fetches


def test_one_failing_expired_command_does_not_strand_later_paused_responses(tmp_path: Path) -> None:
    capture, _store = make_capture(tmp_path)
    sent = _recording_send(capture)
    capture.pending[1] = PendingCommand("snapshot_storage", {"group": 1}, 0.0)
    capture.pending[2] = PendingCommand("fetch_body", {"key": "missing", "fetchId": "f2", "sessionId": "s"}, 0.0)
    capture.paused_fetches["f2"] = ("s", "missing")

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("boom")

    capture._handle_snapshot_response = explode  # type: ignore[method-assign]
    capture._process_pending_timeouts()
    assert ("Fetch.continueResponse", {"requestId": "f2"}, "s") in sent
    assert capture.stats["eventErrors"] == 1


def test_redirect_hop_settled_at_shutdown_is_complete(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    _recording_send(capture)
    _start(capture, "1", "Document", "http://a.test/")
    capture._request_will_be_sent(
        "s",
        {
            "requestId": "1",
            "timestamp": 10.1,
            "wallTime": 1_700_000_000.1,
            "type": "Document",
            "redirectHasExtraInfo": True,
            "redirectResponse": {"status": 302, "headers": {"location": "https://a.test/"}},
            "request": {"url": "https://a.test/", "method": "GET", "headers": {}},
        },
    )
    capture.flush_open("keyboardInterrupt")
    hops = {entry["hop"]: entry for entry in _saved(store)}
    assert not hops[0].get("incomplete")
    assert hops[0]["extraInfoIncomplete"] is True
    assert hops[1]["incomplete"] is True
    assert capture.stats["incompleteFlushed"] == 1


@pytest.mark.parametrize(
    ("resource_type", "headers", "streams"),
    [
        ("Fetch", [{"name": "content-type", "value": "text/plain"}], True),
        ("XHR", [{"name": "content-type", "value": "application/json"}], True),
        (
            "Fetch",
            [{"name": "content-type", "value": "text/x-component"}, {"name": "content-length", "value": "9"}],
            True,
        ),
        (
            "Fetch",
            [{"name": "content-type", "value": "application/json"}, {"name": "content-length", "value": "9"}],
            False,
        ),
        ("Document", [{"name": "content-type", "value": "text/html"}], False),
        (
            "Document",
            [
                {"name": "content-disposition", "value": "attachment; filename=x.csv"},
                {"name": "content-length", "value": "9"},
            ],
            True,
        ),
    ],
)
def test_streamed_or_unsized_api_responses_are_not_held_back(
    tmp_path: Path, resource_type: str, headers: list[dict[str, str]], streams: bool
) -> None:
    capture, _store = make_capture(tmp_path)
    sent = _recording_send(capture)
    _start(capture, "1", resource_type)
    _pause(capture, "1", headers)
    continued = ("Fetch.continueResponse", {"requestId": "fetch-1"}, "s") in sent
    assert continued is streams
    assert bool(capture.paused_fetches) is not streams


def test_failed_request_keeps_its_raw_response_headers(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    _recording_send(capture)
    _start(capture, "1")
    capture._response_extra("s", {"requestId": "1", "statusCode": 200, "headers": {"x-reason": "no cors header"}})
    capture._loading_failed(
        "s",
        {"requestId": "1", "timestamp": 10.2, "errorText": "net::ERR_FAILED", "corsErrorStatus": {"corsError": "X"}},
    )
    _flush_deadlines(capture)
    saved = _saved(store)[0]
    assert saved["extraInfo"]["response"]["headers"] == {"x-reason": "no cors header"}
    assert saved["hasUserGesture"] is True


def test_failed_request_accepts_response_headers_that_arrive_after_the_failure(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    _recording_send(capture)
    _start(capture, "1")
    capture._loading_failed("s", {"requestId": "1", "timestamp": 10.2, "errorText": "net::ERR_FAILED"})
    capture._response_extra("s", {"requestId": "1", "statusCode": 403, "headers": {"server": "edge"}})
    _flush_deadlines(capture)
    assert _saved(store)[0]["extraInfo"]["response"]["statusCode"] == 403


def test_fetch_stage_body_failure_recovered_by_fallback_is_not_a_loss(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    _recording_send(capture)
    _start(capture, "1", "Document", "https://a.test/")
    _pause(capture, "1", [{"name": "content-type", "value": "text/html"}, {"name": "content-length", "value": "5"}])
    fetch_id = next(mid for mid, command in capture.pending.items() if command.kind == "fetch_body")
    capture._handle_command_response({"id": fetch_id, "error": {"code": -32000, "message": "gone"}})
    # A paused 200 is not a response that "never had a body".
    entry = next(iter(capture.registry.entries.values()))
    assert "responseBodyUnavailableReason" not in entry
    assert capture.stats["bodyErrors"] == 1

    capture._response_received(
        "s",
        {"requestId": "1", "type": "Document", "hasExtraInfo": False, "response": {"status": 200, "headers": {}}},
    )
    capture._loading_finished("s", {"requestId": "1", "timestamp": 11.0})
    fallback_id = next(mid for mid, command in capture.pending.items() if command.kind == "response_body")
    capture._handle_command_response({"id": fallback_id, "result": {"body": "<p>", "base64Encoded": False}})
    _flush_deadlines(capture)
    saved = _saved(store)[0]
    assert saved["response"]["body"]
    assert capture.stats["bodyErrors"] == 0
    assert capture.stats["bodies"] == 1


def test_body_failure_after_failed_fallback_is_counted_once(tmp_path: Path) -> None:
    capture, _store = make_capture(tmp_path)
    _recording_send(capture)
    _start(capture, "1", "Document", "https://a.test/")
    entry = next(iter(capture.registry.entries.values()))
    entry["response"] = {"status": 200}
    capture._record_body_failure(entry, "fetchResponseBodyError", {"message": "a"})
    capture._record_body_failure(entry, "responseBodyError", {"message": "b"})
    assert capture.stats["bodyErrors"] == 1


def test_renderer_crash_is_recorded_with_a_warning(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.handle(
        {"method": "Target.targetCrashed", "params": {"targetId": "t1", "status": "crashed", "errorCode": 5}}
    )
    crash = next(payload for path, payload in store.writes if path == "browser/targets.jsonl")
    assert crash["event"] == "crashed"
    assert crash["status"] == "crashed"
    assert store.timelines[-1][0] == "target_crashed"
    assert any("renderer crashed" in warning for warning in store.warnings)


def test_spa_route_changes_are_recorded_as_navigations(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.handle(
        {
            "method": "Page.navigatedWithinDocument",
            "sessionId": "s",
            "params": {"frameId": "f", "url": "https://a.test/#/cart", "navigationType": "historyApi"},
        }
    )
    navigation = next(payload for path, payload in store.writes if path == "browser/navigations.jsonl")
    assert navigation["event"] == "navigatedWithinDocument"
    assert store.timelines[-1][1]["event"] == "navigatedWithinDocument"


def test_console_errors_and_exceptions_reach_the_timeline_but_logs_do_not(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture._console_event("s", {"timestamp": 1.0, "type": "log", "args": [{"type": "string", "value": "chatter"}]})
    capture._console_event("s", {"timestamp": 2.0, "type": "error", "args": [{"type": "string", "value": "boom"}]})
    capture._exception_event(
        "s",
        {
            "timestamp": 3.0,
            "exceptionDetails": {"text": "Uncaught", "exception": {"description": "TypeError: x\n at y"}},
        },
    )
    kinds = [(kind, payload.get("text")) for kind, payload in store.timelines]
    assert ("console", "boom") in kinds
    assert ("exception", "TypeError: x at y") in kinds
    assert all(text != "chatter" for _, text in kinds)


def test_user_events_carry_frame_id_and_a_readable_label(tmp_path: Path) -> None:
    capture, store = make_capture(tmp_path)
    capture.interaction_contexts["s"] = {7}
    capture.interaction_context_origins["s"] = {7: {"origin": "https://a.test", "frameId": "frame-1"}}
    capture._user_event(
        "s",
        {
            "executionContextId": 7,
            "payload": '{"event":"click","ts":1700000000000,"target":{"tag":"button","id":"go","text":"Log in"}}',
        },
    )
    path, event = store.writes[-1]
    assert path == "interactions/events.jsonl"
    assert event["frameId"] == "frame-1"
    assert store.timelines[-1][1]["label"] == 'click button#go "Log in"'
