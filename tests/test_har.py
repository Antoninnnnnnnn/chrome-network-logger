from __future__ import annotations

import base64
import gzip
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from chrome_logger import har
from chrome_logger.config import CaptureConfig
from chrome_logger.har import write_har
from chrome_logger.redaction import Redactor
from chrome_logger.storage import CaptureStore

BASE_MS = 1_700_000_000_000
BASE_MONOTONIC = 5_000.0
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x01"
JSON_BODY = '{"items":[1,2,3],"name":"café"}'.encode()
POST_BODY = b'{"name":"new item"}'
LARGE_FRAME = "x" * 70_000

ENTRY_FIELDS = {"pageref", "startedDateTime", "time", "request", "response", "cache", "timings"}
ENTRY_FIELDS |= {"serverIPAddress", "connection", "comment"}
REQUEST_FIELDS = {"method", "url", "httpVersion", "cookies", "headers", "queryString", "headersSize", "bodySize"}
RESPONSE_FIELDS = {"status", "statusText", "httpVersion", "cookies", "headers", "content", "redirectURL"}
RESPONSE_FIELDS |= {"headersSize", "bodySize"}
TIMING_FIELDS = {"blocked", "dns", "connect", "ssl", "send", "wait", "receive", "comment"}


def stamp(offset_ms: float, *, monotonic: bool = True) -> dict[str, Any]:
    epoch_ms = BASE_MS + offset_ms
    result: dict[str, Any] = {
        "epochMs": epoch_ms,
        "iso": datetime.fromtimestamp(epoch_ms / 1000).astimezone().isoformat(timespec="milliseconds"),
    }
    if monotonic:
        result["cdpMonotonicSeconds"] = BASE_MONOTONIC + offset_ms / 1000
    return result


def stored_body(
    session: Path,
    raw: bytes,
    *,
    content_type: str,
    textual: bool,
    **extra: Any,
) -> dict[str, Any]:
    """Write a body file the way CaptureStore.store_body does and return its reference."""
    digest = hashlib.sha256(raw).hexdigest()
    relative = f"network/bodies/{digest}{'.txt.gz' if textual else '.bin'}"
    target = session / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(gzip.compress(raw) if textual else raw)
    reference: dict[str, Any] = {
        "sha256": digest,
        "storedSha256": digest,
        "storedBytes": len(raw),
        "originalBytes": len(raw),
        "processedBytes": len(raw),
        "contentType": content_type,
        "textual": textual,
        "compressed": textual,
        "truncated": False,
        "redacted": False,
        "role": "response",
        "path": relative,
    }
    if textual:
        reference["encoding"] = "utf-8"
    reference.update(extra)
    return reference


def write_lines(path: Path, lines: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join((line if isinstance(line, str) else json.dumps(line, ensure_ascii=False)) + "\n" for line in lines)
    path.write_text(text, encoding="utf-8")


def build_session(session: Path) -> None:
    get_entry = {
        "schemaVersion": 3,
        "id": "root::1::hop0",
        "requestId": "1",
        "hop": 0,
        "sessionId": None,
        "type": "Fetch",
        "isApi": True,
        "started": stamp(100),
        "finished": stamp(210),
        "durationMs": 110,
        "encodedDataLength": 400,
        "initiator": {"type": "script", "url": "https://app.example.test/app.js"},
        "request": {
            "method": "GET",
            "url": "https://api.example.test/items?q=caf%C3%A9&empty=&q=2",
            "headers": {"Accept": "application/json"},
            "initialPriority": "High",
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "protocol": "http/1.1",
            "mimeType": "application/json",
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "remoteIPAddress": "[2001:db8::1]",
            "connectionId": 42,
            "timing": {
                "requestTime": BASE_MONOTONIC + 0.110,
                "proxyStart": -1,
                "proxyEnd": -1,
                "dnsStart": 1,
                "dnsEnd": 5,
                "connectStart": 5,
                "connectEnd": 20,
                "sslStart": 10,
                "sslEnd": 20,
                "sendStart": 21,
                "sendEnd": 22,
                "receiveHeadersEnd": 80,
            },
            "body": stored_body(session, JSON_BODY, content_type="application/json", textual=True),
        },
        "extraInfo": {
            "request": {"headers": {"Accept": "application/json", "Cookie": "sid=abc; theme=dark"}},
            "response": {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Set-Cookie": "sid=new; Path=/; HttpOnly; Expires=Wed, 21 Oct 2026 07:28:00 GMT\n"
                    "theme=light; Secure; SameSite=Lax",
                },
                "headersText": "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n",
            },
        },
    }
    post_entry = {
        "id": "S1::2::hop0",
        "hop": 0,
        "sessionId": "S1",
        "target": {"targetId": "T1", "type": "page"},
        "type": "XHR",
        "isApi": True,
        "started": stamp(0),
        "finished": stamp(40),
        "request": {
            "method": "POST",
            "url": "https://api.example.test/items",
            "headers": {"Content-Type": "application/json"},
            "hasPostData": True,
            "body": stored_body(session, POST_BODY, content_type="application/json", textual=True, role="request"),
        },
        "response": {"status": 201, "statusText": "Created", "protocol": "h2", "headers": {"content-type": "text/x"}},
        "responseBodyError": {"code": -32000, "message": "No resource with given identifier found"},
    }
    redirect_hop = {
        "id": "root::3::hop0",
        "hop": 0,
        "type": "Document",
        "isRedirect": True,
        "redirectTo": "https://example.test/new",
        "responseBodyUnavailableReason": "CDP does not expose redirect response bodies",
        "started": stamp(300),
        "finished": stamp(320),
        "request": {"method": "GET", "url": "https://example.test/old", "headers": {}},
        "response": {"status": 302, "statusText": "Found", "protocol": "http/1.1", "headers": {"Location": "/new"}},
    }
    final_hop = {
        "id": "root::3::hop1",
        "hop": 1,
        "type": "Document",
        "started": stamp(320),
        "finished": stamp(400),
        "request": {"method": "GET", "url": "https://example.test/new", "headers": {}},
        "response": {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": {
                "omitted": True,
                "omittedReason": "sessionBodyLimit",
                "storedBytes": 0,
                "wouldStoreBytes": 2048,
                "originalBytes": 2048,
                "textual": True,
            },
        },
    }
    failed_entry = {
        "id": "root::4::hop0",
        "hop": 0,
        "type": "Fetch",
        "isApi": True,
        "started": stamp(500),
        "finished": stamp(530),
        "request": {"method": "GET", "url": "https://down.example.test/"},
        "failure": {"errorText": "net::ERR_CONNECTION_REFUSED", "canceled": False, "type": "Fetch"},
        "responseBodyUnavailableReason": "the request failed before any response arrived",
    }
    binary_entry = {
        "id": "root::5::hop0",
        "type": "Image",
        "started": stamp(150),
        "finished": stamp(160),
        "request": {"method": "GET", "url": "https://cdn.example.test/logo.png"},
        "response": {
            "status": 200,
            "headers": {"Content-Type": "image/png"},
            "body": stored_body(session, PNG, content_type="image/png", textual=False),
        },
    }
    missing_reference = stored_body(session, b"gone", content_type="text/plain", textual=True)
    (session / missing_reference["path"]).unlink()
    missing_entry = {
        "id": "root::6::hop0",
        "type": "Fetch",
        "started": stamp(600),
        "finished": stamp(610),
        "request": {"method": "GET", "url": "https://api.example.test/missing"},
        "response": {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": missing_reference},
    }
    corrupt_reference = stored_body(
        session, b"hello preview", content_type="text/plain", textual=True, preview="hello preview"
    )
    (session / corrupt_reference["path"]).write_bytes(b"not a gzip stream")
    corrupt_entry = {
        "id": "root::7::hop0",
        "type": "Fetch",
        "started": stamp(650),
        "finished": stamp(655),
        "request": {"method": "GET", "url": "https://api.example.test/corrupt"},
        "response": {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": corrupt_reference},
    }
    unstarted_entry = {
        "id": "root::8::hop0",
        "type": "Other",
        "incomplete": True,
        "incompleteReason": "captureStopped",
        "request": {"method": "GET", "url": "https://late.example.test/"},
    }
    websocket_entry = {
        "schemaVersion": 3,
        "id": "S1::ws1",
        "requestId": "ws1",
        "sessionId": "S1",
        "type": "WebSocket",
        "isApi": True,
        "started": stamp(700),
        "finished": stamp(5700),
        "url": "wss://chat.example.test/socket",
        "request": {"method": "GET", "url": "wss://chat.example.test/socket", "headers": {"Upgrade": "websocket"}},
        "response": {
            "status": 101,
            "statusText": "Switching Protocols",
            "headers": {"Upgrade": "websocket"},
            "headersText": "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        },
        "realtime": {"framesFile": "realtime/websocket_frames.jsonl", "frameCount": 3, "errorCount": 0},
    }
    write_lines(
        session / "network" / "requests.jsonl",
        [
            get_entry,
            post_entry,
            '{"id": "broken", "started": ',
            redirect_hop,
            final_hop,
            failed_entry,
            binary_entry,
            missing_entry,
            corrupt_entry,
            unstarted_entry,
            websocket_entry,
        ],
    )
    large_frame = stored_body(
        session, LARGE_FRAME.encode(), content_type="text/plain", textual=True, role="websocket-frame"
    )
    write_lines(
        session / "realtime" / "websocket_frames.jsonl",
        [
            {"connectionId": "S1::ws1", "direction": "sent", "time": stamp(800), "opcode": 1, "payloadData": "hello"},
            {"connectionId": "other::ws", "direction": "received", "time": stamp(810), "opcode": 1, "payloadData": "x"},
            "{oops",
            {
                "connectionId": "S1::ws1",
                "direction": "received",
                "time": stamp(900),
                "opcode": 2,
                "payloadBase64": base64.b64encode(b"\x00\x01\x02").decode(),
            },
            {
                "connectionId": "S1::ws1",
                "direction": "received",
                "time": stamp(1000),
                "opcode": 1,
                "payload": large_frame,
            },
        ],
    )
    (session / "manifest.json").write_text(json.dumps({"chrome": {"browser": "Chrome/150.0.1234.56"}}))


def assert_fields(value: dict[str, Any], required: set[str], allowed: set[str]) -> None:
    assert required <= set(value), sorted(required - set(value))
    unexpected = [key for key in value if key not in allowed and not key.startswith("_")]
    assert not unexpected, unexpected


def assert_valid_har(document: dict[str, Any]) -> None:
    log = document["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "chrome-network-logger"
    assert isinstance(log["pages"], list)
    assert isinstance(log["comment"], str)
    for entry in log["entries"]:
        assert_fields(entry, {"startedDateTime", "time", "request", "response", "cache", "timings"}, ENTRY_FIELDS)
        datetime.fromisoformat(entry["startedDateTime"].replace("Z", "+00:00"))
        assert entry["cache"] == {}
        request, response = entry["request"], entry["response"]
        assert_fields(request, REQUEST_FIELDS, REQUEST_FIELDS | {"postData", "comment"})
        assert_fields(response, RESPONSE_FIELDS, RESPONSE_FIELDS | {"comment"})
        assert isinstance(request["method"], str) and isinstance(request["url"], str)
        assert isinstance(response["status"], int) and isinstance(response["httpVersion"], str)
        for item in request["headers"] + response["headers"] + request["queryString"]:
            assert set(item) == {"name", "value"}
            assert isinstance(item["name"], str) and isinstance(item["value"], str)
        assert all("\n" not in header["value"] for header in request["headers"] + response["headers"])
        for cookie in request["cookies"] + response["cookies"]:
            assert isinstance(cookie["name"], str) and isinstance(cookie["value"], str)
        if "postData" in request:
            assert_fields(request["postData"], {"mimeType"}, {"mimeType", "params", "text", "comment"})
        content = response["content"]
        assert_fields(content, {"size", "mimeType"}, {"size", "compression", "mimeType", "text", "encoding", "comment"})
        assert isinstance(content["size"], int) and isinstance(content["mimeType"], str)
        assert isinstance(request["bodySize"], int) and isinstance(response["bodySize"], int)
        timings = entry["timings"]
        assert_fields(timings, {"send", "wait", "receive"}, TIMING_FIELDS)
        assert all(timings[phase] >= 0 for phase in ("send", "wait", "receive"))
        assert all(timings[phase] == -1 or timings[phase] >= 0 for phase in ("blocked", "dns", "connect", "ssl"))
        phases = ("blocked", "dns", "connect", "send", "wait", "receive")
        assert entry["time"] == pytest.approx(sum(max(0, timings[phase]) for phase in phases), abs=0.01)


@pytest.fixture
def exported(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    session = tmp_path / "session"
    build_session(session)
    path = write_har(session, creator_version="9.9.9")
    assert path == session / "reports" / "session.har"
    assert not (session / "reports" / "session.har.tmp").exists()
    return session, json.loads(path.read_text(encoding="utf-8"))


def by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["_id"]: entry for entry in document["log"]["entries"]}


def test_export_is_structurally_valid_and_sorted_by_start_time(exported) -> None:
    _, document = exported
    assert_valid_har(document)
    log = document["log"]
    assert log["creator"] == {"name": "chrome-network-logger", "version": "9.9.9"}
    assert log["browser"] == {"name": "Chrome", "version": "150.0.1234.56"}
    assert [entry["_id"] for entry in log["entries"]] == [
        "S1::2::hop0",
        "root::1::hop0",
        "root::5::hop0",
        "root::3::hop0",
        "root::3::hop1",
        "root::4::hop0",
        "root::6::hop0",
        "root::7::hop0",
        "S1::ws1",
        "root::8::hop0",  # no start time: last
    ]
    starts = [entry["startedDateTime"] for entry in log["entries"][:-1]]
    assert starts == sorted(starts)
    assert starts[0] == "2023-11-14T22:13:20.000Z"
    export = log["_export"]
    assert export["entries"] == 10
    assert export["skippedLines"] == 1
    assert export["skipped"][0]["line"] == 3
    assert "invalid JSON" in export["skipped"][0]["reason"]


def test_http_entry_keeps_headers_cookies_query_body_and_timings(exported) -> None:
    _, document = exported
    entry = by_id(document)["root::1::hop0"]
    request, response = entry["request"], entry["response"]

    assert request["httpVersion"] == response["httpVersion"] == "HTTP/1.1"
    assert {"name": "Cookie", "value": "sid=abc; theme=dark"} in request["headers"]  # raw ExtraInfo headers win
    assert request["cookies"] == [{"name": "sid", "value": "abc"}, {"name": "theme", "value": "dark"}]
    assert request["queryString"] == [
        {"name": "q", "value": "café"},
        {"name": "empty", "value": ""},
        {"name": "q", "value": "2"},
    ]
    set_cookies = [header["value"] for header in response["headers"] if header["name"] == "Set-Cookie"]
    assert set_cookies == [
        "sid=new; Path=/; HttpOnly; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        "theme=light; Secure; SameSite=Lax",
    ]
    assert response["cookies"] == [
        {
            "name": "sid",
            "value": "new",
            "httpOnly": True,
            "secure": False,
            "path": "/",
            "expires": "2026-10-21T07:28:00.000Z",
        },
        {"name": "theme", "value": "light", "httpOnly": False, "secure": True, "sameSite": "Lax"},
    ]
    headers_size = len("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n")
    assert response["headersSize"] == headers_size
    assert response["bodySize"] == 400 - headers_size
    assert response["_transferSize"] == 400
    assert response["content"]["text"] == JSON_BODY.decode()
    assert response["content"]["size"] == len(JSON_BODY)
    assert response["content"]["mimeType"] == "application/json; charset=utf-8"
    assert "encoding" not in response["content"]
    assert response["content"]["_bodyPath"].startswith("network/bodies/")

    timings = entry["timings"]
    assert timings["blocked"] == pytest.approx(11)  # 10 ms queued + 1 ms before DNS
    assert timings["dns"] == pytest.approx(4)
    assert timings["connect"] == pytest.approx(15)
    assert timings["ssl"] == pytest.approx(10)
    assert timings["send"] == pytest.approx(2)
    assert timings["wait"] == pytest.approx(58)
    assert timings["receive"] == pytest.approx(20)
    assert entry["time"] == pytest.approx(110)
    assert entry["serverIPAddress"] == "2001:db8::1"
    assert entry["connection"] == "42"
    assert entry["_resourceType"] == "fetch"
    assert entry["_isApi"] is True
    assert entry["_priority"] == "High"
    assert entry["_initiator"]["type"] == "script"
    assert entry["_hop"] == 0


def test_request_bodies_binary_bodies_and_body_problems_are_explained(exported) -> None:
    _, document = exported
    entries = by_id(document)

    post = entries["S1::2::hop0"]
    assert post["request"]["postData"]["mimeType"] == "application/json"
    assert post["request"]["postData"]["text"] == POST_BODY.decode()
    assert post["request"]["bodySize"] == len(POST_BODY)
    assert post["response"]["httpVersion"] == "HTTP/2.0"
    assert post["response"]["content"]["size"] == -1
    assert "could not be retrieved" in post["response"]["content"]["comment"]
    assert post["_responseBodyError"]["code"] == -32000
    assert post["_sessionId"] == "S1" and post["_target"]["targetId"] == "T1"
    assert post["timings"]["wait"] == pytest.approx(40)  # no ResourceTiming: the duration is wait
    assert "comment" in post["timings"]

    binary = entries["root::5::hop0"]["response"]["content"]
    assert binary["encoding"] == "base64"
    assert base64.b64decode(binary["text"]) == PNG
    assert binary["size"] == len(PNG)

    missing = entries["root::6::hop0"]["response"]["content"]
    assert "text" not in missing
    assert "missing" in missing["comment"]
    assert missing["_bodyPath"].startswith("network/bodies/")

    corrupt = entries["root::7::hop0"]["response"]["content"]
    assert "could not be read" in corrupt["comment"]
    assert corrupt["text"] == "hello preview"  # recovered from the record's preview

    omitted = entries["root::3::hop1"]["response"]["content"]
    assert "text" not in omitted
    assert "sessionBodyLimit" in omitted["comment"]
    assert omitted["size"] == 2048

    unstarted = entries["root::8::hop0"]
    assert unstarted["_incomplete"] is True and unstarted["_incompleteReason"] == "captureStopped"
    assert "placeholder" in unstarted["comment"]
    assert unstarted["response"]["status"] == 0


def test_redirect_hops_and_failures_are_preserved(exported) -> None:
    _, document = exported
    entries = by_id(document)

    hop = entries["root::3::hop0"]
    assert hop["response"]["status"] == 302
    assert hop["response"]["redirectURL"] == "/new"
    assert hop["response"]["content"]["size"] == 0
    assert hop["_responseBodyUnavailableReason"] == "CDP does not expose redirect response bodies"
    assert "https://example.test/new" in hop["comment"]
    assert entries["root::3::hop1"]["_hop"] == 1

    failed = entries["root::4::hop0"]
    assert failed["response"]["status"] == 0
    assert failed["response"]["_error"] == "net::ERR_CONNECTION_REFUSED"
    assert failed["_failure"]["errorText"] == "net::ERR_CONNECTION_REFUSED"
    assert "ERR_CONNECTION_REFUSED" in failed["comment"]
    assert failed["timings"]["blocked"] == pytest.approx(30)
    assert failed["time"] == pytest.approx(30)


def test_websocket_frames_become_chrome_websocket_messages(exported) -> None:
    _, document = exported
    entry = by_id(document)["S1::ws1"]
    assert entry["_resourceType"] == "websocket"
    assert entry["response"]["status"] == 101
    assert entry["response"]["httpVersion"] == "HTTP/1.1"
    assert entry["timings"]["receive"] == pytest.approx(5000)
    assert entry["_realtime"]["frameCount"] == 3
    messages = entry["_webSocketMessages"]
    assert [message["type"] for message in messages] == ["send", "receive", "receive"]
    assert [message["opcode"] for message in messages] == [1, 2, 1]
    assert messages[0]["data"] == "hello"
    assert messages[0]["time"] == pytest.approx((BASE_MS + 800) / 1000)
    assert base64.b64decode(messages[1]["data"]) == b"\x00\x01\x02"
    assert messages[2]["data"] == LARGE_FRAME
    assert document["log"]["_export"]["webSocketFramesWithoutEntry"] == 1
    assert document["log"]["_export"]["webSocketFramesSkipped"] == 1


def test_large_bodies_and_extra_websocket_frames_are_left_out_with_a_reason(tmp_path: Path, monkeypatch) -> None:
    session = tmp_path / "session"
    build_session(session)
    monkeypatch.setattr(har, "MAX_WEBSOCKET_MESSAGES", 2)

    document = json.loads(write_har(session, creator_version="1", max_inline_body_bytes=20).read_text("utf-8"))

    assert_valid_har(document)
    entries = by_id(document)
    content = entries["root::1::hop0"]["response"]["content"]
    assert len(JSON_BODY) > 20 >= len(PNG)
    assert "text" not in content
    assert "20-byte HAR inline limit" in content["comment"]
    assert content["size"] == len(JSON_BODY)
    assert content["_bodyPath"].startswith("network/bodies/")
    assert base64.b64decode(entries["root::5::hop0"]["response"]["content"]["text"]) == PNG
    websocket = entries["S1::ws1"]
    assert len(websocket["_webSocketMessages"]) == 2
    assert "first 2 of 3 frames" in websocket["comment"]
    assert document["log"]["_export"]["maxInlineBodyBytes"] == 20


def test_missing_requests_file_returns_none(tmp_path: Path) -> None:
    assert write_har(tmp_path, creator_version="1") is None
    assert not (tmp_path / "reports").exists()
    with pytest.raises(ValueError, match="max_inline_body_bytes"):
        write_har(tmp_path, creator_version="1", max_inline_body_bytes=-1)


def test_body_paths_cannot_escape_the_session_directory(tmp_path: Path) -> None:
    session = tmp_path / "session"
    (tmp_path / "secret.txt").write_text("top secret")
    reference = {"path": "../secret.txt", "storedBytes": 10, "textual": True, "compressed": False}
    write_lines(
        session / "network" / "requests.jsonl",
        [
            {
                "id": "a",
                "started": stamp(0),
                "request": {"url": "https://x.test/"},
                "response": {"status": 200, "body": reference},
            }
        ],
    )

    document = json.loads(write_har(session, creator_version="1").read_text("utf-8"))

    content = document["log"]["entries"][0]["response"]["content"]
    assert "text" not in content
    assert "outside the session directory" in content["comment"]


def test_hostile_or_odd_records_still_produce_valid_json(tmp_path: Path) -> None:
    session = tmp_path / "session"
    write_lines(
        session / "network" / "requests.jsonl",
        [
            "[1, 2]",
            '{"id": "surrogate", "request": {"method": "GET", "url": "https://x.test/\\ud800"}, '
            '"started": {"epochMs": NaN}}',
            {
                "id": "odd",
                "type": 5,
                "started": {"epochMs": 1e300},
                "request": "oops",
                "response": {"status": "200", "headers": ["x"], "timing": {"requestTime": "soon"}, "body": 7},
                "failure": "boom",
            },
            {"id": "plain", "started": stamp(0), "request": {"url": "https://x.test/"}, "response": {"status": 204}},
        ],
    )

    text = write_har(session, creator_version="1").read_text("utf-8")
    document = json.loads(text)

    assert_valid_har(document)
    entries = document["log"]["entries"]
    assert [entry["_id"] for entry in entries] == ["plain", "odd", "surrogate"]  # no start time sorts last
    assert entries[1]["startedDateTime"] == "1970-01-01T00:00:00.000Z"  # 1e300 ms is not a representable date
    assert "placeholder" in entries[1]["comment"]
    assert entries[2]["request"]["url"] == "https://x.test/\ud800"
    assert document["log"]["_export"]["skippedLines"] == 1
    assert document["log"]["_export"]["skipped"] == [{"line": 1, "reason": "not a JSON object"}]


def test_bodies_written_by_the_capture_store_are_read_back(tmp_path: Path) -> None:
    store = CaptureStore(CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile"), Redactor("raw"))
    text_reference = store.store_body('{"ok": true, "word": "naïve"}', content_type="application/json")
    binary_reference = store.store_body(
        base64.b64encode(b"\x00\xff\x10binary").decode(),
        base64_encoded=True,
        content_type="application/octet-stream",
    )
    for index, reference in enumerate((text_reference, binary_reference)):
        store.write_jsonl(
            "network/requests.jsonl",
            {
                "id": f"root::{index}::hop0",
                "started": stamp(index),
                "request": {"method": "GET", "url": f"https://x.test/{index}"},
                "response": {"status": 200, "body": reference},
            },
        )
    store.close()

    document = json.loads(write_har(store.base, creator_version="1").read_text("utf-8"))

    assert_valid_har(document)
    text_content, binary_content = (entry["response"]["content"] for entry in document["log"]["entries"])
    assert text_content["text"] == '{"ok": true, "word": "naïve"}'
    assert "encoding" not in text_content
    assert binary_content["encoding"] == "base64"
    assert base64.b64decode(binary_content["text"]) == b"\x00\xff\x10binary"
