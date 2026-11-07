"""The files an analyst (often an AI agent) reads first: timeline order, summary, overview, INDEX."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from chrome_logger.config import CaptureConfig
from chrome_logger.labels import element_label, interaction_label
from chrome_logger.overview import build_overview, normalize_path
from chrome_logger.redaction import Redactor
from chrome_logger.session_index import render_session_index
from chrome_logger.storage import CaptureStore, sort_jsonl_by_time

BASE_MS = 1_700_000_000_000


def _time(offset_ms: float) -> dict[str, Any]:
    return {"epochMs": BASE_MS + offset_ms, "iso": f"2023-11-14T22:13:{20 + offset_ms / 1000:06.3f}+00:00"}


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def _request(
    request_id: str,
    offset_ms: float,
    url: str,
    *,
    method: str = "GET",
    resource_type: str = "Fetch",
    status: int | None = 200,
    failure: dict[str, Any] | None = None,
    session: str = "S1",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": f"{session}::{request_id}::hop0",
        "sessionId": session,
        "type": resource_type,
        "started": _time(offset_ms),
        "durationMs": 12,
        "request": {"method": method, "url": url},
        "isApi": resource_type in {"Fetch", "XHR", "Document"},
    }
    if status is not None:
        record["response"] = {"status": status}
    if failure:
        record["failure"] = failure
    return record


def make_store(tmp_path: Path) -> CaptureStore:
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile", sensitive_mode="raw")
    return CaptureStore(config, Redactor("raw"))


def test_timeline_is_sorted_by_time_and_stable(tmp_path: Path) -> None:
    path = tmp_path / "timeline.jsonl"
    records = [
        {"kind": "a", "time": {"epochMs": 30}},
        {"kind": "b", "time": {"epochMs": 10}},
        {"kind": "c", "time": None},
        {"kind": "d", "time": {"epochMs": 10}},
        {"kind": "e", "time": {"epochMs": 20}},
    ]
    _write_jsonl(path, records)
    assert sort_jsonl_by_time(path) is True
    kinds = [json.loads(line)["kind"] for line in path.read_text(encoding="utf-8").splitlines()]
    # "c" has no time and keeps the time of the line before it (10).
    assert kinds == ["b", "c", "d", "e", "a"]
    assert sort_jsonl_by_time(path) is False


def test_timeline_external_sort_merges_chunks_in_order(tmp_path: Path) -> None:
    path = tmp_path / "timeline.jsonl"
    times = [(index * 7919) % 1000 for index in range(1000)]
    _write_jsonl(path, [{"kind": str(index), "time": {"epochMs": value}} for index, value in enumerate(times)])
    assert sort_jsonl_by_time(path, chunk_lines=64) is True
    sorted_times = [json.loads(line)["time"]["epochMs"] for line in path.read_text(encoding="utf-8").splitlines()]
    assert sorted_times == sorted(times)
    assert not list(tmp_path.glob("*.tmp"))


def test_close_sorts_the_timeline_written_out_of_order(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.timeline("request_finished", {"epochMs": 300})
    store.timeline("request_started", {"epochMs": 100})
    store.timeline("user_event", {"epochMs": 200})
    store.close()
    lines = (store.base / "timeline.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["kind"] for line in lines] == ["request_started", "user_event", "request_finished"]


def test_summary_and_csv_are_in_start_order_with_time_and_duration(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.write_jsonl("network/requests.jsonl", _request("2", 500, "https://a.test/late"))
    store.write_jsonl("network/requests.jsonl", _request("1", 100, "https://a.test/early", status=404))
    store.close()
    summary = (store.base / "reports" / "summary.txt").read_text(encoding="utf-8").splitlines()
    assert summary[0].endswith("https://a.test/early")
    assert "12ms" in summary[0]
    with open(store.base / "reports" / "requests.csv", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert [row["url"] for row in rows] == ["https://a.test/early", "https://a.test/late"]
    assert rows[0]["duration_ms"] == "12"
    assert rows[0]["started"].startswith("2023-11-14T22:13:20")
    assert "HTTP errors (status >= 400): 1" in (store.base / "reports" / "stats.txt").read_text(encoding="utf-8")


def test_overview_lists_errors_endpoints_and_what_each_action_triggered(tmp_path: Path) -> None:
    base = tmp_path
    _write_jsonl(
        base / "network" / "requests.jsonl",
        [
            _request("1", 0, "https://shop.test/", resource_type="Document"),
            _request("2", 1005, "https://shop.test/api/login", method="POST"),
            _request("3", 2002, "https://shop.test/api/items/123?page=1"),
            _request("4", 2003, "https://shop.test/api/items/456?page=2&sort=asc"),
            _request("5", 2050, "https://shop.test/api/missing", status=404),
            _request("6", 2060, "https://cdn.test/logo.png", resource_type="Image"),
            _request("7", 2070, "https://shop.test/api/x", status=None, failure={"errorText": "net::ERR_FAILED"}),
            _request("8", 2080, "https://shop.test/api/y", status=None, failure={"errorText": "net::ERR_ABORTED"}),
            _request("9", 2010, "https://shop.test/api/other-tab", session="S2"),
        ],
    )
    _write_jsonl(
        base / "browser" / "navigations.jsonl",
        [
            {
                "event": "frameNavigated",
                "time": _time(0),
                "sessionId": "S1",
                "target": {"type": "page", "targetId": "F"},
                "params": {"frame": {"id": "F", "url": "https://shop.test/"}},
            },
            {
                "event": "frameNavigated",
                "time": _time(1),
                "sessionId": "S1",
                "target": {"type": "page", "targetId": "F"},
                "params": {"frame": {"id": "child", "parentId": "F", "url": "https://ads.test/"}},
            },
            {
                "event": "navigatedWithinDocument",
                "time": _time(3000),
                "sessionId": "S1",
                "target": {"type": "page", "targetId": "F"},
                "params": {"frameId": "F", "url": "https://shop.test/cart", "navigationType": "historyApi"},
            },
        ],
    )
    click = {"tag": "button", "id": "login", "text": "Log in"}
    _write_jsonl(
        base / "interactions" / "events.jsonl",
        [
            {"event": "focus", "time": _time(990), "sessionId": "S1", "target": click},
            {"event": "click", "time": _time(1000), "sessionId": "S1", "target": click},
            {"event": "click", "time": _time(2000), "sessionId": "S1", "target": {"tag": "a", "text": "Items"}},
        ],
    )
    _write_jsonl(
        base / "browser" / "console.jsonl",
        [
            {"time": _time(2100), "level": "error", "values": ["boom", 42], "target": {"url": "https://shop.test/"}},
            {"time": _time(2101), "level": "log", "values": ["chatter"], "target": {}},
        ],
    )
    _write_jsonl(
        base / "browser" / "exceptions.jsonl",
        [{"time": _time(2200), "details": {"exception": {"description": "TypeError: x is undefined\n  at f"}}}],
    )

    text, analysis = build_overview(base)

    assert analysis["httpErrors"] == 1
    assert analysis["networkFailures"] == 1
    assert analysis["cancelledRequests"] == 1
    assert analysis["consoleErrors"] == 1
    assert analysis["exceptions"] == 1
    assert analysis["pagesVisited"] == 2
    assert analysis["userActions"] == 2
    assert "https://shop.test/cart" in text and "https://ads.test/" not in text
    assert "TypeError: x is undefined" in text and "chatter" not in text
    # Both item calls collapse into one endpoint with the union of query keys.
    assert "`https://shop.test/api/items/{id}` | page / page&sort | 2 |" in text
    assert "logo.png" not in text.split("## API endpoints", 1)[1].split("## User actions", 1)[0]
    actions = text.split("## User actions and the requests that followed", 1)[1].split("## Hosts", 1)[0]
    login, items = actions.split('`click a "Items"`')
    assert "POST 200 `https://shop.test/api/login`" in login
    assert "api/items/123" not in login
    assert "api/items/123" in items and "api/missing" in items
    # A request from another tab is never attributed to this tab's click.
    assert "other-tab" not in actions


def test_overview_of_an_empty_session_says_so(tmp_path: Path) -> None:
    text, analysis = build_overview(tmp_path)
    assert "No top-level navigation was recorded." in text
    assert "No HTTP error" in text
    assert analysis["apiEndpoints"] == 0


def test_normalize_path_collapses_identifiers_only() -> None:
    assert normalize_path("/api/users/42/orders") == "/api/users/{id}/orders"
    assert normalize_path("/v2/items/3f2504e0-4f89-11d3-9a0c-0305e82c3301") == "/v2/items/{id}"
    assert normalize_path("/blob/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3") == "/blob/{id}"
    assert normalize_path("/api/v2/graphql") == "/api/v2/graphql"
    assert normalize_path("/s/AbCdEfGhIjKlMnOpQrSt12") == "/s/{id}"


def test_labels_describe_elements_like_a_person_would() -> None:
    assert element_label({"tag": "button", "id": "go", "text": "Log in"}) == 'button#go "Log in"'
    assert element_label({"tag": "div", "testId": "cart", "text": ""}) == "div[data-testid=cart]"
    assert element_label({"tag": "input", "name": "email", "type": "email", "label": "E-mail"}) == (
        'input[name=email][type=email] "E-mail"'
    )
    assert interaction_label({"event": "keydown", "key": "Enter", "ctrl": True, "target": {"tag": "input"}}) == (
        "keydown input key=ctrl+Enter"
    )
    # A script-handled form (no action/method attribute) does not claim a GET to the page.
    scripted = {"event": "form_submit", "action": "https://a.test/", "method": "get", "target": {"tag": "form"}}
    assert interaction_label(scripted) == "form_submit form"
    declared = {**scripted, "method": "post", "target": {"tag": "form", "attrs": {"method": "post"}}}
    assert interaction_label(declared) == "form_submit form → POST https://a.test/"


def test_close_writes_the_overview_and_points_index_to_it(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.write_jsonl("network/requests.jsonl", _request("1", 0, "https://a.test/api/x", status=500))
    store.close(stats={"requests": 1})
    manifest = json.loads((store.base / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["analysis"]["httpErrors"] == 1
    assert (store.base / "reports" / "overview.md").exists()
    index = (store.base / "INDEX.md").read_text(encoding="utf-8")
    assert "read `reports/overview.md`" in index
    assert "| HTTP errors (status ≥ 400) | 1 |" in index
    assert "`reports/overview.md`" in index.split("## Files", 1)[1]


def test_index_lists_analysis_numbers_only_when_present() -> None:
    index = render_session_index({"status": "complete", "stats": {}, "analysis": {"consoleErrors": 3}}, "s")
    assert "| Console errors | 3 |" in index
    assert "Uncaught exceptions" not in index


def test_operator_note_is_shown_first_in_the_index() -> None:
    index = render_session_index({"status": "complete", "note": "Checkout bug\nwith promo code"}, "s")
    assert index.index("## Operator note") < index.index("## Outcome")
    assert "> Checkout bug\n> with promo code" in index
    assert "## Operator note" not in render_session_index({"status": "complete", "note": "  "}, "s")


def test_overview_stays_small_on_a_busy_session(tmp_path: Path) -> None:
    requests, events = [], []
    for action in range(200):
        at = action * 1000
        events.append({"event": "click", "time": _time(at), "sessionId": "S1", "target": {"tag": "button"}})
        requests += [_request(f"{action}.{n}", at + 10 + n, f"https://a.test/api/{action}/{n}/x") for n in range(15)]
    _write_jsonl(tmp_path / "network" / "requests.jsonl", requests)
    _write_jsonl(tmp_path / "interactions" / "events.jsonl", events)
    text, analysis = build_overview(tmp_path)
    assert len(text.encode("utf-8")) < 80_000
    assert "left out to keep this report short" in text
    assert analysis["userActions"] == 200


def test_overview_counts_form_posts_and_mousedown_requests(tmp_path: Path) -> None:
    gesture = _request("1", 900, "https://a.test/api/early")
    gesture["hasUserGesture"] = True
    _write_jsonl(
        tmp_path / "network" / "requests.jsonl",
        [
            _request("0", 850, "https://a.test/api/poll"),
            gesture,
            _request("2", 1500, "https://a.test/login", method="POST", resource_type="Document"),
            _request("3", 1600, "https://a.test/home", resource_type="Document"),
        ],
    )
    _write_jsonl(
        tmp_path / "interactions" / "events.jsonl",
        [
            {"event": "click", "time": _time(1000), "sessionId": "S1", "target": {"tag": "button", "id": "go"}},
            {"event": "click", "time": _time(5000), "sessionId": "S1", "target": {"tag": "a", "id": "idle"}},
        ],
    )
    text, analysis = build_overview(tmp_path)
    endpoints = text.split("## API endpoints", 1)[1].split("## User actions", 1)[0]
    assert "| POST | `https://a.test/login`" in endpoints and "a.test/home" not in endpoints
    actions = text.split("## User actions and the requests that followed", 1)[1]
    assert "-100 ms GET 200 `https://a.test/api/early`" in actions
    assert "api/poll" not in actions  # no user gesture, before the click
    assert "1 action(s) were followed by no request." in actions
    assert analysis["apiEndpoints"] == 3


def test_a_failed_timeline_sort_leaves_no_temporary_files(monkeypatch, tmp_path: Path) -> None:
    import chrome_logger.storage as storage_module

    path = tmp_path / "timeline.jsonl"
    _write_jsonl(path, [{"kind": str(n), "time": {"epochMs": 100 - n}} for n in range(50)])
    original = path.read_bytes()

    def broken_merge(*_iterables, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(storage_module.heapq, "merge", broken_merge)
    try:
        sort_jsonl_by_time(path, chunk_lines=8)
    except OSError:
        pass
    assert path.read_bytes() == original
    assert sorted(item.name for item in tmp_path.iterdir()) == ["timeline.jsonl"]
