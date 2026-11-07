"""Write ``reports/overview.md``: a short, pre-digested reading of a session.

A session is often analysed by an AI agent with a limited context window. It
should not have to stream megabytes of JSONL to learn which pages were
visited, which API endpoints were called, what failed, and which user action
was followed by which request. This report answers those questions from the
files already on disk, with every section bounded, and names the record ``id``
to look up for details. It is a derived view: ``network/requests.jsonl`` wins
if they disagree.
"""

from __future__ import annotations

import bisect
import json
import re
import statistics
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .fileio import replace_with_retry
from .labels import console_text, interaction_label

# Actions a person takes on purpose; focus and debounced input are too chatty
# to attribute requests to.
ACTION_EVENTS = frozenset({"click", "form_submit", "keydown", "change", "paste"})
# Requests that a user action plausibly "causes" and an analyst cares about.
CAUSED_TYPES = frozenset({"Document", "XHR", "Fetch", "EventSource", "WebSocket", "Ping", "Other"})
# Static resources and CORS preflights are not API endpoints. A Document is
# one only when it is not a GET (a classic form POST), see below.
NOT_ENDPOINT_TYPES = frozenset({"Image", "Stylesheet", "Font", "Script", "Media", "Manifest", "TextTrack", "Preflight"})
API_TYPES = frozenset({"XHR", "Fetch", "EventSource", "WebSocket", "Ping"})
CANCELLED_ERRORS = frozenset({"net::ERR_ABORTED"})
CONSOLE_ERROR_LEVELS = frozenset({"error", "assert"})

ACTION_WINDOW_MS = 2_000
# Libraries often fire on pointerdown/mousedown, shortly before the click
# event; such a request is attributed only if Chrome saw a user gesture.
GESTURE_LEAD_MS = 300
# The report is meant to fit an analyst's context window: every section is
# bounded, and the action section also has a size budget.
MAX_ROWS = 25
MAX_ENDPOINTS = 80
MAX_HOSTS = 25
MAX_PAGES = 40
MAX_REQUESTS_PER_ACTION = 6
ACTION_SECTION_BUDGET = 24_000
URL_DISPLAY = 160

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
_NUMBER = re.compile(r"^\d+$")
_TOKEN = re.compile(r"^[A-Za-z0-9_\-]{20,}$")


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def _epoch(value: Any) -> float | None:
    if isinstance(value, dict):
        value = value.get("epochMs")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _clock(epoch_ms: float | None) -> str:
    if epoch_ms is None:
        return "--:--:--.---"
    try:
        return datetime.fromtimestamp(epoch_ms / 1000).strftime("%H:%M:%S.%f")[:-3]
    except (ValueError, OverflowError, OSError):
        return "--:--:--.---"


def _cell(value: Any, limit: int = URL_DISPLAY) -> str:
    text = " ".join(str(value if value is not None else "").split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|").replace("`", "'")


def normalize_path(path: str) -> str:
    """Collapse identifiers in a URL path so calls to one endpoint group together."""
    parts = []
    for segment in path.split("/"):
        if _NUMBER.match(segment) or _UUID.match(segment) or _HEX.match(segment):
            parts.append("{id}")
        elif _TOKEN.match(segment) and any(char.isdigit() for char in segment):
            parts.append("{id}")
        else:
            parts.append(segment)
    return "/".join(parts) or "/"


def _endpoint(url: str) -> tuple[str, str]:
    """Return (origin + normalized path, sorted query parameter names)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url, ""
    if not parts.scheme or not parts.netloc:
        return url.split("?", 1)[0], ""
    names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(names[:8]) + ("&…" if len(names) > 8 else "")
    return f"{parts.scheme}://{parts.netloc}{normalize_path(parts.path)}", query


def _host(url: str) -> str:
    try:
        return urlsplit(url).netloc or urlsplit(url).scheme or "?"
    except ValueError:
        return "?"


def _status_text(counts: dict[Any, int]) -> str:
    ordered = sorted(counts.items(), key=lambda item: str(item[0]))
    return ", ".join(f"{status}×{count}" if count > 1 else str(status) for status, count in ordered)


def _more(lines: list[str], total: int, shown: int, where: str) -> None:
    if total > shown:
        lines.append(f"\n… {total - shown} more in `{where}`.")


class _Request:
    __slots__ = (
        "id",
        "session",
        "type",
        "method",
        "url",
        "status",
        "failure",
        "start",
        "duration",
        "incomplete",
        "gesture",
    )

    def __init__(self, record: dict[str, Any]):
        request = record.get("request") or {}
        response = record.get("response") or {}
        self.id = str(record.get("id") or "")
        self.session = record.get("sessionId")
        self.type = str(record.get("type") or "Other")
        self.method = str(request.get("method") or ("WS" if self.type == "WebSocket" else "?"))
        self.url = str(request.get("url") or record.get("url") or "")
        status = response.get("status")
        self.status = status if isinstance(status, (int, float)) and not isinstance(status, bool) else None
        self.failure = record.get("failure") if isinstance(record.get("failure"), dict) else None
        self.start = _epoch(record.get("started") or record.get("created"))
        duration = record.get("durationMs")
        self.duration = duration if isinstance(duration, (int, float)) else None
        self.incomplete = bool(record.get("incomplete"))
        self.gesture = record.get("hasUserGesture") is True

    @property
    def cancelled(self) -> bool:
        failure = self.failure or {}
        return bool(failure.get("canceled")) or failure.get("errorText") in CANCELLED_ERRORS

    def outcome(self) -> str:
        if self.failure:
            failure = self.failure
            detail = failure.get("errorText") or "failed"
            if failure.get("blockedReason"):
                detail += f" blocked:{failure['blockedReason']}"
            cors = (failure.get("corsErrorStatus") or {}).get("corsError")
            if cors:
                detail += f" cors:{cors}"
            return detail
        if self.incomplete:
            return "incomplete"
        return str(int(self.status)) if self.status is not None else "?"


def _main_frame_navigation(record: dict[str, Any]) -> tuple[str, str] | None:
    """Return (kind, url) for a top-level page navigation, else None."""
    event = record.get("event")
    params = record.get("params") or {}
    target = record.get("target") or {}
    if target.get("type") not in (None, "page"):
        return None
    if event == "frameNavigated":
        frame = params.get("frame") or {}
        if frame.get("parentId"):
            return None
        return "load", str(frame.get("url") or "") + str(frame.get("urlFragment") or "")
    if event == "navigatedWithinDocument":
        if target.get("targetId") and params.get("frameId") != target.get("targetId"):
            return None
        kind = "route" if params.get("navigationType") in (None, "historyApi", "other") else "fragment"
        return kind, str(params.get("url") or "")
    return None


def _console_text(record: dict[str, Any]) -> str:
    return " ".join(console_text(value) for value in record.get("values") or [])


def _exception_text(record: dict[str, Any]) -> str:
    details = record.get("details") or {}
    exception = details.get("exception") or {}
    text = exception.get("description") or details.get("text") or "Uncaught exception"
    return str(text).split("\n", 1)[0]


def build_overview(base: Path) -> tuple[str, dict[str, Any]]:
    """Return the Markdown overview and the numbers recorded in the manifest."""
    requests: list[_Request] = []
    for record in _iter_jsonl(base / "network" / "requests.jsonl"):
        requests.append(_Request(record))
    requests.sort(key=lambda item: item.start if item.start is not None else float("inf"))

    pages: list[tuple[float | None, str, str, str]] = []
    for record in _iter_jsonl(base / "browser" / "navigations.jsonl"):
        navigation = _main_frame_navigation(record)
        if navigation and navigation[1] and not navigation[1].startswith("about:blank"):
            pages.append((_epoch(record.get("time")), navigation[0], navigation[1], str(record.get("sessionId") or "")))
    pages.sort(key=lambda item: item[0] if item[0] is not None else float("inf"))

    actions: list[tuple[float, str, str, str]] = []
    for name in ("events.jsonl", "forms.jsonl"):
        for record in _iter_jsonl(base / "interactions" / name):
            if record.get("event") not in ACTION_EVENTS:
                continue
            when = _epoch(record.get("time")) or _epoch(record.get("ts"))
            if when is None:
                continue
            actions.append(
                (when, str(record.get("sessionId") or ""), interaction_label(record), str(record.get("url") or ""))
            )
    actions.sort(key=lambda item: item[0])

    console_errors: list[tuple[float | None, str, str]] = []
    for record in _iter_jsonl(base / "browser" / "console.jsonl"):
        if record.get("level") in CONSOLE_ERROR_LEVELS:
            console_errors.append(
                (_epoch(record.get("time")), _console_text(record), str((record.get("target") or {}).get("url") or ""))
            )
    exceptions: list[tuple[float | None, str, str]] = []
    for record in _iter_jsonl(base / "browser" / "exceptions.jsonl"):
        details = record.get("details") or {}
        exceptions.append((_epoch(record.get("time")), _exception_text(record), str(details.get("url") or "")))

    http_errors = [item for item in requests if item.status is not None and item.status >= 400]
    failed = [item for item in requests if item.failure and not item.cancelled]
    cancelled = [item for item in requests if item.failure and item.cancelled]
    incomplete = [item for item in requests if item.incomplete]

    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    hosts: dict[str, dict[str, int]] = {}
    for item in requests:
        host = hosts.setdefault(_host(item.url), {"requests": 0, "api": 0, "problems": 0})
        host["requests"] += 1
        problem = (item.status is not None and item.status >= 400) or (item.failure and not item.cancelled)
        host["problems"] += int(bool(problem))
        if item.type in NOT_ENDPOINT_TYPES:
            continue
        if item.type not in API_TYPES and item.method in {"GET", "HEAD", "?"}:
            continue
        host["api"] += 1
        path, query = _endpoint(item.url)
        group = endpoints.setdefault(
            (item.method, path),
            {"query": set(), "statuses": {}, "durations": [], "first": item, "count": 0},
        )
        group["count"] += 1
        if query:
            group["query"].add(query)
        outcome = item.outcome()
        group["statuses"][outcome] = group["statuses"].get(outcome, 0) + 1
        if item.duration is not None:
            group["durations"].append(item.duration)

    lines: list[str] = [
        "# Session overview",
        "",
        "Pre-digested from the session files when the capture ended, for a reader who should not have to scan every "
        "record. Times are the local clock (`time.iso`). Each row names a record `id`: look it up in "
        "`network/requests.jsonl` for headers, timings and the body reference.",
        "",
        "| | |",
        "|---|---:|",
        f"| Requests | {len(requests)} |",
        f"| API endpoints (method + path, ids collapsed) | {len(endpoints)} |",
        f"| HTTP errors (status ≥ 400) | {len(http_errors)} |",
        f"| Network failures (not counting cancellations) | {len(failed)} |",
        f"| Cancelled requests | {len(cancelled)} |",
        f"| Incomplete requests | {len(incomplete)} |",
        f"| Console errors | {len(console_errors)} |",
        f"| Uncaught exceptions | {len(exceptions)} |",
        f"| User actions (click, submit, change, key, paste) | {len(actions)} |",
    ]

    lines += ["", "## Pages visited", ""]
    if pages:
        lines += ["| Time | Kind | URL | Tab |", "|---|---|---|---|"]
        for when, kind, url, session in pages[:MAX_PAGES]:
            lines.append(f"| {_clock(when)} | {kind} | `{_cell(url)}` | `{session[:8]}` |")
        _more(lines, len(pages), MAX_PAGES, "browser/navigations.jsonl")
    else:
        lines.append("No top-level navigation was recorded.")

    lines += ["", "## Problems", ""]
    any_problem = False
    if http_errors:
        any_problem = True
        lines += ["### HTTP errors", "", "| Time | Method | Status | URL | id |", "|---|---|---:|---|---|"]
        for item in http_errors[:MAX_ROWS]:
            lines.append(
                f"| {_clock(item.start)} | {item.method} | {int(item.status or 0)} | `{_cell(item.url)}` | `{item.id}` |"
            )
        _more(lines, len(http_errors), MAX_ROWS, "network/requests.jsonl")
        lines.append("")
    if failed:
        any_problem = True
        lines += ["### Network failures", "", "| Time | Method | Error | URL | id |", "|---|---|---|---|---|"]
        for item in failed[:MAX_ROWS]:
            lines.append(
                f"| {_clock(item.start)} | {item.method} | {_cell(item.outcome(), 80)} | `{_cell(item.url)}` | "
                f"`{item.id}` |"
            )
        _more(lines, len(failed), MAX_ROWS, "network/requests.jsonl")
        lines.append("")
    if incomplete:
        any_problem = True
        lines += [
            "### Incomplete requests",
            "",
            "Never finished loading (see `incompleteReason`).",
            "",
            "| Time | Method | URL | id |",
            "|---|---|---|---|",
        ]
        for item in incomplete[:MAX_ROWS]:
            lines.append(f"| {_clock(item.start)} | {item.method} | `{_cell(item.url)}` | `{item.id}` |")
        _more(lines, len(incomplete), MAX_ROWS, "network/requests.jsonl")
        lines.append("")
    for title, rows, where in (
        ("Console errors", console_errors, "browser/console.jsonl"),
        ("Uncaught exceptions", exceptions, "browser/exceptions.jsonl"),
    ):
        if not rows:
            continue
        any_problem = True
        lines += [f"### {title}", "", "| Time | Message | Page or script |", "|---|---|---|"]
        for when, text, url in rows[:MAX_ROWS]:
            lines.append(f"| {_clock(when)} | {_cell(text, 200)} | `{_cell(url, 100)}` |")
        _more(lines, len(rows), MAX_ROWS, where)
        lines.append("")
    if cancelled:
        lines.append(
            f"{len(cancelled)} request(s) were cancelled (`net::ERR_ABORTED`, usually navigation or an aborted fetch); "
            "they are not listed as problems."
        )
        lines.append("")
    if not any_problem:
        lines += ["No HTTP error, network failure, console error or uncaught exception was recorded.", ""]

    lines += ["## API endpoints", ""]
    if endpoints:
        lines += [
            "Calls grouped by method and path; numeric, UUID, hex and token-like path segments are shown as `{id}`. "
            "Outcomes are status codes or network errors.",
            "",
            "| First call | Method | Endpoint | Query keys | Calls | Outcomes | Median ms | First id |",
            "|---|---|---|---|---:|---|---:|---|",
        ]
        ordered = sorted(
            endpoints.items(),
            key=lambda pair: pair[1]["first"].start if pair[1]["first"].start is not None else float("inf"),
        )
        for (method, path), group in ordered[:MAX_ENDPOINTS]:
            first: _Request = group["first"]
            durations = group["durations"]
            median = f"{statistics.median(durations):.0f}" if durations else ""
            query = _cell(" / ".join(sorted(group["query"])[:3]), 60)
            lines.append(
                f"| {_clock(first.start)} | {method} | `{_cell(path)}` | {query} | {group['count']} | "
                f"{_cell(_status_text(group['statuses']), 60)} | {median} | `{first.id}` |"
            )
        _more(lines, len(endpoints), MAX_ENDPOINTS, "network/requests.jsonl")
    else:
        lines.append("No API call (XHR, Fetch, EventSource, WebSocket, beacon, or non-GET request) was recorded.")

    lines += ["", "## User actions and the requests that followed", ""]
    if actions:
        lines += [
            f"Heuristic: requests from the same tab (CDP session; its workers and out-of-process iframes are not "
            f"included) that started within {ACTION_WINDOW_MS / 1000:g} s after an action and before the next "
            f"action, plus those Chrome flagged `hasUserGesture` up to {GESTURE_LEAD_MS} ms before it "
            "(handlers on mousedown). Static resources are left out. A request listed here is likely, not "
            "certainly, caused by the action; check its `initiator`. Actions followed by no request are only "
            "counted; `timeline.jsonl` has every action.",
            "",
        ]
        by_session: dict[str, list[_Request]] = {}
        for item in requests:
            if item.start is not None and item.type in CAUSED_TYPES:
                by_session.setdefault(str(item.session or ""), []).append(item)
        starts = {session: [item.start for item in items] for session, items in by_session.items()}
        previous_action: dict[int, float] = {}
        next_action: dict[int, float] = {}
        last_seen: dict[str, int] = {}
        for index, (when, session, _label, _url) in enumerate(actions):
            if session in last_seen:
                next_action[last_seen[session]] = when
                previous_action[index] = actions[last_seen[session]][0]
            last_seen[session] = index
        used = 0
        listed = 0
        silent = 0
        omitted = 0
        for index, (when, session, label, url) in enumerate(actions):
            items = by_session.get(session, [])
            times = starts.get(session, [])
            low = max(when - GESTURE_LEAD_MS, previous_action.get(index, float("-inf")))
            high = min(when + ACTION_WINDOW_MS, next_action.get(index, float("inf")))
            followed = [
                item
                for item in items[bisect.bisect_left(times, low) : bisect.bisect_left(times, high)]
                if item.start is not None and (item.start >= when or item.gesture)
            ]
            if not followed:
                silent += 1
                continue
            block = [f"- {_clock(when)} `{_cell(label, 120)}` on `{_cell(url, 100)}`"]
            for item in followed[:MAX_REQUESTS_PER_ACTION]:
                delta = (item.start or when) - when
                block.append(
                    f"  - {delta:+.0f} ms {item.method} {item.outcome()} `{_cell(item.url, 120)}` — `{item.id}`"
                )
            if len(followed) > MAX_REQUESTS_PER_ACTION:
                block.append(f"  - … {len(followed) - MAX_REQUESTS_PER_ACTION} more")
            size = sum(len(line) + 1 for line in block)
            if used + size > ACTION_SECTION_BUDGET:
                omitted += 1
                continue
            used += size
            listed += 1
            lines += block
        if not listed:
            lines.append("No request followed any user action.")
        if omitted:
            lines.append(
                f"\n… {omitted} more action(s) followed by requests are left out to keep this report short; "
                "use `timeline.jsonl`."
            )
        if silent:
            lines.append(f"\n{silent} action(s) were followed by no request.")
    else:
        lines.append("No user action was recorded.")

    lines += ["", "## Hosts", "", "| Host | Requests | API calls | Problems |", "|---|---:|---:|---:|"]
    ranked = sorted(hosts.items(), key=lambda pair: (-pair[1]["requests"], pair[0]))
    for host, counts in ranked[:MAX_HOSTS]:
        lines.append(f"| `{_cell(host, 80)}` | {counts['requests']} | {counts['api']} | {counts['problems']} |")
    _more(lines, len(hosts), MAX_HOSTS, "network/requests.jsonl")
    lines.append("")

    analysis = {
        "apiEndpoints": len(endpoints),
        "httpErrors": len(http_errors),
        "networkFailures": len(failed),
        "cancelledRequests": len(cancelled),
        "consoleErrors": len(console_errors),
        "exceptions": len(exceptions),
        "pagesVisited": len(pages),
        "userActions": len(actions),
        "hosts": len(hosts),
    }
    return "\n".join(lines), analysis


def write_overview(base: Path) -> dict[str, Any]:
    """Write ``reports/overview.md`` atomically and return its headline numbers."""
    text, analysis = build_overview(base)
    target = base / "reports" / "overview.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    replace_with_retry(temporary, target)
    return analysis
