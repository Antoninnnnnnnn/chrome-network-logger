"""Write ``INDEX.md``, the entry point of a finished session directory.

Session directories are read by people and by automated (often AI) analysts
that arrive with no prior knowledge of the format. The index states what
happened, what each file holds, how to open compressed bodies, and which
caveats apply, using only facts recorded in the manifest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .fileio import replace_with_retry

_STATUS_MEANING = {
    "complete": "the capture ended normally and every request was finalized",
    "partial": "the data on disk is valid, but the browser closed or requests were still in flight at shutdown",
    "error": "a capture or finalization error occurred; treat the data as incomplete",
    "running": "the capture did not finalize (the process was killed); files may end mid-record",
}

_REASON_MEANING = {
    "keyboardInterrupt": "stopped with Ctrl+C",
    "user": "stopped by the user",
    "chromeExited": "the browser window was closed",
    "cdpDisconnected": "the DevTools connection to the browser dropped",
    "durationElapsed": "the requested --duration elapsed",
}

# What each well-known file contains, in reading order.
_FILE_GUIDE: list[tuple[str, str]] = [
    (
        "reports/overview.md",
        "READ FIRST. Pages visited, problems (HTTP errors, failures, console errors, exceptions), API endpoints, "
        "and which user action was followed by which request.",
    ),
    (
        "reports/summary.txt",
        "One line per request in start order: time, type, method, status, API flag, duration, URL.",
    ),
    (
        "network/requests.jsonl",
        "CANONICAL. One JSON object per HTTP redirect hop, WebSocket or WebTransport connection.",
    ),
    ("reports/session.har", "The same HTTP traffic as HAR 1.2, bodies inlined up to 1 MiB; opens in DevTools."),
    ("reports/requests.csv", "Spreadsheet view of requests.jsonl (formula-neutralized)."),
    (
        "timeline.jsonl",
        "Requests, user actions, navigations, console errors, exceptions, cookie and storage changes, sorted by "
        "`time.epochMs`; use it to correlate.",
    ),
    ("interactions/events.jsonl", "User clicks, inputs, key presses, focus, navigation inside pages."),
    ("interactions/forms.jsonl", "Form submissions with their field values."),
    ("realtime/websocket_frames.jsonl", "WebSocket frames; `connectionId` equals the request `id`."),
    ("realtime/websocket_connections.jsonl", "WebSocket connection lifecycles and handshakes."),
    ("realtime/sse_messages.jsonl", "Server-sent events messages."),
    ("realtime/webtransport.jsonl", "WebTransport lifecycles (CDP exposes no payloads)."),
    ("storage/cookie_changes.jsonl", "Cookie jar diffs (added/updated/removed) with what triggered each read."),
    ("storage/dom_storage_events.jsonl", "Every localStorage/sessionStorage mutation."),
    ("storage/page_flushes.jsonl", "Full storage dumps sent by pages as they were hidden or unloaded."),
    ("storage/indexeddb.jsonl", "IndexedDB databases, schemas and bounded record dumps."),
    ("storage/cache_storage.jsonl", "Cache Storage caches and entry metadata."),
    ("snapshots/cookies_final.json", "Final cookie jar rebuilt from the event stream."),
    ("snapshots/dom_storage_final.json", "Final Web Storage per origin (sessionStorage per tab)."),
    ("browser/console.jsonl", "console.* calls."),
    ("browser/exceptions.jsonl", "Uncaught JavaScript exceptions."),
    ("browser/log.jsonl", "Browser Log-domain entries (interventions, network errors, ...)."),
    (
        "browser/navigations.jsonl",
        "Frame navigations, SPA route changes (`navigatedWithinDocument`), loading start/stop.",
    ),
    ("browser/targets.jsonl", "Tabs, popups, iframes and workers attached/detached."),
    ("browser/protocol_errors.jsonl", "CDP command failures (diagnostics, not application errors)."),
    ("browser/protocol_capabilities.jsonl", "Optional CDP features that were or were not available."),
    ("browser/proxy_toggles.jsonl", "When the upstream proxy was switched on or off."),
]

_STAT_LABELS: list[tuple[str, str]] = [
    ("requests", "Requests (HTTP hops + WebSocket + WebTransport)"),
    ("responses", "Responses"),
    ("redirects", "Redirect hops"),
    ("failures", "Failed requests (network errors, blocked, cancelled)"),
    ("bodies", "Response bodies stored"),
    ("bodyErrors", "Bodies lost to errors"),
    ("bodiesUnavailable", "Responses that never had a body (HEAD, 204/304, redirect, cancelled)"),
    ("incompleteFlushed", "Requests still in flight at shutdown (marked incomplete)"),
    ("incompleteDetached", "Requests cut off because their tab/iframe/worker closed"),
    ("webSocketFrames", "WebSocket frames"),
    ("sseMessages", "Server-sent events"),
    ("userEvents", "User interaction events"),
    ("cookieChanges", "Cookie changes"),
    ("storageChanges", "Web Storage changes"),
    ("storageFlushes", "Page storage flushes"),
    ("idbEntries", "IndexedDB records dumped"),
    ("cacheEntries", "Cache Storage entries dumped"),
    ("degradedSessions", "Secondary targets captured partially"),
    ("eventErrors", "Internal event-handler errors"),
]

_ANALYSIS_LABELS: list[tuple[str, str]] = [
    ("httpErrors", "HTTP errors (status ≥ 400)"),
    ("networkFailures", "Network failures (excluding cancellations)"),
    ("consoleErrors", "Console errors"),
    ("exceptions", "Uncaught exceptions"),
    ("apiEndpoints", "Distinct API endpoints"),
    ("pagesVisited", "Top-level page loads and SPA route changes"),
    ("userActions", "User actions (click, submit, change, key, paste)"),
]


_OTHER_FILES = {
    "reports/stats.txt": "Request counts by resource type.",
    "reports/interactions.html": "Readable, HTML-escaped view of interactions/events.jsonl.",
    "realtime/websocket_errors.jsonl": "WebSocket frame errors.",
}


def _describe_other(path: str) -> str:
    """Describe files whose names carry a variable part, such as a snapshot label."""
    if path in _OTHER_FILES:
        return _OTHER_FILES[path]
    name = path.rsplit("/", 1)[-1]
    if path.startswith("snapshots/cookies_") and name.endswith(".json"):
        return f"Whole cookie jar read at the `{name[len('cookies_') : -len('.json')]}` snapshot."
    if path.startswith("snapshots/storage_") and name.endswith(".jsonl"):
        label = name[len("storage_") : -len(".jsonl")]
        return f"localStorage/sessionStorage of each open page read at the `{label}` snapshot."
    return ""


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _reason_text(reason: str | None) -> str:
    if not reason:
        return "unknown"
    if reason in _REASON_MEANING:
        return f"{reason} ({_REASON_MEANING[reason]})"
    if reason.startswith("signal:"):
        return f"{reason} (stopped by a signal)"
    if reason.startswith("error:"):
        return f"{reason} (a capture error)"
    return reason


def render_session_index(manifest: dict[str, Any], session_name: str) -> str:
    configuration = manifest.get("configuration") or {}
    stats = manifest.get("stats") or {}
    files = {item.get("path"): item for item in manifest.get("files") or [] if isinstance(item, dict)}
    status = str(manifest.get("status") or "unknown")
    sensitive = configuration.get("sensitiveMode")
    compressed = configuration.get("compressTextBodies", True)
    chrome = manifest.get("chrome") or {}
    lines: list[str] = [
        f"# Capture session `{session_name}`",
        "",
        "Start here. This file is generated when the capture ends and describes, from the recorded",
        "manifest, what was captured, where it is, and how to read it. Paths are relative to this directory.",
        "",
        "**Next, read `reports/overview.md`**: it already lists the pages visited, every error, the API endpoints, "
        "and which user action was followed by which request, so most questions need no scan of the raw files.",
        "",
    ]
    note = str(manifest.get("note") or "").strip()
    if note:
        # The operator's own description of the scenario: the context an analyst cannot infer.
        lines += ["## Operator note", "", *[f"> {line}" for line in note.splitlines()], ""]
    lines += [
        "## Outcome",
        "",
        f"- **Status:** `{status}` — {_STATUS_MEANING.get(status, 'see manifest.json')}.",
        f"- **Stopped because:** {_reason_text(manifest.get('shutdownReason'))}.",
        f"- **Time:** {manifest.get('startedAt', '?')} → {manifest.get('endedAt', '?')}.",
        f"- **Browser:** {chrome.get('browser') or 'unknown'}; logger {manifest.get('loggerVersion', '?')}.",
    ]
    if sensitive == "raw":
        lines.append(
            "- **Sensitive data:** raw mode — credentials, cookies, tokens and form values are stored in clear text."
        )
    elif sensitive == "safe":
        lines.append(
            "- **Sensitive data:** safe mode — secrets appear as `<redacted len=N hmac=XXXX>`; equal HMACs within "
            "this session mean equal values. Form values appear as `<redacted len=N source=browser>`."
        )
    lines.append(
        f"- **Body policy:** `{configuration.get('bodyMode', '?')}` (none = metadata only, api = XHR/Fetch/Document, "
        "all = every resource)."
    )
    proxy = manifest.get("proxy") or {}
    if proxy.get("enabled"):
        lines.append(f"- **Network route:** upstream proxy `{proxy.get('upstream')}`.")
    warnings = [str(item) for item in manifest.get("warnings") or []]
    if warnings:
        lines += ["", "### Warnings", ""]
        lines += [f"- {warning}" for warning in warnings[:25]]
        if len(warnings) > 25:
            lines.append(f"- … {len(warnings) - 25} more in `manifest.json`.")
        if manifest.get("warningsSuppressed"):
            lines.append(f"- {manifest['warningsSuppressed']} further distinct warnings were not recorded.")

    analysis = manifest.get("analysis") or {}
    shown = [(label, stats.get(key)) for key, label in _STAT_LABELS if stats.get(key)]
    shown += [(label, analysis.get(key)) for key, label in _ANALYSIS_LABELS if analysis.get(key)]
    if shown:
        lines += ["", "## Key numbers", "", "| Measure | Value |", "|---|---:|"]
        lines += [f"| {label} | {value} |" for label, value in shown]
    body_storage = manifest.get("bodyStorage") or {}
    if body_storage.get("omittedBodies"):
        lines.append(
            f"\n{body_storage['omittedBodies']} unique bodies were not stored because the session body limit "
            'was reached (`omittedReason: "sessionBodyLimit"`).'
        )

    lines += ["", "## Files", "", "| File | Size | Records | Contents |", "|---|---:|---:|---|"]
    described: set[str] = set()
    for path, description in _FILE_GUIDE:
        item = files.get(path)
        if not item:
            continue
        described.add(path)
        records = item.get("records", "")
        lines.append(f"| `{path}` | {_human_size(int(item.get('bytes') or 0))} | {records} | {description} |")
    bodies = files.get("network/bodies/")
    if bodies:
        described.add("network/bodies/")
        lines.append(
            f"| `network/bodies/` | {_human_size(int(bodies.get('bytes') or 0))} | {bodies.get('files', '')} files | "
            "Body blobs named by SHA-256, referenced from records; never read them blindly. |"
        )
    for path, item in sorted(files.items()):
        if path in described or not path:
            continue
        records = item.get("records", "")
        lines.append(
            f"| `{_cell(path)}` | {_human_size(int(item.get('bytes') or 0))} | {records} | {_describe_other(path)} |"
        )

    lines += [
        "",
        "## How to read the data",
        "",
        "- Every `.jsonl` file holds one JSON object per line; read them line by line and filter, they can be large.",
        "- In `network/requests.jsonl`, `id` is unique (`<sessionId>::<requestId>::hop<N>`). Useful fields: "
        "`type`, `isApi`, `request.method`, `request.url`, `response.status`, `response.headers`, `extraInfo` "
        "(raw wire headers including cookies), `failure`, `durationMs`, `started.epochMs`.",
        "- A body is referenced as `response.body` / `request.body`: `path` points into `network/bodies/`, "
        "`preview` holds small text bodies inline, `truncated`/`omitted` say when the file is not the whole body.",
    ]
    if compressed:
        lines.append(
            "- Text bodies are gzip-compressed (`.gz`, `compressed: true`). To print one: "
            "`python -c \"import gzip,sys; sys.stdout.write(gzip.open(sys.argv[1], 'rt', encoding='utf-8', "
            "errors='replace').read())\" network/bodies/<file>.gz`. Run the logger with `--no-text-compression` "
            "to store plain files."
        )
    lines += [
        "- `responseBodyUnavailableReason` means the response could never carry a body; `responseBodyError` "
        "means a body existed but could not be read.",
        "- `incomplete: true` with `incompleteReason` marks a request that never finished loading; "
        "`extraInfoIncomplete: true` only means the raw wire headers did not arrive.",
        "- `sessionId` identifies the tab, iframe or worker; `browser/targets.jsonl` maps it to a URL and type.",
        "- To find what a click caused, take its `time.epochMs` in `timeline.jsonl` and read the `request_started` "
        "lines of the same `sessionId` that follow; each request's `initiator` names the script and stack.",
        "- `network/requests.jsonl` is in completion order, not start order; sort on `started.epochMs` if needed.",
        "- `reports/` files are derived views; `network/requests.jsonl` wins if they disagree.",
        "",
        "## Not captured",
        "",
        "Raw DNS/TCP/TLS/QUIC packets, WebRTC media and DataChannels, WebTransport payloads, redirect response "
        "bodies, and multipart file bytes that Chrome does not expose are outside the DevTools protocol.",
        "",
        "Field definitions: https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/docs/CAPTURE_SCHEMA.md",
        "",
    ]
    return "\n".join(lines)


def write_session_index(base: Path, manifest: dict[str, Any]) -> Path:
    """Render and atomically write ``INDEX.md`` into the session directory."""
    target = base / "INDEX.md"
    temporary = base / "INDEX.md.tmp"
    temporary.write_text(render_session_index(manifest, base.name), encoding="utf-8")
    replace_with_retry(temporary, target)
    return target
