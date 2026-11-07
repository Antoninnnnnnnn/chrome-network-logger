"""HAR 1.2 export of a capture session.

``write_har`` turns ``network/requests.jsonl`` (plus WebSocket frames from
``realtime/websocket_frames.jsonl`` and the stored body files) into
``reports/session.har``. The JSONL stream stays the canonical record; the HAR
is a derived view for HAR tooling and for agents reading the session, so every
gap (missing body, skipped line, unknown timing) is explained in the file
itself instead of being silently dropped.

Records are never all held in memory: a first pass keeps only
``(start time, line number, byte offset)`` per line, a second pass re-reads the
lines in start-time order and streams the HAR to disk.
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import gzip
import json
import logging
import math
import os
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import IO, Any
from urllib.parse import parse_qsl, urlsplit

from .constants import REDIRECT_CODES

LOG = logging.getLogger(__name__)

REQUESTS_FILE = "network/requests.jsonl"
FRAMES_FILE = "realtime/websocket_frames.jsonl"
HAR_FILE = "reports/session.har"
MAX_WEBSOCKET_MESSAGES = 1_000

_MAX_LISTED_SKIPS = 100
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_ENTRY_PAD = " " * 6
_EPOCH_PLACEHOLDER = "1970-01-01T00:00:00.000Z"
_HTTP_VERSIONS = {
    "http/0.9": "HTTP/0.9",
    "http/1.0": "HTTP/1.0",
    "http/1.1": "HTTP/1.1",
    "h2": "HTTP/2.0",
    "http/2": "HTTP/2.0",
    "http/2.0": "HTTP/2.0",
    "h3": "HTTP/3.0",
    "http/3": "HTTP/3.0",
}
# Chrome DevTools names resource types in lower case; these two also gain hyphens.
_DEVTOOLS_RESOURCE_TYPES = {"SignedExchange": "signed-exchange", "CSPViolationReport": "csp-violation-report"}
_PASSTHROUGH_FIELDS = (
    ("hop", "_hop"),
    ("failure", "_failure"),
    ("incomplete", "_incomplete"),
    ("incompleteReason", "_incompleteReason"),
    ("responseBodyUnavailableReason", "_responseBodyUnavailableReason"),
    ("responseBodyError", "_responseBodyError"),
    ("fetchResponseBodyError", "_fetchResponseBodyError"),
    ("requestPostDataError", "_requestPostDataError"),
    ("extraInfoIncomplete", "_extraInfoIncomplete"),
    ("realtime", "_realtime"),
)
_TIMED_PHASES = ("blocked", "dns", "connect", "send", "wait", "receive")


@dataclass(slots=True)
class _Export:
    session_dir: Path
    root: Path
    limit: int
    frame_offsets: dict[str, list[int]] = field(default_factory=dict)
    frame_counts: dict[str, int] = field(default_factory=dict)
    frames_handle: IO[bytes] | None = None
    frames_error: str | None = None
    frames_skipped: int = 0
    orphan_frames: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)
    skipped_count: int = 0

    def skip(self, line: int, reason: str) -> None:
        LOG.debug("HAR export skipped %s line %s: %s", REQUESTS_FILE, line, reason)
        self.skipped_count += 1
        if len(self.skipped) < _MAX_LISTED_SKIPS:
            self.skipped.append({"line": line, "reason": reason})


@dataclass(slots=True)
class _Payload:
    text: str | None = None
    base64: bool = False
    size: int = -1
    path: str | None = None
    notes: list[str] = field(default_factory=list)


def write_har(session_dir: Path, *, creator_version: str, max_inline_body_bytes: int = 1_048_576) -> Path | None:
    """Write ``reports/session.har`` from the session's network stream.

    Returns the HAR path, or ``None`` when the session has no
    ``network/requests.jsonl``. Bodies whose stored size exceeds
    ``max_inline_body_bytes`` (``0`` keeps every body out) are referenced
    rather than inlined. Malformed lines, missing or corrupt body files and
    unreadable frames are skipped or annotated; only errors writing the HAR
    itself propagate.
    """
    if max_inline_body_bytes < 0:
        raise ValueError("max_inline_body_bytes must be >= 0")
    session_dir = Path(session_dir)
    source = session_dir / REQUESTS_FILE
    if not source.is_file():
        return None
    state = _Export(session_dir=session_dir, root=session_dir.resolve(), limit=max_inline_body_bytes)
    target = session_dir / HAR_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        with contextlib.ExitStack() as stack:
            records = stack.enter_context(source.open("rb"))
            index, websocket_ids = _index_records(records, state)
            _index_frames(session_dir / FRAMES_FILE, websocket_ids, state)
            if state.frame_offsets:
                try:
                    state.frames_handle = stack.enter_context((session_dir / FRAMES_FILE).open("rb"))
                except OSError as exc:
                    state.frames_error = f"{type(exc).__name__}: {exc}"
            # backslashreplace keeps lone surrogates from the input as valid JSON escapes.
            output = stack.enter_context(temporary.open("w", encoding="utf-8", errors="backslashreplace", newline="\n"))
            _write_log(output, records, index, state, creator_version, _browser(session_dir))
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if state.skipped_count:
        LOG.warning("HAR export skipped %s unusable line(s) of %s", state.skipped_count, REQUESTS_FILE)
    return target


# --- passes over the input -------------------------------------------------


def _parse_line(line: bytes) -> tuple[Any, str | None]:
    try:
        return json.loads(line, parse_constant=lambda _constant: None), None
    except (ValueError, RecursionError) as exc:
        return None, f"invalid JSON ({type(exc).__name__}: {exc})"


def _sort_time(record: dict[str, Any]) -> float:
    for key in ("started", "finished"):
        value = _epoch_ms(record.get(key))
        if value is not None:
            return value
    return math.inf


def _index_records(handle: IO[bytes], state: _Export) -> tuple[list[tuple[float, int, int]], set[str]]:
    index: list[tuple[float, int, int]] = []
    websocket_ids: set[str] = set()
    offset = 0
    for line_number, line in enumerate(handle, start=1):
        start = offset
        offset += len(line)
        if not line.strip():
            continue
        record, error = _parse_line(line)
        if not isinstance(record, dict):
            state.skip(line_number, error or "not a JSON object")
            continue
        index.append((_sort_time(record), line_number, start))
        if record.get("type") == "WebSocket" and isinstance(record.get("id"), str):
            websocket_ids.add(record["id"])
    index.sort()
    return index, websocket_ids


def _index_frames(path: Path, websocket_ids: set[str], state: _Export) -> None:
    if not path.is_file():
        return
    try:
        with path.open("rb") as handle:
            offset = 0
            for line in handle:
                start = offset
                offset += len(line)
                if not line.strip():
                    continue
                frame, _ = _parse_line(line)
                if not isinstance(frame, dict):
                    state.frames_skipped += 1
                    continue
                connection = frame.get("connectionId")
                if not isinstance(connection, str) or connection not in websocket_ids:
                    state.orphan_frames += 1
                    continue
                count = state.frame_counts.get(connection, 0) + 1
                state.frame_counts[connection] = count
                if count <= MAX_WEBSOCKET_MESSAGES:
                    state.frame_offsets.setdefault(connection, []).append(start)
    except OSError as exc:
        state.frames_error = f"{type(exc).__name__}: {exc}"


def _browser(session_dir: Path) -> dict[str, str] | None:
    path = session_dir / "manifest.json"
    try:
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    product = _text(_dict(_dict(manifest).get("chrome")).get("browser"))
    name, _, version = (product or "").partition("/")
    return {"name": name, "version": version} if name and version else None


# --- output ----------------------------------------------------------------


def _dump(value: Any, pad: str) -> str:
    # JSON strings never contain raw newlines, so this only re-indents structure.
    return json.dumps(value, ensure_ascii=False, indent=2).replace("\n", "\n" + pad)


def _write_log(
    output: IO[str],
    records: IO[bytes],
    index: list[tuple[float, int, int]],
    state: _Export,
    creator_version: str,
    browser: dict[str, str] | None,
) -> None:
    head: dict[str, Any] = {
        "version": "1.2",
        "creator": {"name": "chrome-network-logger", "version": creator_version},
    }
    if browser:
        head["browser"] = browser
    head["pages"] = []
    head["comment"] = _log_comment(state.limit)
    output.write('{\n  "log": {\n')
    for key, value in head.items():
        output.write(f"    {json.dumps(key)}: {_dump(value, '    ')},\n")
    output.write('    "entries": [')
    written = 0
    for _, line_number, offset in index:
        records.seek(offset)
        record, error = _parse_line(records.readline())
        if not isinstance(record, dict):
            state.skip(line_number, error or "the line changed during the export")
            continue
        try:
            entry, connection = _build_entry(record, state)
            text = _dump(entry, _ENTRY_PAD)
        except Exception as exc:  # one odd record must not abort the whole export
            state.skip(line_number, f"could not be converted ({type(exc).__name__}: {exc})")
            continue
        output.write(",\n" if written else "\n")
        _write_entry(output, text, _websocket_messages(state, connection) if connection else None)
        written += 1
    output.write("\n    ],\n" if written else "],\n")
    output.write(f'    "_export": {_dump(_export_summary(state, written), "    ")}\n  }}\n}}\n')


def _write_entry(output: IO[str], text: str, messages: Iterator[dict[str, Any]] | None) -> None:
    output.write(_ENTRY_PAD)
    if messages is None:
        output.write(text)
        return
    # Stream WebSocket messages after the entry body instead of materialising them.
    output.write(text[:-1].rstrip())
    output.write(f',\n{_ENTRY_PAD}  "_webSocketMessages": [')
    count = 0
    for message in messages:
        output.write(f"{',' if count else ''}\n{_ENTRY_PAD}    {json.dumps(message, ensure_ascii=False)}")
        count += 1
    output.write(f"\n{_ENTRY_PAD}  ]\n{_ENTRY_PAD}}}" if count else f"]\n{_ENTRY_PAD}}}")


def _log_comment(limit: int) -> str:
    return (
        f"Exported by chrome-network-logger from {REQUESTS_FILE}: one entry per HTTP redirect hop, WebSocket "
        "connection and WebTransport session, sorted by start time. "
        f"Bodies are inlined up to {limit} stored bytes; a body that is larger, omitted, missing or unreadable is "
        "left out and content.comment / postData.comment says why, with _bodyPath naming the stored file when there "
        "is one. Binary bodies are base64 (content.encoding, or postData._encoding for request bodies). "
        "A size of -1 means unknown; a timing of -1 means the phase did not apply or is unknown. "
        f"Custom fields: _id (record id in {REQUESTS_FILE}), _sessionId and _target (CDP target), _resourceType "
        "(Chrome DevTools resource type), _isApi, _hop (redirect hop), _initiator, _priority, _fromCache, "
        "_failure, _incomplete/_incompleteReason (capture ended first), _responseBodyUnavailableReason (the "
        "response could not carry a body), _responseBodyError/_fetchResponseBodyError/_requestPostDataError "
        "(a body existed but could not be retrieved), _extraInfoIncomplete (raw wire headers never arrived), "
        "_realtime, response._transferSize and response._error (Chrome DevTools fields), and _webSocketMessages "
        "(Chrome DevTools format: type send/receive, time in epoch seconds, opcode, data; binary data is base64). "
        "log._export, after the entries, lists export statistics and any skipped lines."
    )


def _export_summary(state: _Export, written: int) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "source": REQUESTS_FILE,
        "entries": written,
        "skippedLines": state.skipped_count,
        "skipped": state.skipped,
        "maxInlineBodyBytes": state.limit,
        "maxWebSocketMessagesPerConnection": MAX_WEBSOCKET_MESSAGES,
        "webSocketFramesSkipped": state.frames_skipped,
        "webSocketFramesWithoutEntry": state.orphan_frames,
    }
    if state.skipped_count > len(state.skipped):
        summary["skippedListTruncated"] = True
    if state.frames_error:
        summary["webSocketFramesError"] = state.frames_error
    return summary


# --- small value helpers ---------------------------------------------------


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _int(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _ms(value: float) -> float | int:
    rounded = round(value, 3)
    return int(rounded) if rounded.is_integer() else rounded


def _epoch_ms(stamp: Any) -> float | None:
    return _number(_dict(stamp).get("epochMs"))


def _monotonic(stamp: Any) -> float | None:
    return _number(_dict(stamp).get("cdpMonotonicSeconds"))


def _elapsed_ms(start: Any, end: Any) -> float | None:
    """Milliseconds between two capture timestamps, preferring the CDP monotonic clock."""
    for read, scale in ((_monotonic, 1000.0), (_epoch_ms, 1.0)):
        first, second = read(start), read(end)
        if first is not None and second is not None and second >= first:
            return (second - first) * scale
    return None


def _iso(epoch_ms: float | None) -> str | None:
    if epoch_ms is None:
        return None
    try:
        moment = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _error_message(error: Any) -> str:
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])
    return str(error)


# --- headers, cookies, query -----------------------------------------------


def _first_headers(*candidates: Any) -> Any:
    for candidate in candidates:
        if isinstance(candidate, (dict, list)) and candidate:
            return candidate
    return None


def _har_headers(headers: Any) -> list[dict[str, str]]:
    """Convert CDP headers to HAR, splitting values that CDP joined with newlines."""
    if isinstance(headers, dict):
        pairs = list(headers.items())
    elif isinstance(headers, list):
        pairs = [(item.get("name"), item.get("value")) for item in headers if isinstance(item, dict)]
    else:
        return []
    result: list[dict[str, str]] = []
    for name, value in pairs:
        for part in ("" if value is None else str(value)).split("\n"):
            result.append({"name": str(name), "value": part})
    return result


def _header_value(headers: list[dict[str, str]], name: str) -> str | None:
    wanted = name.lower()
    for header in headers:
        if header["name"].lower() == wanted:
            return header["value"]
    return None


def _text_size(text: str | None) -> int:
    return len(text.encode("utf-8", errors="replace")) if text else -1


def _http_version(protocol: Any, headers_text: str | None, *, request_line: bool) -> str:
    name = _text(protocol)
    if name:
        return _HTTP_VERSIONS.get(name.lower(), name)
    if headers_text:
        lines = headers_text.splitlines()
        words = lines[0].split() if lines else []
        if request_line:
            candidate = words[-1] if len(words) >= 3 else ""  # "GET /path HTTP/1.1"
        else:
            candidate = words[0] if words else ""  # "HTTP/1.1 200 OK"
        if candidate.upper().startswith("HTTP/"):
            return candidate.upper()
    return ""


def _request_cookies(headers: list[dict[str, str]]) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for header in headers:
        if header["name"].lower() != "cookie":
            continue
        for pair in header["value"].split(";"):
            name, _, value = pair.strip().partition("=")
            if name.strip() or value.strip():
                cookies.append({"name": name.strip(), "value": value.strip()})
    return cookies


def _cookie_expiry(value: str) -> str | None:
    try:
        moment = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _response_cookies(headers: list[dict[str, str]]) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for header in headers:
        if header["name"].lower() != "set-cookie":
            continue
        first, *attributes = header["value"].split(";")
        name, _, value = first.partition("=")
        if not name.strip():
            continue
        cookie: dict[str, Any] = {"name": name.strip(), "value": value.strip(), "httpOnly": False, "secure": False}
        for attribute in attributes:
            key, _, setting = attribute.strip().partition("=")
            key = key.strip().lower()
            if key in {"path", "domain"}:
                cookie[key] = setting.strip()
            elif key == "expires":
                expires = _cookie_expiry(setting)
                if expires:
                    cookie["expires"] = expires
            elif key == "httponly":
                cookie["httpOnly"] = True
            elif key == "secure":
                cookie["secure"] = True
            elif key == "samesite":
                cookie["sameSite"] = setting.strip()
        cookies.append(cookie)
    return cookies


def _query_string(url: str) -> list[dict[str, str]]:
    try:
        query = urlsplit(url).query
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []
    return [{"name": name, "value": value} for name, value in pairs]


# --- bodies ----------------------------------------------------------------


def _reference_notes(reference: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if reference.get("truncated") is True:
        stored, processed = reference.get("storedBytes"), reference.get("processedBytes")
        notes.append(f"Truncated at capture time: {stored} of {processed} bytes were stored.")
    if reference.get("redacted") is True:
        notes.append("Sensitive values were redacted at capture time.")
    if reference.get("decodeError"):
        notes.append(f"Capture-time decode error: {reference['decodeError']}.")
    return notes


def _contained(state: _Export, relative: str) -> Path | None:
    try:
        candidate = (state.session_dir / relative).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate if candidate.is_relative_to(state.root) else None


def _read_reference(
    state: _Export, reference: dict[str, Any], budget: int, notes: list[str]
) -> tuple[bytes | None, bool]:
    """Load a stored body; return ``(bytes or None, whether the file itself was the problem)``."""
    if reference.get("omitted") is True:
        reason = reference.get("omittedReason") or "unknown reason"
        notes.append(f"Not stored ({reason}): {reference.get('wouldStoreBytes', '?')} bytes were never written.")
        return None, False
    relative = _text(reference.get("path"))
    if relative is None:
        notes.append("The body reference names no stored file.")
        return None, False
    stored = _int(reference.get("storedBytes"))
    if stored is not None and stored > budget:
        notes.append(f"Not inlined: {stored} bytes exceed the {state.limit}-byte HAR inline limit; see {relative}.")
        return None, False
    target = _contained(state, relative)
    if target is None:
        notes.append(f"Body path {relative!r} is outside the session directory and was not read.")
        return None, False
    compressed = reference.get("compressed")
    if not isinstance(compressed, bool):
        compressed = relative.endswith(".gz")
    try:
        # Reading at most budget + 1 bytes also bounds a corrupt or hostile gzip stream.
        with gzip.open(target, "rb") if compressed else target.open("rb") as handle:
            raw = handle.read(budget + 1)
    except FileNotFoundError:
        notes.append(f"Body file {relative} is missing.")
        return None, True
    except (OSError, EOFError, zlib.error) as exc:
        notes.append(f"Body file {relative} could not be read ({type(exc).__name__}: {exc}).")
        return None, True
    if len(raw) > budget:
        notes.append(f"Not inlined: the body exceeds the {state.limit}-byte HAR inline limit; see {relative}.")
        return None, False
    return raw, False


def _codec(name: str | None) -> str:
    try:
        codec = codecs.lookup(name or "utf-8").name
        b"".decode(codec)  # rejects bytes-to-bytes codecs such as base64_codec
    except LookupError:
        return "utf-8"
    return codec


def _decode(raw: bytes, textual: bool | None, encoding: str | None, notes: list[str]) -> tuple[str, bool]:
    """Return ``(text, is_base64)``: text bodies decoded, binary ones base64-encoded.

    ``textual`` is the capture-time verdict; ``None`` (unknown) means text only
    if the bytes decode cleanly.
    """
    if textual is not False:
        codec = _codec(encoding)
        try:
            return raw.decode(codec), False
        except UnicodeDecodeError:
            if textual is True:
                notes.append(
                    f"Some bytes were not valid {codec} and were replaced with U+FFFD; "
                    "the stored file has the exact bytes."
                )
                return raw.decode(codec, errors="replace"), False
    return base64.b64encode(raw).decode("ascii"), True


def _body_size(reference: dict[str, Any]) -> int | None:
    for key in ("originalBytes", "processedBytes", "storedBytes"):
        size = _int(reference.get(key))
        if size is not None:
            return size
    return None


def _payload(state: _Export, references: list[Any]) -> _Payload:
    """Load one body, or the concatenated parts of a multi-part request body."""
    payload = _Payload()
    chunks: list[bytes] = []
    sizes: list[int | None] = []
    flags: list[Any] = []
    encoding: str | None = None
    readable = True
    file_problem = False
    for reference in references:
        if not isinstance(reference, dict):
            readable = False
            sizes.append(None)
            payload.notes.append("A body part was not stored.")
            continue
        sizes.append(_body_size(reference))
        payload.notes.extend(_reference_notes(reference))
        raw, problem = _read_reference(state, reference, state.limit - sum(map(len, chunks)), payload.notes)
        file_problem = file_problem or problem
        if raw is None:
            readable = False
            continue
        chunks.append(raw)
        flags.append(reference.get("textual"))
        encoding = encoding or _text(reference.get("encoding"))
    if sizes and all(size is not None for size in sizes):
        payload.size = sum(size for size in sizes if size is not None)
    single = references[0] if len(references) == 1 and isinstance(references[0], dict) else None
    if single is not None:
        payload.path = _text(single.get("path"))
    if readable:
        textual = False if False in flags else (True if all(flag is True for flag in flags) else None)
        payload.text, payload.base64 = _decode(b"".join(chunks), textual, encoding, payload.notes)
    elif single is not None and file_problem and isinstance(single.get("preview"), str):
        payload.text = single["preview"]
        payload.notes.append("The text comes from the preview kept in the record.")
    return payload


def _missing_body(record: dict[str, Any], request: dict[str, Any], status: int) -> tuple[int, str]:
    reason = _text(record.get("responseBodyUnavailableReason"))
    if reason:
        return 0, f"No body: {reason}."
    resource_type = record.get("type")
    if resource_type == "WebSocket":
        return 0, "WebSocket handshake; the messages are in _webSocketMessages."
    if resource_type == "WebTransport":
        return 0, "WebTransport session; CDP exposes its lifecycle only, not its payloads."
    error = record.get("responseBodyError") or record.get("fetchResponseBodyError")
    if error:
        return -1, f"The body existed but could not be retrieved: {_error_message(error)}."
    if not status:
        return 0, "No response was received."
    if str(request.get("method") or "").upper() == "HEAD" or status in {204, 205, 304} or status in REDIRECT_CODES:
        return 0, "This response has no body."
    return -1, (
        "No body was captured for this response (not selected by the capture's body mode, or not retrievable); "
        "its size is unknown."
    )


def _response_content(
    state: _Export,
    record: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    headers: list[dict[str, str]],
    status: int,
) -> dict[str, Any]:
    reference = response.get("body")
    mime = _header_value(headers, "content-type") or _text(response.get("mimeType"))
    if not isinstance(reference, dict):
        size, reason = _missing_body(record, request, status)
        return {"size": size, "mimeType": mime or "x-unknown", "comment": reason}
    payload = _payload(state, [reference])
    mime = mime or _text(reference.get("contentType")) or "x-unknown"
    content: dict[str, Any] = {"size": payload.size, "mimeType": mime}
    if payload.text is not None:
        content["text"] = payload.text
        if payload.base64:
            content["encoding"] = "base64"
    if payload.notes:
        content["comment"] = " ".join(payload.notes)
    if payload.path:
        content["_bodyPath"] = payload.path
    return content


def _post_data(
    state: _Export, record: dict[str, Any], request: dict[str, Any], headers: list[dict[str, str]]
) -> tuple[dict[str, Any] | None, int]:
    body = request.get("body")
    parts = request.get("postDataEntries")
    mime = _header_value(headers, "content-type")
    if isinstance(body, dict):
        references: list[Any] = [body]
        mime = mime or _text(body.get("contentType"))
    elif isinstance(parts, list) and parts:
        references = [_dict(part).get("body") for part in parts]
    else:
        error = record.get("requestPostDataError")
        if request.get("hasPostData") is True or error:
            note = "The request had a body but it was not captured"
            note += f": {_error_message(error)}." if error else "."
            return {"mimeType": mime or "", "comment": note}, -1
        return None, 0
    payload = _payload(state, references)
    post: dict[str, Any] = {"mimeType": mime or ""}
    if payload.text is not None:
        post["text"] = payload.text
        if payload.base64:
            post["_encoding"] = "base64"
            payload.notes.append("Binary body: text is base64-encoded.")
    if payload.notes:
        post["comment"] = " ".join(payload.notes)
    if payload.path:
        post["_bodyPath"] = payload.path
    return post, payload.size


# --- timings ---------------------------------------------------------------


def _resource_timings(
    timing: dict[str, Any], request_time: float, issued: float | None, ended: float | None, total: float | None
) -> dict[str, Any]:
    """Map CDP ResourceTiming to contiguous HAR phases, as Chrome DevTools does."""

    def offset(name: str) -> float:
        value = _number(timing.get(name))
        return value if value is not None and value >= 0 else -1.0

    dns_start, dns_end = offset("dnsStart"), offset("dnsEnd")
    connect_start, connect_end = offset("connectStart"), offset("connectEnd")
    ssl_start, ssl_end = offset("sslStart"), offset("sslEnd")
    send_end, headers_end = offset("sendEnd"), offset("receiveHeadersEnd")
    queued = (request_time - issued) * 1000 if issued is not None and request_time >= issued else -1.0
    starts = [value for value in (dns_start, connect_start, offset("sendStart")) if value >= 0]
    network_start = min(starts) if starts else -1.0
    blocked = -1.0 if queued < 0 and network_start < 0 else max(queued, 0.0) + max(network_start, 0.0)
    result: dict[str, Any] = {
        "blocked": blocked,
        "dns": -1.0,
        "connect": -1.0,
        "ssl": -1.0,
        "send": 0.0,
        "wait": 0.0,
        "receive": 0.0,
        "_blocked_queueing": queued,
    }
    proxy_start, proxy_end = offset("proxyStart"), offset("proxyEnd")
    if 0 <= proxy_start <= proxy_end:
        result["_blocked_proxy"] = proxy_end - proxy_start
        result["blocked"] = max(blocked, proxy_end - proxy_start)
    # Each phase starts where the previous known one ended, so the phases add up to the entry time.
    cursor = max(network_start, 0.0)
    if dns_start >= 0 and dns_end >= 0:
        result["dns"] = max(0.0, dns_end - cursor)
        cursor = max(cursor, dns_end)
    if connect_start >= 0 and connect_end >= 0:
        result["connect"] = max(0.0, connect_end - cursor)
        cursor = max(cursor, connect_end)
        if 0 <= ssl_start <= ssl_end:
            result["ssl"] = ssl_end - ssl_start  # already included in connect, as HAR requires
    if send_end >= 0:
        result["send"] = max(0.0, send_end - cursor)
        cursor = max(cursor, send_end)
    if ended is not None:
        finish: float | None = (ended - request_time) * 1000
    elif total is not None:
        finish = total - max(queued, 0.0)
    else:
        finish = None
    if headers_end >= 0:
        result["wait"] = max(0.0, headers_end - cursor)
        if finish is not None:
            result["receive"] = max(0.0, finish - max(cursor, headers_end))
    elif finish is not None:
        result["wait"] = max(0.0, finish - cursor)
    return result


def _coarse_timings(
    record: dict[str, Any], response: dict[str, Any], status: int, total: float | None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "blocked": -1.0,
        "dns": -1.0,
        "connect": -1.0,
        "ssl": -1.0,
        "send": 0.0,
        "wait": 0.0,
        "receive": 0.0,
    }
    resource_type = record.get("type")
    if total is None:
        result["comment"] = "Duration unknown: the record has no usable start and end time."
    elif resource_type == "WebTransport":
        established = _elapsed_ms(record.get("started"), response.get("established"))
        if established is not None and established <= total:
            result["wait"], result["receive"] = established, total - established
            result["comment"] = "WebTransport: wait lasts until the session was established, receive is its lifetime."
        else:
            result["receive"] = total
            result["comment"] = "WebTransport: the whole session lifetime is reported as receive."
    elif resource_type == "WebSocket":
        result["receive"] = total
        result["comment"] = (
            "WebSocket: CDP exposes no handshake timing; the connection lifetime is reported as receive."
        )
    elif not status:
        result["blocked"] = total
        result["comment"] = "No response was received; the time until the failure is reported as blocked."
    else:
        result["wait"] = total
        result["comment"] = "CDP gave no ResourceTiming (memory cache, data: URL...); the whole duration is wait."
    return result


def _timings(record: dict[str, Any], response: dict[str, Any], status: int) -> tuple[dict[str, Any], float | int]:
    started, finished = record.get("started"), record.get("finished")
    total = _elapsed_ms(started, finished)
    if total is None:
        duration = _number(record.get("durationMs"))
        total = duration if duration is not None and duration >= 0 else None
    timing = _dict(response.get("timing"))
    request_time = _number(timing.get("requestTime"))
    if request_time is not None:
        result = _resource_timings(timing, request_time, _monotonic(started), _monotonic(finished), total)
    else:
        result = _coarse_timings(record, response, status, total)
    for key, value in result.items():
        if isinstance(value, float):
            result[key] = _ms(value)
    return result, _ms(float(sum(max(0, result[phase]) for phase in _TIMED_PHASES)))


# --- entries ---------------------------------------------------------------


def _entry_notes(record: dict[str, Any], state: _Export) -> list[str]:
    notes: list[str] = []
    failure = _dict(record.get("failure"))
    if failure:
        text = f"Request failed: {failure.get('errorText') or 'unknown error'}"
        if failure.get("canceled"):
            text += " (cancelled)"
        if failure.get("blockedReason"):
            text += f"; blocked: {failure['blockedReason']}"
        cors = _dict(failure.get("corsErrorStatus")).get("corsError")
        if cors:
            text += f"; CORS: {cors}"
        notes.append(text + ".")
    if record.get("incomplete"):
        reason = record.get("incompleteReason") or "unknown reason"
        notes.append(f"Incomplete: the capture ended before this request finished ({reason}).")
    if record.get("isRedirect") and record.get("redirectTo"):
        notes.append(f"Redirect hop {record.get('hop', '?')}; the request continued to {record['redirectTo']}.")
    if record.get("extraInfoIncomplete"):
        notes.append(
            "Raw wire headers (ExtraInfo) never arrived: headers come from the CDP request/response objects and may "
            "lack cookies or headers added by the network stack."
        )
    if record.get("type") == "WebSocket":
        found = state.frame_counts.get(str(record.get("id")), 0)
        declared = _int(_dict(record.get("realtime")).get("frameCount"))
        if found > MAX_WEBSOCKET_MESSAGES:
            notes.append(
                f"_webSocketMessages holds the first {MAX_WEBSOCKET_MESSAGES} of {found} frames; "
                f"all frames are in {FRAMES_FILE}."
            )
        if declared is not None and declared > found:
            notes.append(f"The capture counted {declared} frames but {FRAMES_FILE} holds {found} for this connection.")
        if state.frames_error:
            notes.append(f"{FRAMES_FILE} could not be read: {state.frames_error}.")
    return notes


def _build_entry(record: dict[str, Any], state: _Export) -> tuple[dict[str, Any], str | None]:
    """Convert one canonical record; also return the WebSocket connection id, if any."""
    request = _dict(record.get("request"))
    response = _dict(record.get("response"))
    extra = _dict(record.get("extraInfo"))
    extra_request, extra_response = _dict(extra.get("request")), _dict(extra.get("response"))
    resource_type = str(record.get("type") or "Other")

    url = _text(request.get("url")) or _text(record.get("url")) or ""
    fragment = _text(request.get("urlFragment"))
    if fragment and "#" not in url:
        url += fragment
    request_headers_text = _text(response.get("requestHeadersText"))
    request_headers = _har_headers(
        _first_headers(extra_request.get("headers"), response.get("requestHeaders"), request.get("headers"))
    )
    post_data, request_body_size = _post_data(state, record, request, request_headers)
    har_request: dict[str, Any] = {
        "method": str(request.get("method") or ""),
        "url": url,
        "httpVersion": _http_version(response.get("protocol"), request_headers_text, request_line=True),
        "cookies": _request_cookies(request_headers),
        "headers": request_headers,
        "queryString": _query_string(url),
        "headersSize": _text_size(request_headers_text),
        "bodySize": request_body_size,
    }
    if post_data is not None:
        har_request["postData"] = post_data

    status = _int(response.get("status"))
    if status is None:
        status = _int(extra_response.get("statusCode"))
    status = status or 0
    headers_text = _text(extra_response.get("headersText")) or _text(response.get("headersText"))
    response_headers = _har_headers(_first_headers(extra_response.get("headers"), response.get("headers")))
    headers_size = _text_size(headers_text)
    transfer_size = _int(record.get("encodedDataLength"))
    from_cache = (
        "disk" if response.get("fromDiskCache") is True else "memory" if record.get("servedFromCache") else None
    )
    if from_cache:
        body_size = 0
    elif transfer_size is not None and headers_size >= 0:
        body_size = max(0, transfer_size - headers_size)
    else:
        body_size = -1
    har_response: dict[str, Any] = {
        "status": status,
        "statusText": str(response.get("statusText") or ""),
        "httpVersion": _http_version(response.get("protocol"), headers_text, request_line=False),
        "cookies": _response_cookies(response_headers),
        "headers": response_headers,
        "content": _response_content(state, record, request, response, response_headers, status),
        "redirectURL": _header_value(response_headers, "location") or _text(record.get("redirectTo")) or "",
        "headersSize": headers_size,
        "bodySize": body_size,
    }
    if transfer_size is not None:
        har_response["_transferSize"] = transfer_size
    error_text = _dict(record.get("failure")).get("errorText")
    if error_text:
        har_response["_error"] = str(error_text)

    notes = _entry_notes(record, state)
    started_ms = _sort_time(record)
    started = _iso(started_ms) if started_ms != math.inf else None
    if started is None:
        started = _text(_dict(record.get("started")).get("iso")) or _EPOCH_PLACEHOLDER
        notes.append("The record has no usable start time; startedDateTime is a placeholder.")
    elif _epoch_ms(record.get("started")) is None:
        notes.append("The record has no start time; startedDateTime is its end time.")
    timings, total = _timings(record, response, status)
    entry: dict[str, Any] = {
        "startedDateTime": started,
        "time": total,
        "request": har_request,
        "response": har_response,
        "cache": {},
        "timings": timings,
    }
    address = _text(response.get("remoteIPAddress"))
    if address:
        entry["serverIPAddress"] = address.strip("[]")
    connection_id = response.get("connectionId")
    if isinstance(connection_id, (int, str)) and not isinstance(connection_id, bool) and str(connection_id) != "0":
        entry["connection"] = str(connection_id)
    if notes:
        entry["comment"] = " ".join(notes)

    entry["_id"] = record.get("id")
    entry["_sessionId"] = record.get("sessionId")
    if record.get("target") is not None:
        entry["_target"] = record["target"]
    entry["_resourceType"] = _DEVTOOLS_RESOURCE_TYPES.get(resource_type, resource_type.lower())
    entry["_isApi"] = bool(record.get("isApi"))
    if isinstance(record.get("initiator"), dict):
        entry["_initiator"] = record["initiator"]
    if _text(request.get("initialPriority")):
        entry["_priority"] = request["initialPriority"]
    if from_cache:
        entry["_fromCache"] = from_cache
    for source, target in _PASSTHROUGH_FIELDS:
        if record.get(source) is not None:
            entry[target] = record[source]
    connection = record.get("id") if resource_type == "WebSocket" and isinstance(record.get("id"), str) else None
    return entry, connection


# --- WebSocket messages ----------------------------------------------------


def _websocket_message(frame: dict[str, Any], state: _Export) -> dict[str, Any]:
    opcode = _int(frame.get("opcode"))
    sent_ms = _epoch_ms(frame.get("time"))
    message: dict[str, Any] = {
        "type": "send" if frame.get("direction") == "sent" else "receive",
        "time": sent_ms / 1000 if sent_ms is not None else None,
        "opcode": opcode,
        "data": "",
    }
    text_frame = opcode == 1
    notes: list[str] = []
    if isinstance(frame.get("payloadData"), str):
        message["data"] = frame["payloadData"]
    elif isinstance(frame.get("payloadBase64"), str):
        encoded = frame["payloadBase64"]
        if text_frame:
            try:
                message["data"] = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except ValueError:  # binascii.Error
                message["data"] = encoded
                notes.append("payloadBase64 is not valid base64; it is copied as is.")
        else:
            message["data"] = encoded
    elif isinstance(frame.get("payload"), dict):
        reference = frame["payload"]
        notes.extend(_reference_notes(reference))
        raw, _ = _read_reference(state, reference, state.limit, notes)
        if raw is not None:
            message["data"] = raw.decode("utf-8", errors="replace") if text_frame else base64.b64encode(raw).decode()
    elif frame.get("payloadOmitted"):
        notes.append(f"Payload of {frame.get('payloadBytes', '?')} bytes was not captured (body capture disabled).")
    if not text_frame and isinstance(frame.get("payloadText"), str):
        message["_text"] = frame["payloadText"]
    if notes:
        message["_comment"] = " ".join(notes)
    return message


def _websocket_messages(state: _Export, connection: str) -> Iterator[dict[str, Any]]:
    handle = state.frames_handle
    if handle is None:
        return
    for offset in state.frame_offsets.get(connection, []):
        try:
            handle.seek(offset)
            line = handle.readline()
        except OSError as exc:
            state.frames_error = f"{type(exc).__name__}: {exc}"
            return
        frame, _ = _parse_line(line)
        if not isinstance(frame, dict):
            state.frames_skipped += 1
            continue
        try:
            message = _websocket_message(frame, state)
        except Exception as exc:  # one odd frame must not abort the export
            LOG.debug("HAR export skipped a WebSocket frame of %s: %s", connection, exc)
            state.frames_skipped += 1
            continue
        yield message
