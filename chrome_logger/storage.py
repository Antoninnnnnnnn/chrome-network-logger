from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import html
import json
import logging
import mimetypes
import os
import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .config import CaptureConfig
from .redaction import Redactor

LOG = logging.getLogger(__name__)
_SENTINEL = object()

_TEXT_MIME_PREFIXES = ("text/",)
_TEXT_MIMES = {
    "application/json",
    "application/ld+json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/graphql-response+json",
    "application/x-www-form-urlencoded",
    "image/svg+xml",
}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _safe_extension(content_type: str | None, textual: bool) -> str:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    overrides = {
        "application/json": ".json",
        "application/ld+json": ".json",
        "application/graphql-response+json": ".json",
        "application/javascript": ".js",
        "application/x-javascript": ".js",
        "application/xml": ".xml",
        "application/xhtml+xml": ".html",
        "image/svg+xml": ".svg",
        "text/html": ".html",
        "text/css": ".css",
        "text/plain": ".txt",
        "text/event-stream": ".txt",
    }
    if ctype in overrides:
        return overrides[ctype]
    guessed = mimetypes.guess_extension(ctype) if ctype else None
    if guessed and len(guessed) <= 10:
        return guessed
    return ".txt" if textual else ".bin"


def _is_textual(content_type: str | None, raw: bytes) -> bool:
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype.startswith(_TEXT_MIME_PREFIXES) or ctype in _TEXT_MIMES or ctype.endswith("+json") or ctype.endswith("+xml"):
        return True
    if b"\x00" in raw[:4096]:
        return False
    if not raw:
        return True
    sample = raw[:4096]
    try:
        sample.decode("utf-8")
        printable = sum((32 <= byte < 127) or byte in b"\r\n\t" for byte in sample)
        return printable / max(1, len(sample)) > 0.85
    except UnicodeDecodeError:
        return False


class CaptureStore:
    """Canonical session store with one writer thread and external body files."""

    def __init__(self, config: CaptureConfig, redactor: Redactor):
        self.config = config
        self.redactor = redactor
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        self.base = config.output_parent / f"session_{stamp}"
        self.paths = {
            "network": self.base / "network",
            "bodies": self.base / "network" / "bodies",
            "realtime": self.base / "realtime",
            "interactions": self.base / "interactions",
            "browser": self.base / "browser",
            "snapshots": self.base / "snapshots",
            "reports": self.base / "reports",
        }
        for path in self.paths.values():
            path.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=config.writer_queue_size)
        self._thread = threading.Thread(target=self._writer_loop, name="capture-writer", daemon=True)
        self._body_lock = threading.Lock()
        self._body_paths: dict[str, tuple[str, bool]] = {}
        self._manifest_lock = threading.RLock()
        self._writer_error: BaseException | None = None
        self._closed = False
        self._manifest: dict[str, Any] = {
            "schemaVersion": 3,
            "loggerVersion": __version__,
            "startedAt": _now_iso(),
            "status": "running",
            "configuration": {
                "bodyMode": config.body_mode,
                "sensitiveMode": config.sensitive_mode,
                "maxBodyBytes": config.max_body_bytes,
                "captureInteractions": config.capture_interactions,
                "captureClipboard": config.capture_clipboard,
                "captureConsole": config.capture_console,
                "captureStorage": config.capture_storage,
            },
            "warnings": [],
        }
        self._write_manifest_atomic()
        self._thread.start()

    def relative(self, path: Path) -> str:
        return path.relative_to(self.base).as_posix()

    def set_manifest(self, **fields: Any) -> None:
        with self._manifest_lock:
            self._manifest.update(fields)
            self._write_manifest_atomic()

    def add_warning(self, warning: str) -> None:
        with self._manifest_lock:
            warnings = self._manifest.setdefault("warnings", [])
            if warning not in warnings:
                warnings.append(warning)
                self._write_manifest_atomic()

    def _write_manifest_atomic(self) -> None:
        target = self.base / "manifest.json"
        temp = target.with_suffix(".json.tmp")
        temp.write_text(json.dumps(self._manifest, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(temp, target)

    def write_jsonl(self, relative_path: str, payload: dict[str, Any], *, redact: bool = False) -> None:
        data = self.redactor.object(payload) if redact else payload
        line = json.dumps(data, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
        self._put(("append_text", relative_path, line))

    def write_json(self, relative_path: str, payload: Any, *, redact: bool = False) -> None:
        data = self.redactor.object(payload) if redact else payload
        text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        self._put(("write_text", relative_path, text))

    def timeline(self, kind: str, timestamp: dict[str, Any], **payload: Any) -> None:
        event = {"kind": kind, "time": timestamp, **payload}
        self.write_jsonl("timeline.jsonl", event, redact=True)

    def store_body(
        self,
        body: str | bytes | None,
        *,
        base64_encoded: bool = False,
        content_type: str | None = None,
        role: str = "response",
    ) -> dict[str, Any] | None:
        if body is None:
            return None
        decode_error: str | None = None
        if isinstance(body, bytes):
            raw = body
        elif base64_encoded:
            try:
                raw = base64.b64decode(body, validate=False)
            except Exception as exc:
                raw = body.encode("utf-8", errors="replace")
                decode_error = f"base64 decode failed: {exc}"
        else:
            raw = body.encode("utf-8", errors="replace")

        original_size = len(raw)
        textual = _is_textual(content_type, raw)
        redacted = False
        if textual and self.redactor.enabled:
            text = raw.decode("utf-8", errors="replace")
            clean = self.redactor.body_text(text, content_type)
            raw = clean.encode("utf-8")
            redacted = clean != text

        processed_size = len(raw)
        digest = hashlib.sha256(raw).hexdigest()
        truncated = False
        if self.config.max_body_bytes and processed_size > self.config.max_body_bytes:
            raw = raw[: self.config.max_body_bytes]
            truncated = True
        stored_digest = hashlib.sha256(raw).hexdigest()
        ext = _safe_extension(content_type, textual)
        compress = textual and self.config.compress_text_bodies
        filename = f"{digest}{ext}{'.gz' if compress else ''}"
        relative_path = f"network/bodies/{filename}"
        with self._body_lock:
            existing = self._body_paths.get(digest)
            if existing is None:
                self._body_paths[digest] = (relative_path, compress)
                self._put(("write_body", relative_path, raw, compress))
            else:
                relative_path, compress = existing

        result: dict[str, Any] = {
            "path": relative_path,
            "sha256": digest,
            "storedSha256": stored_digest,
            "storedBytes": len(raw),
            "originalBytes": original_size,
            "processedBytes": processed_size,
            "contentType": content_type,
            "textual": textual,
            "compressed": compress,
            "truncated": truncated,
            "redacted": redacted,
            "role": role,
        }
        if decode_error:
            result["decodeError"] = decode_error
        if textual and len(raw) <= self.config.body_inline_limit:
            result["preview"] = raw.decode("utf-8", errors="replace")
        return result

    def _put(self, task: Any) -> None:
        if self._closed:
            raise RuntimeError("CaptureStore is closed")
        if self._writer_error:
            raise RuntimeError("Capture writer failed") from self._writer_error
        self._queue.put(task)

    def _writer_loop(self) -> None:
        handles: dict[str, Any] = {}
        try:
            while True:
                task = self._queue.get()
                try:
                    if task is _SENTINEL:
                        return
                    kind, relative_path, *args = task
                    target = self.base / relative_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if kind == "append_text":
                        handle = handles.get(relative_path)
                        if handle is None:
                            handle = open(target, "a", encoding="utf-8", buffering=1)
                            handles[relative_path] = handle
                        handle.write(args[0])
                    elif kind == "write_text":
                        temp = target.with_name(target.name + ".tmp")
                        temp.write_text(args[0], encoding="utf-8")
                        os.replace(temp, target)
                    elif kind == "write_body":
                        raw, compress = args
                        if not target.exists():
                            temp = target.with_name(target.name + ".tmp")
                            if compress:
                                with gzip.open(temp, "wb", compresslevel=6) as file:
                                    file.write(raw)
                            else:
                                temp.write_bytes(raw)
                            os.replace(temp, target)
                    else:
                        raise ValueError(f"Unknown writer task: {kind}")
                finally:
                    self._queue.task_done()
        except BaseException as exc:  # keep the error for the producer thread
            self._writer_error = exc
            LOG.exception("Capture writer failed")
            while True:
                try:
                    pending = self._queue.get_nowait()
                except queue.Empty:
                    break
                else:
                    self._queue.task_done()
                    if pending is _SENTINEL:
                        break
        finally:
            for handle in handles.values():
                try:
                    handle.flush()
                    handle.close()
                except Exception:
                    pass

    def flush(self) -> None:
        self._queue.join()
        if self._writer_error:
            raise RuntimeError("Capture writer failed") from self._writer_error

    def generate_reports(self) -> None:
        self.flush()
        source = self.base / "network" / "requests.jsonl"
        summary = self.base / "reports" / "summary.txt"
        csv_path = self.base / "reports" / "requests.csv"
        counts: dict[str, int] = {}
        total = 0
        api_total = 0
        failures = 0
        with open(summary, "w", encoding="utf-8") as summary_file, open(
            csv_path, "w", encoding="utf-8", newline=""
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["id", "type", "method", "status", "is_api", "failed", "url", "response_body"],
            )
            writer.writeheader()
            if source.exists():
                with open(source, encoding="utf-8") as input_file:
                    for line in input_file:
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        total += 1
                        resource_type = str(entry.get("type") or "Other")
                        counts[resource_type] = counts.get(resource_type, 0) + 1
                        is_api = bool(entry.get("isApi"))
                        api_total += int(is_api)
                        failed = bool(entry.get("failure"))
                        failures += int(failed)
                        request = entry.get("request") or {}
                        response = entry.get("response") or {}
                        method = request.get("method") or ("WS" if resource_type == "WebSocket" else "?")
                        url = request.get("url") or entry.get("url") or "?"
                        status = response.get("status", "—")
                        body_path = ((response.get("body") or {}).get("path")) or ""
                        summary_file.write(
                            f"[{resource_type:>12}] {str(method):7} {str(status):>4} "
                            f"{'API' if is_api else '   '} {'FAIL' if failed else '    '} {url}\n"
                        )
                        writer.writerow(
                            {
                                "id": entry.get("id"),
                                "type": resource_type,
                                "method": method,
                                "status": status,
                                "is_api": is_api,
                                "failed": failed,
                                "url": url,
                                "response_body": body_path,
                            }
                        )
        stats_lines = [
            "Chrome Network Logger v3",
            "========================",
            f"Requests: {total}",
            f"API-classified: {api_total}",
            f"Failures: {failures}",
            "",
            "By resource type:",
        ]
        stats_lines.extend(f"  {key}: {value}" for key, value in sorted(counts.items()))
        (self.base / "reports" / "stats.txt").write_text("\n".join(stats_lines) + "\n", encoding="utf-8")
        self._generate_interactions_html()

    def _generate_interactions_html(self) -> None:
        source = self.base / "interactions" / "events.jsonl"
        if not source.exists():
            return
        target = self.base / "reports" / "interactions.html"
        with open(target, "w", encoding="utf-8") as report:
            report.write(
                "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>Interaction report</title>"
                "<style>body{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem}"
                "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f5f5;padding:1rem}"
                "details{margin:.5rem 0}</style></head><body><h1>Interaction report</h1>\n"
            )
            with open(source, encoding="utf-8") as file:
                for index, line in enumerate(file):
                    if index >= 10_000:
                        report.write("<p>Report truncated after 10,000 events.</p>\n")
                        break
                    try:
                        value = json.loads(line)
                        pretty = json.dumps(value, indent=2, ensure_ascii=False)
                    except Exception:
                        pretty = line
                    report.write(
                        f"<details><summary>Event {index + 1}</summary>"
                        f"<pre>{html.escape(pretty)}</pre></details>\n"
                    )
            report.write("</body></html>\n")

    def close(self, *, status: str = "complete", stats: dict[str, Any] | None = None) -> None:
        if self._closed:
            return
        try:
            self.flush()
            self.generate_reports()
        finally:
            with self._manifest_lock:
                self._manifest["endedAt"] = _now_iso()
                self._manifest["status"] = status
                if stats is not None:
                    self._manifest["stats"] = stats
                self._write_manifest_atomic()
            self._closed = True
            self._queue.put(_SENTINEL)
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                LOG.error("Writer thread did not stop cleanly")
