"""Writer backpressure, Windows replace retries, bounded warnings and the session index."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from chrome_logger import fileio
from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor
from chrome_logger.session_index import render_session_index
from chrome_logger.storage import CaptureStore


def make_store(tmp_path: Path, **overrides) -> CaptureStore:
    config = CaptureConfig(output_parent=tmp_path, profile_dir=tmp_path / "profile", **overrides)
    return CaptureStore(config, Redactor(config.sensitive_mode))


def test_replace_retries_transient_sharing_violations(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "a.tmp"
    target = tmp_path / "a.json"
    source.write_text("new", encoding="utf-8")
    real_replace = fileio.os.replace
    attempts = {"count": 0}

    def flaky_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise PermissionError("[WinError 5] Access is denied")
        real_replace(src, dst)

    monkeypatch.setattr(fileio.os, "replace", flaky_replace)
    monkeypatch.setattr(fileio.time, "sleep", lambda _seconds: None)
    fileio.replace_with_retry(source, target)
    assert target.read_text(encoding="utf-8") == "new"
    assert attempts["count"] == 3


def test_replace_gives_up_after_the_last_attempt(monkeypatch, tmp_path: Path) -> None:
    def always_denied(_src, _dst):
        raise PermissionError("denied")

    monkeypatch.setattr(fileio.os, "replace", always_denied)
    monkeypatch.setattr(fileio.time, "sleep", lambda _seconds: None)
    with pytest.raises(PermissionError):
        fileio.replace_with_retry(tmp_path / "a", tmp_path / "b", attempts=3)


def test_manifest_warnings_are_capped_and_counted(tmp_path: Path) -> None:
    store = make_store(tmp_path, max_manifest_warnings=3)
    for index in range(10):
        store.add_warning(f"warning {index}")
    store.add_warning("warning 0")
    store.close()
    manifest = json.loads((store.base / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["warnings"] == ["warning 0", "warning 1", "warning 2"]
    assert manifest["warningsSuppressed"] == 7


def test_writer_queue_is_bounded_in_bytes(tmp_path: Path) -> None:
    store = make_store(tmp_path, writer_queue_max_bytes=1024 * 1024)
    with store._bytes_condition:
        store._queued_bytes = 900 * 1024  # 900 KiB already waiting for the disk

    finished = threading.Event()

    def producer() -> None:
        store.write_jsonl("network/block.jsonl", {"blob": "x" * (300 * 1024)})
        finished.set()

    threading.Thread(target=producer, daemon=True).start()
    time.sleep(0.3)
    assert not finished.is_set(), "a write beyond the byte budget must wait for the writer"
    store._release_task_bytes(("append_text", "x", "y" * (900 * 1024)))
    assert finished.wait(2)
    store.close()
    assert (store.base / "network" / "block.jsonl").exists()
    assert store._queued_bytes == 0


def test_close_writes_an_index_and_a_file_inventory(tmp_path: Path) -> None:
    store = make_store(tmp_path, compress_text_bodies=True)
    store.write_jsonl(
        "network/requests.jsonl",
        {"id": "s::1::hop0", "type": "XHR", "isApi": True, "request": {"method": "GET", "url": "https://a.test/"}},
    )
    store.store_body('{"ok":true}', content_type="application/json")
    store.add_warning("Something to know")
    store.close(status="partial", stats={"requests": 1, "incompleteDetached": 2}, reason="chromeExited")

    manifest = json.loads((store.base / "manifest.json").read_text(encoding="utf-8"))
    inventory = {item["path"]: item for item in manifest["files"]}
    assert inventory["network/requests.jsonl"]["records"] == 1
    assert inventory["network/bodies/"]["files"] == 1
    assert "reports/summary.txt" in inventory

    index = (store.base / "INDEX.md").read_text(encoding="utf-8")
    assert "`partial`" in index
    assert "the browser window was closed" in index
    assert "Something to know" in index
    assert "| `network/requests.jsonl` |" in index
    assert "gzip" in index
    assert "Requests cut off because their tab/iframe/worker closed | 2 |" in index


def test_index_explains_redaction_only_in_safe_mode() -> None:
    raw = render_session_index({"status": "complete", "configuration": {"sensitiveMode": "raw"}}, "session_x")
    safe = render_session_index({"status": "complete", "configuration": {"sensitiveMode": "safe"}}, "session_x")
    assert "clear text" in raw and "<redacted" not in raw
    assert "<redacted len=N hmac=XXXX>" in safe
