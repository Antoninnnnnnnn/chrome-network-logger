from __future__ import annotations

import csv
import gzip
import json
import time
from pathlib import Path

import pytest

from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor
from chrome_logger.storage import CaptureStore


def make_store(
    tmp_path: Path,
    mode: str = "safe",
    max_body: int = 1024,
    max_session_body: int = 2 * 1024 * 1024 * 1024,
) -> CaptureStore:
    config = CaptureConfig(
        output_parent=tmp_path,
        profile_dir=tmp_path / "profile",
        sensitive_mode=mode,
        max_body_bytes=max_body,
        max_session_body_bytes=max_session_body,
    )
    return CaptureStore(config, Redactor(mode))


def test_body_is_redacted_externalized_and_deduplicated(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    first = store.store_body('{"password":"secret","value":1}', content_type="application/json")
    second = store.store_body('{"password":"secret","value":1}', content_type="application/json")
    assert first is not None and second is not None
    assert first["path"] == second["path"]
    store.close()
    body_path = store.base / first["path"]
    with gzip.open(body_path, "rt", encoding="utf-8") as file:
        parsed = json.load(file)
    assert parsed["value"] == 1
    assert "secret" not in parsed["password"]


def test_body_truncation_is_recorded(tmp_path: Path) -> None:
    store = make_store(tmp_path, mode="raw", max_body=4)
    ref = store.store_body("abcdefgh", content_type="text/plain")
    assert ref is not None
    assert ref["truncated"] is True
    assert ref["storedBytes"] == 4
    assert ref["originalBytes"] == 8
    store.close()


def test_session_body_limit_omits_later_unique_bodies(tmp_path: Path) -> None:
    store = make_store(tmp_path, mode="raw", max_body=0, max_session_body=5)
    first = store.store_body(b"12345", content_type="application/octet-stream")
    second = store.store_body(b"67890", content_type="application/octet-stream")
    assert first is not None and second is not None
    assert "path" in first
    assert "path" not in second
    assert second["storedBytes"] == 0
    assert second["wouldStoreBytes"] == 5
    assert second["omittedReason"] == "sessionBodyLimit"
    store.close()
    manifest = json.loads((store.base / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["bodyStorage"] == {
        "uniqueBodies": 1,
        "storedBytes": 5,
        "omittedBodies": 1,
        "omittedBytes": 5,
    }


def test_safe_redaction_preserves_declared_latin1_encoding(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    body = "password=très-secret".encode("iso-8859-1")
    ref = store.store_body(body, content_type="text/plain; charset=iso-8859-1")
    assert ref is not None
    assert ref["encoding"] == "iso8859-1"
    store.close()
    with gzip.open(store.base / ref["path"], "rt", encoding="iso-8859-1") as file:
        saved = file.read()
    assert "très-secret" not in saved
    assert "redacted" in saved


def test_interaction_report_escapes_html(tmp_path: Path) -> None:
    store = make_store(tmp_path, mode="raw")
    store.write_jsonl("interactions/events.jsonl", {"outerHTML": '<img src=x onerror="alert(1)">'})
    store.close()
    report = (store.base / "reports" / "interactions.html").read_text(encoding="utf-8")
    assert "&lt;img" in report
    assert '<img src=x onerror="alert(1)">' not in report


def test_session_names_are_unique_even_when_created_immediately(tmp_path: Path) -> None:
    first = make_store(tmp_path)
    second = make_store(tmp_path)
    assert first.base != second.base
    first.close()
    second.close()


def test_csv_report_neutralizes_formula_cells(tmp_path: Path) -> None:
    store = make_store(tmp_path, mode="raw")
    store.write_jsonl(
        "network/requests.jsonl",
        {
            "id": "1",
            "type": "Document",
            "request": {"method": "GET", "url": '=HYPERLINK("https://example.test")'},
            "response": {"status": 200},
        },
    )
    store.close()
    with (store.base / "reports" / "requests.csv").open(encoding="utf-8", newline="") as file:
        row = next(csv.DictReader(file))
    assert row["url"].startswith("'=")


def test_writer_failure_is_reported_without_flush_deadlock(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store._put(("unknown-task", "broken.txt", "payload"))
    deadline = time.monotonic() + 2
    while store._writer_error is None and time.monotonic() < deadline:
        time.sleep(0.01)
    with pytest.raises(RuntimeError, match="Capture writer failed"):
        store.check_health()
    with pytest.raises(RuntimeError, match="Capture finalization failed"):
        store.close()
    manifest = json.loads((store.base / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "error"
    assert manifest["writer"]["error"]
