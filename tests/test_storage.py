from __future__ import annotations

import gzip
import json
from pathlib import Path

from chrome_logger.config import CaptureConfig
from chrome_logger.redaction import Redactor
from chrome_logger.storage import CaptureStore


def make_store(tmp_path: Path, mode: str = "safe", max_body: int = 1024) -> CaptureStore:
    config = CaptureConfig(
        output_parent=tmp_path,
        profile_dir=tmp_path / "profile",
        sensitive_mode=mode,
        max_body_bytes=max_body,
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


def test_interaction_report_escapes_html(tmp_path: Path) -> None:
    store = make_store(tmp_path, mode="raw")
    store.write_jsonl("interactions/events.jsonl", {"outerHTML": '<img src=x onerror="alert(1)">'})
    store.close()
    report = (store.base / "reports" / "interactions.html").read_text(encoding="utf-8")
    assert "&lt;img" in report
    assert '<img src=x onerror="alert(1)">' not in report
