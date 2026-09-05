from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from chrome_logger.cdp import CDPCapture
from chrome_logger.config import CaptureConfig


class DummyStore:
    pass


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_injected_interaction_script_has_valid_javascript_syntax(tmp_path: Path) -> None:
    capture = CDPCapture(9222, CaptureConfig(tmp_path, tmp_path / "profile"), DummyStore())
    script = tmp_path / "interactions.js"
    script.write_text(capture._interaction_script(), encoding="utf-8")
    subprocess.run([shutil.which("node") or "node", "--check", str(script)], check=True, capture_output=True, text=True)


def test_safe_interaction_script_never_serializes_raw_outer_html_or_form_values(tmp_path: Path) -> None:
    capture = CDPCapture(9222, CaptureConfig(tmp_path, tmp_path / "profile"), DummyStore())
    script = capture._interaction_script()
    assert 'outerHTML = `<${el.tagName.toLowerCase()} data-capture-redacted="true">`' in script
    assert "SAFE && !(value instanceof File) ? redact(normalized)" in script
    assert "isFormControl(el)) ? redact(value)" in script


def test_injected_script_flushes_storage_before_a_page_disappears(tmp_path: Path) -> None:
    capture = CDPCapture(9222, CaptureConfig(tmp_path, tmp_path / "profile"), DummyStore())
    script = capture._interaction_script()
    for trigger in ("pagehide", "freeze", "unload", "beforeunload"):
        assert f"flushState('{trigger}')" in script
    assert "document.visibilityState === 'hidden'" in script
    assert "event: 'storage_state'" in script
    # Safe mode must not ship raw cookie values out of the page.
    assert "if (!SAFE) return raw;" in script
