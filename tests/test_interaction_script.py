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
