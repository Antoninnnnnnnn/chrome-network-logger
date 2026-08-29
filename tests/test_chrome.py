from __future__ import annotations

from pathlib import Path

import pytest

from chrome_logger import chrome as chrome_module
from chrome_logger.chrome import ChromeProcess, fetch_json, wait_for_cdp


class ExitedProcess:
    pid = 123

    def poll(self):
        return 0


class RunningProcess:
    pid = 456

    def poll(self):
        return None


def test_terminate_cleans_profile_children_even_if_launcher_already_exited(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda path: calls.append(path) or 1)
    chrome = ChromeProcess(process=ExitedProcess(), port=9222, profile_dir=tmp_path)
    chrome.terminate()
    assert calls == [tmp_path]


def test_wait_for_cdp_reads_chromes_atomically_selected_port(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "DevToolsActivePort").write_text("45678\n/devtools/browser/test\n", encoding="utf-8")
    requested: list[tuple[int, str, float]] = []

    def fake_fetch_json(port: int, path: str, *, timeout: float):
        requested.append((port, path, timeout))
        return {"Browser": "Chrome/Test"}

    monkeypatch.setattr(chrome_module, "fetch_json", fake_fetch_json)
    chrome = ChromeProcess(process=RunningProcess(), port=0, profile_dir=tmp_path)
    version = wait_for_cdp(chrome, timeout=1)
    assert chrome.port == 45678
    assert version["Browser"] == "Chrome/Test"
    assert requested == [(45678, "/json/version", 1)]


def test_fetch_json_rejects_non_local_paths_and_invalid_ports() -> None:
    for port, path in ((0, "/json"), (65536, "/json"), (9222, "http://example.test"), (9222, "//host/json")):
        with pytest.raises(ValueError):
            fetch_json(port, path)
