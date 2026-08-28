from __future__ import annotations

from pathlib import Path

from chrome_logger import chrome as chrome_module
from chrome_logger.chrome import ChromeProcess


class ExitedProcess:
    pid = 123

    def poll(self):
        return 0


def test_terminate_cleans_profile_children_even_if_launcher_already_exited(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda path: calls.append(path) or 1)
    chrome = ChromeProcess(process=ExitedProcess(), port=9222, profile_dir=tmp_path)
    chrome.terminate()
    assert calls == [tmp_path]
