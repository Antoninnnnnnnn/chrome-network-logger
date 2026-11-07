"""Profile process matching, parallel cleanup and clean browser shutdown."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from chrome_logger import chrome as chrome_module
from chrome_logger.chrome import ChromeProcess, user_data_dir_argument, uses_profile


def test_profile_match_is_exact_not_a_substring(tmp_path: Path) -> None:
    wanted = tmp_path / "profiles" / "a"
    assert uses_profile(["chrome", f"--user-data-dir={wanted}"], wanted)
    assert uses_profile(["chrome", "--user-data-dir", str(wanted)], wanted)
    assert uses_profile(["chrome", f'--user-data-dir="{wanted}"'], wanted)
    assert uses_profile(["chrome", f"--user-data-dir={wanted}{chrome_module.os.sep}"], wanted)
    assert not uses_profile(["chrome", f"--user-data-dir={tmp_path / 'profiles' / 'ab'}"], wanted)
    assert not uses_profile(["chrome", f"--disk-cache-dir={wanted}"], wanted)
    assert not uses_profile(None, wanted)


def test_user_data_dir_argument_handles_missing_values() -> None:
    assert user_data_dir_argument(["chrome", "--user-data-dir"]) is None
    assert user_data_dir_argument([]) is None


class FakePsProcess:
    def __init__(self, pid: int, cmdline: list[str], name: str = "chrome.exe") -> None:
        self.pid = pid
        self.info = {"pid": pid, "name": name, "cmdline": cmdline}
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_cleanup_terminates_all_matches_then_waits_once(monkeypatch, tmp_path: Path) -> None:
    profile = tmp_path / "capture_profile"
    ours = [FakePsProcess(index, ["chrome", f"--user-data-dir={profile}"]) for index in range(3)]
    other = FakePsProcess(99, ["chrome", f"--user-data-dir={profile}2"])
    unrelated = FakePsProcess(100, ["python", f"--user-data-dir={profile}"], name="python.exe")
    waits: list[tuple[int, float]] = []

    def fake_wait_procs(processes: list[Any], timeout: float):
        waits.append((len(processes), timeout))
        if len(waits) == 1:
            return processes[:2], processes[2:]
        return processes, []

    monkeypatch.setattr(chrome_module.psutil, "process_iter", lambda _attrs: iter([*ours, other, unrelated]))
    monkeypatch.setattr(chrome_module.psutil, "wait_procs", fake_wait_procs)

    assert chrome_module.kill_profile_chrome_processes(profile) == 3
    assert all(process.terminated for process in ours)
    assert not other.terminated and not unrelated.terminated
    assert [process.killed for process in ours] == [False, False, True]
    assert waits == [(3, 3.0), (1, 2)]


class ClosingProcess:
    pid = 4242

    def __init__(self, exits_on_close: bool) -> None:
        self.exits_on_close = exits_on_close
        self.closed = False
        self.terminated = False
        self.killed = False

    def poll(self):
        return 0 if (self.closed and self.exits_on_close) or self.terminated or self.killed else None

    def wait(self, timeout: float | None = None):
        if self.poll() is None:
            raise subprocess.TimeoutExpired("chrome", timeout or 0)
        return 0

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_terminate_asks_chrome_to_close_cleanly_first(monkeypatch, tmp_path: Path) -> None:
    process = ClosingProcess(exits_on_close=True)

    def fake_close(port: int, timeout: float = 2.0) -> bool:
        assert port == 9333
        process.closed = True
        return True

    monkeypatch.setattr(chrome_module, "request_browser_close", fake_close)
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda _path: 0)
    ChromeProcess(process=process, port=9333, profile_dir=tmp_path).terminate(timeout=0.1)  # type: ignore[arg-type]
    assert process.closed and not process.terminated and not process.killed


def test_terminate_falls_back_when_browser_close_fails(monkeypatch, tmp_path: Path) -> None:
    process = ClosingProcess(exits_on_close=False)
    monkeypatch.setattr(chrome_module, "request_browser_close", lambda _port, timeout=2.0: False)
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda _path: 0)
    monkeypatch.setattr(chrome_module.os, "killpg", lambda _pid, _sig: process.terminate(), raising=False)
    ChromeProcess(process=process, port=9333, profile_dir=tmp_path).terminate(timeout=0.1)  # type: ignore[arg-type]
    assert process.terminated


def test_a_browser_the_user_closed_is_not_asked_to_close_again(monkeypatch, tmp_path: Path) -> None:
    process = ClosingProcess(exits_on_close=False)
    process.closed = True  # the user closed the window; Chrome exits on its own
    process.exits_on_close = True
    asked: list[int] = []
    monkeypatch.setattr(chrome_module, "request_browser_close", lambda port, timeout=2.0: asked.append(port) or True)
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda _path: 0)
    ChromeProcess(process=process, port=9333, profile_dir=tmp_path).terminate(already_closing=True)  # type: ignore[arg-type]
    assert asked == [] and not process.terminated and not process.killed


def test_a_browser_stuck_while_closing_is_still_stopped(monkeypatch, tmp_path: Path) -> None:
    process = ClosingProcess(exits_on_close=False)
    monkeypatch.setattr(chrome_module, "CLOSING_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(chrome_module, "request_browser_close", lambda _port, timeout=2.0: True)
    monkeypatch.setattr(chrome_module, "kill_profile_chrome_processes", lambda _path: 0)
    monkeypatch.setattr(chrome_module.os, "killpg", lambda _pid, _sig: process.terminate(), raising=False)
    ChromeProcess(process=process, port=9333, profile_dir=tmp_path).terminate(already_closing=True)  # type: ignore[arg-type]
    assert process.terminated


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed = False

    def send(self, payload: str) -> None:
        self.sent.append(payload)

    def recv(self) -> str:
        return '{"id":1,"result":{}}'

    def close(self) -> None:
        self.closed = True


def test_browser_close_uses_only_the_loopback_endpoint(monkeypatch) -> None:
    connection = FakeConnection()
    opened: list[str] = []

    def fake_create_connection(url: str, **_kwargs: Any) -> FakeConnection:
        opened.append(url)
        return connection

    monkeypatch.setattr(chrome_module.websocket, "create_connection", fake_create_connection)
    monkeypatch.setattr(
        chrome_module,
        "fetch_json",
        lambda port, path, timeout=3: {"webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/browser/x"},
    )
    assert chrome_module.request_browser_close(9555) is True
    assert opened == ["ws://127.0.0.1:9555/devtools/browser/x"]
    assert '"Browser.close"' in connection.sent[0]
    assert connection.closed

    monkeypatch.setattr(
        chrome_module,
        "fetch_json",
        lambda port, path, timeout=3: {"webSocketDebuggerUrl": "ws://evil.example.test:9555/devtools/browser/x"},
    )
    assert chrome_module.request_browser_close(9555) is False
    assert len(opened) == 1
