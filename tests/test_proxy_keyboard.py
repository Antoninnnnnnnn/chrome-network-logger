from __future__ import annotations

import io
import os
import sys
import threading
import time
import types

import pytest

from chrome_logger import proxy as proxy_module
from chrome_logger.proxy import start_toggle_keyboard

ORIGINAL_ATTRS = ["original-terminal-settings"]


class FakeRelay:
    def __init__(self) -> None:
        self.enabled = True
        self.toggles = 0

    def toggle(self) -> bool:
        self.enabled = not self.enabled
        self.toggles += 1
        return self.enabled


class FakeTerminal:
    """Stands in for termios, tty, atexit and stdin so the POSIX path runs on every OS."""

    def __init__(self) -> None:
        self.cbreak_calls: list[int] = []
        self.restores: list[tuple[int, int, list[str]]] = []
        self.registered: list = []
        self.unregistered: list = []
        self.cbreak_error: Exception | None = None

        class TermiosError(Exception):
            pass

        self.termios = types.SimpleNamespace(
            TCSANOW=0,
            TCSADRAIN=1,
            TCSAFLUSH=2,
            error=TermiosError,
            tcgetattr=lambda fd: list(ORIGINAL_ATTRS),
            tcsetattr=lambda fd, when, attrs: self.restores.append((fd, when, attrs)),
        )
        self.tty = types.SimpleNamespace(setcbreak=self._setcbreak)
        self.atexit = types.SimpleNamespace(register=self.registered.append, unregister=self.unregistered.append)

    def _setcbreak(self, fd: int) -> None:
        if self.cbreak_error is not None:
            raise self.cbreak_error
        self.cbreak_calls.append(fd)


class FakeTTYStdin:
    def __init__(self, fd: int = 42) -> None:
        self.fd = fd

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return self.fd


class ScriptedReader:
    """Replaces _PosixKeyReader: returns scripted chunks, then idles like a quiet terminal."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.fd: int | None = None
        self.closed = False
        self.idle_reads = 0  # > 0 once every scripted chunk has been fully handled by the loop

    def __call__(self, fd: int) -> ScriptedReader:
        self.fd = fd
        return self

    def read(self, timeout: float) -> bytes | None:
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        self.idle_reads += 1
        time.sleep(min(timeout, 0.01))
        return None

    def close(self) -> None:
        self.closed = True


def wait_for(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.01)


@pytest.fixture
def terminal(monkeypatch) -> FakeTerminal:
    fake = FakeTerminal()
    monkeypatch.setitem(sys.modules, "termios", fake.termios)
    monkeypatch.setitem(sys.modules, "tty", fake.tty)
    monkeypatch.setattr(proxy_module, "atexit", fake.atexit)
    monkeypatch.setattr(proxy_module, "_owns_terminal", lambda fd: True)
    monkeypatch.setattr(proxy_module.sys, "stdin", FakeTTYStdin())
    return fake


def start_posix(monkeypatch, script: list, on_toggle=None):
    reader = ScriptedReader(script)
    monkeypatch.setattr(proxy_module, "_PosixKeyReader", reader)
    relay = FakeRelay()
    stop = threading.Event()
    thread = proxy_module._start_posix_toggle(relay, stop, on_toggle)
    return thread, relay, stop, reader


def test_posix_toggle_is_not_started_without_a_tty(monkeypatch, terminal: FakeTerminal) -> None:
    monkeypatch.setattr(proxy_module.sys, "stdin", io.StringIO())
    thread, _, _, _ = start_posix(monkeypatch, [])
    assert thread is None
    assert terminal.cbreak_calls == []
    assert terminal.registered == []


def test_posix_toggle_is_not_started_without_stdin(monkeypatch, terminal: FakeTerminal) -> None:
    monkeypatch.setattr(proxy_module.sys, "stdin", None)
    thread, _, _, _ = start_posix(monkeypatch, [])
    assert thread is None
    assert terminal.cbreak_calls == []


def test_posix_toggle_leaves_background_jobs_alone(monkeypatch, terminal: FakeTerminal) -> None:
    monkeypatch.setattr(proxy_module, "_owns_terminal", lambda fd: False)
    thread, _, _, _ = start_posix(monkeypatch, [])
    assert thread is None
    assert terminal.cbreak_calls == []


@pytest.mark.skipif(os.name == "nt", reason="Windows uses the msvcrt console path")
def test_start_toggle_keyboard_returns_none_when_stdin_is_not_a_tty(monkeypatch) -> None:
    monkeypatch.setattr(proxy_module.sys, "stdin", io.StringIO())
    assert start_toggle_keyboard(FakeRelay(), threading.Event()) is None


def test_posix_toggle_flips_on_p_and_restores_the_terminal(monkeypatch, terminal: FakeTerminal) -> None:
    states: list[bool] = []
    script = [b"p", b"\x1bOP", b"x", b"P"]  # F1 arrives as ESC O P and must not count as a P keypress
    thread, relay, stop, reader = start_posix(monkeypatch, script, on_toggle=states.append)
    assert thread is not None
    assert thread.daemon
    assert terminal.cbreak_calls == [42]
    assert reader.fd == 42
    wait_for(lambda: reader.idle_reads > 0)
    assert relay.toggles == 2
    assert states == [False, True]
    assert terminal.restores == []  # still in cbreak mode while the loop runs

    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert reader.closed
    assert terminal.restores == [(42, terminal.termios.TCSADRAIN, ORIGINAL_ATTRS)]
    assert len(terminal.registered) == 1
    assert terminal.unregistered == terminal.registered


@pytest.mark.parametrize("ending", [b"", OSError("terminal hung up")], ids=["eof", "read-error"])
def test_posix_toggle_restores_the_terminal_when_input_ends(monkeypatch, terminal: FakeTerminal, ending) -> None:
    thread, relay, _, reader = start_posix(monkeypatch, [ending])
    assert thread is not None
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert relay.toggles == 0
    assert reader.closed
    assert terminal.restores == [(42, terminal.termios.TCSADRAIN, ORIGINAL_ATTRS)]


def test_posix_toggle_keeps_running_when_the_callback_fails(monkeypatch, terminal: FakeTerminal) -> None:
    def broken(_enabled: bool) -> None:
        raise RuntimeError("callback failed")

    thread, relay, stop, reader = start_posix(monkeypatch, [b"p", b"p"], on_toggle=broken)
    assert thread is not None
    wait_for(lambda: reader.idle_reads > 0)
    assert relay.toggles == 2
    assert thread.is_alive()
    stop.set()
    thread.join(timeout=2)
    assert terminal.restores == [(42, terminal.termios.TCSADRAIN, ORIGINAL_ATTRS)]


def test_posix_atexit_safety_net_restores_exactly_once(monkeypatch, terminal: FakeTerminal) -> None:
    thread, _, stop, _ = start_posix(monkeypatch, [])
    assert thread is not None
    (safety_net,) = terminal.registered
    safety_net()  # interpreter exit while the daemon thread is still polling
    assert terminal.restores == [(42, terminal.termios.TCSADRAIN, ORIGINAL_ATTRS)]
    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert len(terminal.restores) == 1


def test_posix_toggle_restores_the_terminal_when_cbreak_fails(monkeypatch, terminal: FakeTerminal) -> None:
    terminal.cbreak_error = terminal.termios.error("not a terminal")
    thread, _, _, _ = start_posix(monkeypatch, [])
    assert thread is None
    assert terminal.restores == [(42, terminal.termios.TCSADRAIN, ORIGINAL_ATTRS)]
    assert terminal.unregistered == terminal.registered


def test_windows_toggle_ignores_extended_keys(monkeypatch) -> None:
    keys = [b"\xe0", b"P", b"\x00", b"p", b"p"]  # Down arrow, then F-key b"\x00p", then a real p
    fake_msvcrt = types.SimpleNamespace(kbhit=lambda: bool(keys), getch=lambda: keys.pop(0))
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    relay = FakeRelay()
    states: list[bool] = []
    stop = threading.Event()
    thread = proxy_module._start_windows_toggle(relay, stop, states.append)
    assert thread is not None
    wait_for(lambda: not keys and relay.toggles >= 1)
    time.sleep(0.1)
    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert relay.toggles == 1
    assert states == [False]


def test_owns_terminal_detects_background_jobs(monkeypatch) -> None:
    monkeypatch.setattr(proxy_module.os, "getpgrp", lambda: 100, raising=False)
    monkeypatch.setattr(proxy_module.os, "tcgetpgrp", lambda fd: 100, raising=False)
    assert proxy_module._owns_terminal(0) is True
    monkeypatch.setattr(proxy_module.os, "tcgetpgrp", lambda fd: 200, raising=False)
    assert proxy_module._owns_terminal(0) is False

    def not_our_terminal(fd: int) -> int:
        raise OSError("not a controlling terminal")

    monkeypatch.setattr(proxy_module.os, "tcgetpgrp", not_our_terminal, raising=False)
    assert proxy_module._owns_terminal(0) is True


@pytest.mark.skipif(os.name == "nt", reason="select() only accepts sockets on Windows")
def test_posix_key_reader_times_out_reads_and_reports_eof() -> None:
    read_fd, write_fd = os.pipe()
    reader = proxy_module._PosixKeyReader(read_fd)
    try:
        assert reader.read(0.05) is None
        os.write(write_fd, b"p")
        assert reader.read(1.0) == b"p"
        os.close(write_fd)
        write_fd = -1
        assert reader.read(1.0) == b""
    finally:
        reader.close()
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.skipif(os.name == "nt", reason="needs a POSIX pseudo-terminal")
def test_posix_toggle_with_a_real_pseudo_terminal(monkeypatch) -> None:
    pty = pytest.importorskip("pty")
    termios = pytest.importorskip("termios")
    master, slave = pty.openpty()
    try:
        original = termios.tcgetattr(slave)
        registered: list = []
        monkeypatch.setattr(
            proxy_module,
            "atexit",
            types.SimpleNamespace(register=registered.append, unregister=registered.remove),
        )
        monkeypatch.setattr(proxy_module, "_owns_terminal", lambda fd: True)
        monkeypatch.setattr(proxy_module.sys, "stdin", FakeTTYStdin(slave))
        relay = FakeRelay()
        stop = threading.Event()
        thread = start_toggle_keyboard(relay, stop)
        assert thread is not None
        local_flags = termios.tcgetattr(slave)[3]
        assert not local_flags & termios.ICANON
        assert not local_flags & termios.ECHO
        assert local_flags & termios.ISIG == original[3] & termios.ISIG  # Ctrl+C still raises SIGINT
        os.write(master, b"p")
        wait_for(lambda: relay.toggles == 1)
        stop.set()
        thread.join(timeout=2)
        assert not thread.is_alive()
        restored = termios.tcgetattr(slave)
        # BSD kernels (macOS) set PENDIN by themselves when a tty switches back
        # to canonical mode, to retype pending input; it is not ours to restore.
        pendin = getattr(termios, "PENDIN", 0)
        restored[3] &= ~pendin
        expected = list(original)
        expected[3] &= ~pendin
        assert restored == expected
        assert registered == []
    finally:
        os.close(master)
        os.close(slave)
