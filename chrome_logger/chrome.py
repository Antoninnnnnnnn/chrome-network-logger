from __future__ import annotations

import http.client
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class ChromeProcess:
    process: subprocess.Popen[Any]
    port: int
    profile_dir: Path

    def terminate(self, timeout: float = 5.0) -> None:
        try:
            if self.process.poll() is None:
                try:
                    if os.name == "nt":
                        self.process.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        os.killpg(self.process.pid, signal.SIGTERM)
                    self.process.wait(timeout=timeout)
                except Exception:
                    try:
                        self.process.terminate()
                        self.process.wait(timeout=2)
                    except Exception:
                        try:
                            self.process.kill()
                        except Exception as exc:
                            LOG.debug("Could not kill Chrome launcher process: %s", exc)
        finally:
            # Chrome's launcher may exit before its browser children. Always
            # clean up processes that still reference our dedicated profile.
            kill_profile_chrome_processes(self.profile_dir)


def find_chrome(explicit: Path | None = None) -> Path:
    if explicit:
        path = explicit.expanduser().resolve()
        if path.is_file():
            return path
        raise FileNotFoundError(f"Chrome executable not found: {path}")

    candidates: list[str | Path] = []
    for executable in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(executable)
        if found:
            candidates.append(found)
    if os.name == "nt":
        candidates.extend(
            [
                Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)"))
                / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Chromium/Application/chrome.exe",
            ]
        )
    elif sys.platform == "darwin":
        candidates.extend(
            [
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                Path.home() / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            ]
        )

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file():
            return path.resolve()
    raise FileNotFoundError("Chrome/Chromium was not found. Use --chrome-path.")


def kill_profile_chrome_processes(profile_dir: Path) -> int:
    profile_text = str(profile_dir.resolve()).casefold()
    killed = 0
    for process in psutil.process_iter(["name", "cmdline"]):
        try:
            name = (process.info.get("name") or "").casefold()
            if "chrome" not in name and "chromium" not in name:
                continue
            command = " ".join(process.info.get("cmdline") or []).casefold()
            if profile_text in command:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except psutil.TimeoutExpired:
                    process.kill()
                killed += 1
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return killed


def profile_chrome_process_ids(profile_dir: Path) -> list[int]:
    """Return Chrome processes that still explicitly reference the dedicated profile."""
    profile_text = str(profile_dir.resolve()).casefold()
    matches: list[int] = []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (process.info.get("name") or "").casefold()
            command = " ".join(process.info.get("cmdline") or []).casefold()
            if ("chrome" in name or "chromium" in name) and profile_text in command:
                matches.append(int(process.info["pid"]))
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, TypeError, ValueError):
            continue
    return matches


def cleanup_profile_locks(profile_dir: Path) -> None:
    names = {
        "SingletonLock",
        "SingletonCookie",
        "SingletonSocket",
        "Lock",
    }
    candidates = [profile_dir, profile_dir / "Default"]
    for directory in candidates:
        for name in names:
            try:
                (directory / name).unlink(missing_ok=True)
            except OSError:
                LOG.debug("Could not remove profile lock %s", directory / name)


def launch_chrome(
    chrome_path: Path,
    profile_dir: Path,
    port: int,
    extra_args: list[str] | None = None,
) -> ChromeProcess:
    profile_dir.mkdir(parents=True, exist_ok=True)
    if port == 0:
        try:
            (profile_dir / "DevToolsActivePort").unlink(missing_ok=True)
        except OSError as exc:
            raise RuntimeError(f"Could not clear stale DevToolsActivePort: {exc}") from exc
    command = [
        str(chrome_path),
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir.resolve()}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=ChromeWhatsNewUI",
    ]
    if port:
        command.append(f"--remote-allow-origins=http://127.0.0.1:{port}")
    command.extend(extra_args or [])
    kwargs: dict[str, Any] = {"close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **kwargs)
    return ChromeProcess(process=process, port=port, profile_dir=profile_dir)


def wait_for_cdp(chrome: ChromeProcess, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if chrome.process.poll() is not None:
            raise RuntimeError(f"Chrome exited with status {chrome.process.returncode}")
        if chrome.port == 0:
            try:
                lines = (chrome.profile_dir / "DevToolsActivePort").read_text(encoding="utf-8").splitlines()
                selected = int(lines[0])
                if not 1 <= selected <= 65535:
                    raise ValueError(f"invalid Chrome debugging port {selected}")
                chrome.port = selected
            except (OSError, ValueError, IndexError) as exc:
                last_error = exc
                time.sleep(0.1)
                continue
        try:
            return fetch_json(chrome.port, "/json/version", timeout=1)
        except (OSError, http.client.HTTPException, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
        time.sleep(0.2)
    raise TimeoutError(f"Chrome CDP did not become ready on port {chrome.port}: {last_error}")


def fetch_json(port: int, path: str, *, timeout: float = 3) -> Any:
    """Fetch JSON from Chrome's fixed loopback endpoint without redirects or alternate URL schemes."""
    if not 1 <= int(port) <= 65535:
        raise ValueError(f"Invalid CDP port: {port}")
    if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
        raise ValueError(f"Invalid CDP path: {path!r}")
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise OSError(f"Chrome CDP returned HTTP {response.status} for {path}")
        return json.loads(response.read())
    finally:
        connection.close()
