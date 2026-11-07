from __future__ import annotations

import http.client
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import psutil
import websocket

LOG = logging.getLogger(__name__)


# How long a browser the user closed may take to exit by itself.
CLOSING_GRACE_SECONDS = 3.0


@dataclass(slots=True)
class ChromeProcess:
    process: subprocess.Popen[Any]
    port: int
    profile_dir: Path

    def terminate(self, timeout: float = 5.0, *, already_closing: bool = False) -> None:
        """Close Chrome cleanly, falling back to a signal and then a hard kill.

        Browser.close lets Chrome flush its profile (cookies, session state) and
        record a clean exit, so the next launch shows no crash-restore prompt.
        CTRL_BREAK_EVENT is not used: on Windows Chrome is a GUI process with no
        console, so it never receives it and the logger only waited it out.

        ``already_closing`` means the user closed the browser: its DevTools
        endpoint is going away, so asking it to close would only time out.
        Chrome gets a short grace period to finish on its own instead.
        """
        try:
            if already_closing and self.process.poll() is None:
                try:
                    self.process.wait(timeout=min(timeout, CLOSING_GRACE_SECONDS))
                except subprocess.TimeoutExpired:
                    LOG.debug("Chrome was still closing after %.1fs", CLOSING_GRACE_SECONDS)
            elif self.process.poll() is None and self.port and request_browser_close(self.port):
                try:
                    self.process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    LOG.debug("Chrome did not exit within %.1fs of Browser.close", timeout)
            if self.process.poll() is None:
                try:
                    if os.name == "nt":
                        self.process.terminate()
                    else:
                        os.killpg(self.process.pid, signal.SIGTERM)
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


def _normalized_path(value: str | Path) -> str:
    text = str(value).strip().strip('"').strip("'")
    return os.path.normcase(os.path.normpath(text))


def user_data_dir_argument(cmdline: list[str] | None) -> str | None:
    """Return the value of Chrome's --user-data-dir flag, if present."""
    arguments = list(cmdline or [])
    for index, argument in enumerate(arguments):
        if argument.startswith("--user-data-dir="):
            return argument.split("=", 1)[1]
        if argument == "--user-data-dir" and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def uses_profile(cmdline: list[str] | None, profile_dir: Path) -> bool:
    """Report whether a command line runs Chrome on exactly this profile.

    The flag value is compared as a whole path: a substring test matches
    `profiles/ab` when looking for `profiles/a` and kills the wrong browser.
    """
    value = user_data_dir_argument(cmdline)
    if not value:
        return False
    try:
        wanted: Path = profile_dir.resolve()
    except OSError:
        wanted = profile_dir
    return _normalized_path(value) == _normalized_path(wanted)


def _profile_processes(profile_dir: Path) -> list[psutil.Process]:
    matches: list[psutil.Process] = []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (process.info.get("name") or "").casefold()
            if "chrome" not in name and "chromium" not in name:
                continue
            if uses_profile(process.info.get("cmdline"), profile_dir):
                matches.append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, TypeError, ValueError):
            continue
    return matches


def kill_profile_chrome_processes(profile_dir: Path, timeout: float = 3.0) -> int:
    """Stop every Chrome process of the dedicated profile, all at once."""
    processes = _profile_processes(profile_dir)
    if not processes:
        return 0
    for process in processes:
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    _, alive = psutil.wait_procs(processes, timeout=timeout)
    for process in alive:
        try:
            process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if alive:
        psutil.wait_procs(alive, timeout=2)
    return len(processes)


def profile_chrome_process_ids(profile_dir: Path) -> list[int]:
    """Return Chrome processes that still explicitly reference the dedicated profile."""
    return [int(process.pid) for process in _profile_processes(profile_dir)]


def request_browser_close(port: int, timeout: float = 2.0) -> bool:
    """Ask Chrome to exit cleanly through its loopback DevTools endpoint."""
    try:
        version = fetch_json(port, "/json/version", timeout=timeout)
        url = str(version["webSocketDebuggerUrl"])
        parsed = urlsplit(url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.port != port:
            LOG.debug("Refusing to close Chrome through an unexpected endpoint: %r", url)
            return False
        connection = websocket.create_connection(url, timeout=timeout, suppress_origin=True)
    except Exception as exc:
        LOG.debug("Chrome DevTools endpoint unavailable for Browser.close: %s", exc)
        return False
    try:
        connection.send(json.dumps({"id": 1, "method": "Browser.close"}))
        try:
            connection.recv()
        except Exception as exc:
            # Chrome may drop the socket before answering; it is closing anyway.
            LOG.debug("No Browser.close acknowledgement: %s", exc)
        return True
    except Exception as exc:
        LOG.debug("Browser.close could not be sent: %s", exc)
        return False
    finally:
        try:
            connection.close()
        except Exception as exc:
            LOG.debug("Could not close the Browser.close connection: %s", exc)


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


def choose_loopback_debugging_port() -> int:
    """Ask the OS for a free non-zero loopback port.

    Chrome exposes ``navigator.webdriver`` when remote debugging uses port 0,
    so the launcher resolves an ephemeral port immediately before startup.
    The CDP endpoint is still validated as loopback-only after Chrome binds it.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = int(reservation.getsockname()[1])
    if not 1 <= port <= 65535:
        raise RuntimeError(f"Operating system returned an invalid debugging port: {port}")
    return port


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
