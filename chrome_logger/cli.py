from __future__ import annotations

import argparse
import logging
import math
import signal
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .cdp import CDPCapture
from .chrome import (
    choose_loopback_debugging_port,
    cleanup_profile_locks,
    find_chrome,
    kill_profile_chrome_processes,
    launch_chrome,
    profile_chrome_process_ids,
    wait_for_cdp,
)
from .config import CaptureConfig
from .managed_chrome import ManagedChrome, ManagedChromeError, ensure_managed_chrome
from .proxy import build_proxy_route, load_proxies, select_proxy, start_toggle_keyboard
from .redaction import Redactor
from .storage import CaptureStore

LOG = logging.getLogger(__name__)


def _safe_group_name(value: str) -> str:
    forbidden = '<>:"/\\|?*'
    cleaned = "".join("_" if char in forbidden else char for char in value.strip()).rstrip(". ")
    return cleaned or "capture"


def _output_parent(argument: str | None, non_interactive: bool) -> Path:
    if argument:
        path = Path(argument).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path
    if non_interactive:
        return Path.cwd()
    raw = input("Capture group/subfolder (empty = current directory): ").strip()
    if not raw:
        return Path.cwd()
    path = Path.cwd() / _safe_group_name(raw)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _non_negative_finite_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be finite and >= 0")
    return parsed


def _start_url(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("-"):
        raise argparse.ArgumentTypeError("must be a URL, not a Chrome option")
    scheme = urlsplit(candidate).scheme.casefold()
    if scheme not in {"about", "chrome", "data", "file", "http", "https"}:
        raise argparse.ArgumentTypeError("must use about, chrome, data, file, http, or https")
    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Chrome Network Logger v3 — application-layer capture through browser-level CDP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--output-dir", help="Parent directory for the timestamped session")
    parser.add_argument("--profile-dir", default="capture_profile", help="Dedicated Chrome profile directory")
    parser.add_argument("--chrome-path", help="Explicit Chrome/Chromium executable")
    parser.add_argument(
        "--managed-chrome-dir",
        help="Cache directory for an official Chrome for Testing fallback",
    )
    parser.add_argument(
        "--no-download-chrome",
        action="store_true",
        help="Fail instead of downloading official Chrome for Testing when Chrome is missing",
    )
    parser.add_argument(
        "--refresh-managed-chrome",
        action="store_true",
        help="Check for a newer managed Stable build when the fallback is needed",
    )
    parser.add_argument(
        "--start-url",
        type=_start_url,
        default="about:blank",
        help="Initial page; about:blank avoids unsolicited new-tab traffic",
    )
    parser.add_argument("--body-mode", choices=("none", "api", "all"), default="api")
    parser.add_argument(
        "--max-body-mb",
        type=_non_negative_finite_float,
        default=32.0,
        help="Maximum stored bytes per body; 0 means unlimited",
    )
    parser.add_argument(
        "--max-session-body-mb",
        type=_non_negative_finite_float,
        default=2048.0,
        help="Maximum stored body bytes for the whole session; 0 means unlimited",
    )
    parser.add_argument(
        "--sensitive", choices=("safe", "raw"), default="safe", help="Redact secrets or preserve raw values"
    )
    parser.add_argument("--no-interactions", action="store_true", help="Disable click/input/form timeline capture")
    parser.add_argument(
        "--capture-clipboard", action="store_true", help="Capture paste payloads; redacted in safe mode"
    )
    parser.add_argument("--no-console", action="store_true", help="Disable console/log/exception files")
    parser.add_argument("--no-storage", action="store_true", help="Disable cookie and Web Storage snapshots")
    parser.add_argument("--no-text-compression", action="store_true", help="Do not gzip textual bodies")
    parser.add_argument(
        "--snapshot-interval",
        type=_non_negative_finite_float,
        default=30.0,
        help="Refresh cookie/storage snapshots every N seconds so a closed browser keeps recent state; 0 disables",
    )
    parser.add_argument(
        "--proxy",
        metavar="N|random|none",
        default="none",
        help="Select a proxy from proxy.txt; direct connection is the default",
    )
    parser.add_argument("--proxy-prompt", action="store_true", help="Prompt for a proxy")
    parser.add_argument("--proxy-file", default="proxy.txt", help="Proxy list path")
    parser.add_argument(
        "--proxy-insecure-tls", action="store_true", help="Disable certificate verification for HTTPS upstream proxies"
    )
    parser.add_argument(
        "--keep-chrome", action="store_true", help="Leave the dedicated Chrome window open after capture"
    )
    parser.add_argument(
        "--non-interactive", action="store_true", help="Do not prompt for folders or first-run confirmation"
    )
    parser.add_argument(
        "--duration", type=_non_negative_finite_float, help="Stop automatically after this many seconds"
    )
    parser.add_argument("--version", action="version", version=f"chrome-network-logger {__version__}")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    profile_dir = Path(args.profile_dir).expanduser().resolve()
    output_parent = _output_parent(args.output_dir, args.non_interactive)
    config = CaptureConfig(
        output_parent=output_parent,
        profile_dir=profile_dir,
        body_mode=args.body_mode,
        sensitive_mode=args.sensitive,
        max_body_bytes=max(0, int(args.max_body_mb * 1024 * 1024)),
        max_session_body_bytes=max(0, int(args.max_session_body_mb * 1024 * 1024)),
        capture_interactions=not args.no_interactions,
        capture_clipboard=args.capture_clipboard,
        capture_console=not args.no_console,
        capture_storage=not args.no_storage,
        compress_text_bodies=not args.no_text_compression,
        snapshot_interval_seconds=args.snapshot_interval,
        log_level=args.log_level,
    )
    config.validate()

    first_run = not (profile_dir / "Default").exists()
    profile_dir.mkdir(parents=True, exist_ok=True)
    if args.no_download_chrome and args.refresh_managed_chrome:
        parser.error("--refresh-managed-chrome cannot be combined with --no-download-chrome")
    explicit_chrome = Path(args.chrome_path) if args.chrome_path else None
    managed_browser: ManagedChrome | None = None
    try:
        chrome_path = find_chrome(explicit_chrome)
    except FileNotFoundError as exc:
        if explicit_chrome is not None or args.no_download_chrome:
            parser.error(str(exc))
        managed_dir = Path(args.managed_chrome_dir) if args.managed_chrome_dir else None
        try:
            managed_browser = ensure_managed_chrome(
                managed_dir,
                refresh=args.refresh_managed_chrome,
                progress=lambda message: LOG.info("%s", message),
            )
        except (ManagedChromeError, OSError) as install_error:
            parser.error(f"Chrome is missing and the managed fallback failed: {install_error}")
        chrome_path = managed_browser.executable
        LOG.info("Using official managed Chrome %s from %s", managed_browser.version, chrome_path)
    killed = kill_profile_chrome_processes(profile_dir)
    if killed:
        LOG.info("Stopped %s orphan Chrome process(es) using the dedicated profile", killed)
    remaining_profile_processes = profile_chrome_process_ids(profile_dir)
    if remaining_profile_processes:
        parser.error(
            "Chrome is still using the dedicated profile; refusing to remove locks "
            f"(PIDs: {', '.join(map(str, remaining_profile_processes))})"
        )
    cleanup_profile_locks(profile_dir)

    if first_run and not args.non_interactive:
        print("\nFirst run: Chrome will use a new isolated profile.")
        print("Log in only to applications you are authorized to inspect.")
        input("Press Enter to launch Chrome and start capture...")

    proxies = load_proxies(Path(args.proxy_file).expanduser())
    try:
        proxy = select_proxy(proxies, args.proxy, prompt=args.proxy_prompt)
        proxy_args, relay = build_proxy_route(proxy, verify_tls=not args.proxy_insecure_tls)
    except ValueError as exc:
        parser.error(str(exc))
        return
    if args.keep_chrome and relay:
        parser.error("--keep-chrome cannot be used with an HTTP(S) relay because the relay stops with the logger")

    redactor = Redactor(config.sensitive_mode)
    store = CaptureStore(config, redactor)
    if managed_browser:
        store.set_manifest(
            browserInstall={
                "source": "chromeForTestingStable",
                "version": managed_browser.version,
                "platform": managed_browser.platform,
                "archiveSha256": managed_browser.archive_sha256,
                "executableSha256": managed_browser.executable_sha256,
            }
        )
    else:
        store.set_manifest(browserInstall={"source": "explicit" if explicit_chrome else "system"})

    def safe_warning(message: str) -> None:
        try:
            store.add_warning(message)
        except Exception:
            LOG.exception("Could not persist warning: %s", message)

    if proxy:
        store.set_manifest(proxy={"enabled": True, "upstream": proxy.label(), "relay": bool(relay)})
        LOG.info("Proxy route enabled: %s", proxy.label())
    else:
        store.set_manifest(proxy={"enabled": False})
        LOG.info("Direct network route enabled")

    chrome = None
    capture = None
    capture_connected = False
    keyboard_stop = threading.Event()
    stop_requested = threading.Event()
    shutdown_reason = "user"
    exit_code = 0
    started_at = time.monotonic()
    if config.sensitive_mode == "raw":
        print("WARNING: raw mode stores credentials, cookies and tokens without redaction.")

    def request_stop(signum=None, _frame=None) -> None:
        nonlocal shutdown_reason
        shutdown_reason = f"signal:{signum}" if signum is not None else "user"
        stop_requested.set()

    previous_signal_handlers: dict[int, object] = {}
    for signal_name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            try:
                previous_signal_handlers[signum] = signal.signal(signum, request_stop)
            except ValueError:
                LOG.debug("Signal handlers can only be installed from the main thread")

    try:
        # Port 0 makes Chrome expose navigator.webdriver=true. Resolve a
        # non-zero loopback port immediately before launch instead.
        port = choose_loopback_debugging_port()
        chrome = launch_chrome(chrome_path, profile_dir, port, [*proxy_args, args.start_url])
        version = wait_for_cdp(chrome)
        port = chrome.port
        LOG.info("Connected to %s", version.get("Browser"))
        capture = CDPCapture(port, config, store)
        if not capture.connect():
            raise RuntimeError("Browser-level CDP connection failed")
        capture_connected = True

        if relay:

            def on_toggle(enabled: bool) -> None:
                store.write_jsonl(
                    "browser/proxy_toggles.jsonl",
                    {
                        "time": capture.timestamps.normalize() if capture else None,
                        "enabled": enabled,
                        "upstream": proxy.label() if proxy else None,
                    },
                    redact=True,
                )

            start_toggle_keyboard(relay, keyboard_stop, on_toggle=on_toggle)
            print("[P] toggles the upstream proxy on Windows; active connections are reset.")

        time.sleep(0.5)
        capture.snapshot("start")
        capture.wait_for_snapshots(config.shutdown_wait_seconds)
        print(f"\nCapture active: {store.base.resolve()}")
        print("Press Ctrl+C to stop and finalize the session.")

        snapshot_interval = config.snapshot_interval_seconds if config.capture_storage else 0.0
        next_snapshot = time.monotonic() + snapshot_interval if snapshot_interval else None
        while not stop_requested.wait(0.5):
            store.check_health()
            if next_snapshot is not None and time.monotonic() >= next_snapshot:
                # Keep a fresh copy on disk: cookies and Web Storage are
                # unreachable once the user closes the browser window.
                capture.snapshot("interval")
                next_snapshot = time.monotonic() + snapshot_interval
            if chrome.process.poll() is not None:
                shutdown_reason = "chromeExited"
                break
            if capture.failure.is_set():
                detail = str(capture.fatal_error or "unknown CDP failure")
                raise RuntimeError(f"Capture health check failed: {detail}")
            if capture.connection_closed.is_set():
                shutdown_reason = "cdpDisconnected"
                safe_warning("The browser-level CDP WebSocket closed unexpectedly")
                break
            if args.duration is not None and time.monotonic() - started_at >= args.duration:
                shutdown_reason = "durationElapsed"
                break
    except KeyboardInterrupt:
        shutdown_reason = "keyboardInterrupt"
    except Exception as exc:
        shutdown_reason = f"error:{type(exc).__name__}"
        exit_code = 1
        LOG.exception("Capture failed: %s", exc)
        safe_warning(f"Capture terminated with {type(exc).__name__}: {exc}")
    finally:
        keyboard_stop.set()
        if capture and capture_connected:
            browser_live = capture.is_live() and not (chrome and chrome.process.poll() is not None)
            if not browser_live:
                # The browser is already gone: cookies and Web Storage cannot be
                # read any more, so finalize from what is on disk instead of
                # waiting out every shutdown timeout on a dead socket.
                safe_warning(
                    "Browser closed before shutdown; keeping captured data and the last interval snapshot"
                )
            if browser_live:
                try:
                    capture.snapshot("end")
                    if not capture.wait_for_snapshots(config.shutdown_wait_seconds):
                        safe_warning("Timed out while waiting for final cookie/storage snapshots")
                except Exception as exc:
                    safe_warning(f"Final snapshot failed: {exc}")
            try:
                if browser_live:
                    if not capture.wait_for_pending_data(config.shutdown_wait_seconds):
                        safe_warning("Timed out while waiting for pending response/request bodies")
                    if not capture.quiesce(config.shutdown_wait_seconds):
                        safe_warning("Timed out while waiting for CDP instrumentation teardown")
                capture.flush_open(shutdown_reason)
            except Exception as exc:
                exit_code = 1
                shutdown_reason = f"error:{type(exc).__name__}"
                LOG.exception("Capture shutdown failed: %s", exc)
                safe_warning(f"Capture shutdown failed with {type(exc).__name__}: {exc}")
            finally:
                capture.stop()
        if relay:
            try:
                relay.stop()
            except Exception as exc:
                exit_code = 1
                safe_warning(f"Proxy relay shutdown failed: {exc}")
        if chrome and not args.keep_chrome:
            try:
                chrome.terminate()
            except Exception as exc:
                exit_code = 1
                safe_warning(f"Chrome shutdown failed: {exc}")
        if capture and not capture_connected:
            capture.stop()
        if shutdown_reason.startswith("error:"):
            status = "error"
        elif shutdown_reason in {"cdpDisconnected", "chromeExited"} or (
            capture and capture.stats.get("incompleteFlushed", 0)
        ):
            status = "partial"
        else:
            status = "complete"
        try:
            store.close(status=status, stats=capture.stats if capture else None)
        except Exception as exc:
            exit_code = 1
            status = "error"
            LOG.exception("Session finalization failed: %s", exc)
        for signum, handler in previous_signal_handlers.items():
            try:
                signal.signal(signum, handler)
            except (OSError, ValueError):
                LOG.debug("Could not restore signal handler %s", signum)
        print(f"Session finalized: {store.base.resolve()} ({status})")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
