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
_LONG_WINDOWS_PROFILE_PATH = 120


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
    raw = _prompt("Capture group/subfolder (empty = current directory): ").strip()
    if not raw:
        return Path.cwd()
    path = Path.cwd() / _safe_group_name(raw)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _prompt(message: str) -> str:
    """Ask a question; a closed stdin (pipe, service, CI) answers with an empty line."""
    try:
        return input(message)
    except EOFError:
        print()
        return ""


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


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
        "--intercept-bodies",
        choices=("none", "document", "api", "all"),
        default="api",
        help="Resource types whose body is taken while the response is paused, which keeps bodies "
        "for iframes, workers, and pages that close mid-request",
    )
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
        "--sensitive",
        choices=("safe", "raw"),
        default="raw",
        help="raw keeps credentials, cookies and tokens as captured; safe redacts them",
    )
    parser.add_argument("--no-interactions", action="store_true", help="Disable click/input/form timeline capture")
    parser.add_argument(
        "--capture-clipboard", action="store_true", help="Capture paste payloads; redacted in safe mode"
    )
    parser.add_argument("--no-console", action="store_true", help="Disable console/log/exception files")
    parser.add_argument("--no-storage", action="store_true", help="Disable cookie and Web Storage snapshots")
    parser.add_argument(
        "--no-client-storage",
        action="store_true",
        help="Disable IndexedDB and Cache Storage capture",
    )
    parser.add_argument(
        "--max-idb-entries",
        type=_positive_int,
        default=500,
        help="Maximum IndexedDB records dumped per object store, per dump",
    )
    parser.add_argument(
        "--max-cache-entries",
        type=_positive_int,
        default=200,
        help="Maximum Cache Storage entries dumped per cache, per dump",
    )
    parser.add_argument("--no-text-compression", action="store_true", help="Do not gzip textual bodies")
    parser.add_argument("--no-har", action="store_true", help="Do not write reports/session.har at the end")
    parser.add_argument(
        "--snapshot-interval",
        type=_non_negative_finite_float,
        default=0.0,
        help="Extra periodic cookie/storage snapshot every N seconds; 0 relies on event capture alone",
    )
    parser.add_argument(
        "--durable-messages",
        action="store_true",
        help="Configure CDP durable messages; on current Chrome this stops response bodies from being retrievable",
    )
    parser.add_argument(
        "--proxy",
        metavar="N|random|none",
        default=None,
        help="Select a proxy from proxy.txt; direct connection (none) is the default",
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
    parser.add_argument(
        "--note",
        help="What this capture is about (scenario, bug, account used); shown at the top of INDEX.md for the analyst",
    )
    parser.add_argument("--version", action="version", version=f"chrome-network-logger {__version__}")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser


def _signal_name(value: str) -> str:
    try:
        return signal.Signals(int(value)).name
    except (ValueError, TypeError):
        return value


def _human_reason(reason: str) -> str:
    """Explain in one clause why the capture stopped."""
    if reason.startswith("signal:"):
        name = _signal_name(reason.split(":", 1)[1])
        if name == "SIGINT":
            return "you stopped it (Ctrl+C)"
        if name == "SIGBREAK":
            return "you stopped it (Ctrl+Break)"
        return f"it received {name}"
    mapping = {
        "keyboardInterrupt": "you stopped it (Ctrl+C)",
        "chromeExited": "you closed the browser",
        "cdpDisconnected": "the browser connection dropped",
        "durationElapsed": "the requested duration elapsed",
        "user": "you stopped it",
    }
    if reason in mapping:
        return mapping[reason]
    if reason.startswith("error:"):
        return f"a capture error ({reason.split(':', 1)[1]})"
    return reason


def _print_session_summary(base: Path, status: str, reason: str, stats: dict[str, int] | None) -> None:
    """Say what was saved, in plain language, so nothing looks lost."""
    stats = stats or {}
    print(f"\nCapture stopped: {_human_reason(reason)}")
    if status == "error":
        print("Some data could not be finalized; see the warnings above and manifest.json.")
    else:
        print("All captured data was written to disk.")
    requests = stats.get("requests", 0)
    bodies = stats.get("bodies", 0)
    body_errors = stats.get("bodyErrors", 0)
    print(f"  Requests: {requests} | bodies stored: {bodies} | bodies lost to errors: {body_errors}")
    no_body = stats.get("bodiesUnavailable", 0)
    if no_body:
        print(f"  {no_body} response(s) had no body to capture (cancelled, HEAD, 204/304, or redirect).")
    state = (
        f"  Cookie changes: {stats.get('cookieChanges', 0)} | "
        f"Web Storage changes: {stats.get('storageChanges', 0)} | "
        f"page flushes: {stats.get('storageFlushes', 0)}"
    )
    print(state)
    if stats.get("idbEntries") or stats.get("cacheEntries"):
        print(
            f"  IndexedDB records: {stats.get('idbEntries', 0)} | Cache Storage entries: {stats.get('cacheEntries', 0)}"
        )
    in_flight = stats.get("incompleteFlushed", 0)
    if in_flight:
        print(f"  {in_flight} request(s) were still in flight and are marked incomplete; everything else is complete.")
    cut_off = stats.get("incompleteDetached", 0)
    if cut_off:
        print(f"  {cut_off} request(s) were cut off because their tab, iframe or worker closed (normal browsing).")
    print(f"  Session: {base}")
    print(f"  Start here: {base / 'INDEX.md'}")
    print(f"  Then: {base / 'reports' / 'summary.txt'} and {base / 'network' / 'requests.jsonl'}")


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
        intercept_bodies=args.intercept_bodies,
        sensitive_mode=args.sensitive,
        max_body_bytes=max(0, int(args.max_body_mb * 1024 * 1024)),
        max_session_body_bytes=max(0, int(args.max_session_body_mb * 1024 * 1024)),
        capture_interactions=not args.no_interactions,
        capture_clipboard=args.capture_clipboard,
        capture_console=not args.no_console,
        capture_storage=not args.no_storage,
        capture_client_storage=not args.no_storage and not args.no_client_storage,
        max_idb_entries=args.max_idb_entries,
        max_cache_entries=args.max_cache_entries,
        compress_text_bodies=not args.no_text_compression,
        snapshot_interval_seconds=args.snapshot_interval,
        durable_messages=args.durable_messages,
        export_har=not args.no_har,
        log_level=args.log_level,
    )
    try:
        config.validate()
    except ValueError as exc:
        parser.error(str(exc))

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
        _prompt("Press Enter to launch Chrome and start capture...")

    proxies = load_proxies(Path(args.proxy_file).expanduser())
    try:
        proxy = select_proxy(proxies, args.proxy, prompt=args.proxy_prompt)
        proxy_args, relay = build_proxy_route(proxy, verify_tls=not args.proxy_insecure_tls)
    except ValueError as exc:
        parser.error(str(exc))
    if args.keep_chrome and relay:
        parser.error(
            "--keep-chrome cannot be used with a proxy relay (HTTP(S) or authenticated SOCKS5) "
            "because the relay stops with the logger"
        )

    redactor = Redactor(config.sensitive_mode)
    store = CaptureStore(config, redactor)
    if args.note and args.note.strip():
        store.set_manifest(note=args.note.strip()[:2000])
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

    if sys.platform == "win32" and len(str(profile_dir)) > _LONG_WINDOWS_PROFILE_PATH:
        # Chrome nests Cache Storage and IndexedDB files ~120 characters deep
        # in the profile; past Windows' 260-character limit, pages then fail
        # with "UnknownError: Unexpected internal error".
        message = (
            f"The profile path is {len(str(profile_dir))} characters long; on Windows, sites may fail to use "
            "Cache Storage or IndexedDB under long paths. Use a shorter --profile-dir."
        )
        LOG.warning(message)
        safe_warning(message)

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
    keyboard_thread: threading.Thread | None = None
    stop_requested = threading.Event()
    shutdown_reason = "user"
    exit_code = 0
    started_at = time.monotonic()
    if config.sensitive_mode == "raw":
        print("WARNING: raw mode is active: this session will store credentials, cookies and tokens in clear text.")
        print("         Anyone who reads the session directory gets them. Use --sensitive safe to redact.")

    def request_stop(signum=None, _frame=None) -> None:
        nonlocal shutdown_reason
        shutdown_reason = f"signal:{signum}" if signum is not None else "user"
        stop_requested.set()

    previous_signal_handlers: dict[int, object] = {}
    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"):
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
        # Always launch on about:blank: a URL on the command line starts loading
        # before CDP is attached, and its first requests would be lost.
        chrome = launch_chrome(chrome_path, profile_dir, port, [*proxy_args, "about:blank"])
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

            keyboard_thread = start_toggle_keyboard(relay, keyboard_stop, on_toggle=on_toggle)
            if keyboard_thread is not None:
                print("[P] toggles the upstream proxy; active connections are reset.")

        if args.start_url != "about:blank":
            if capture.open_start_url(args.start_url):
                LOG.info("Opened the start URL after the first tab was instrumented")
            else:
                safe_warning("The start URL was opened before the first tab was fully instrumented")
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
        if keyboard_thread is not None:
            # Lets the toggle thread restore the terminal mode before exit.
            keyboard_thread.join(timeout=1)
        if capture and capture_connected:
            browser_live = capture.is_live() and not (chrome and chrome.process.poll() is not None)
            if not browser_live:
                # The browser is already gone, so finalize from the event-sourced
                # state instead of waiting out shutdown timeouts on a dead socket.
                safe_warning("Browser closed before shutdown; writing the state rebuilt from captured events")
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
                capture.write_final_state()
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
            store.close(
                status=status,
                stats=capture.stats if capture else None,
                reason=shutdown_reason,
            )
        except Exception as exc:
            exit_code = 1
            status = "error"
            LOG.exception("Session finalization failed: %s", exc)
            safe_warning(f"Session finalization failed with {type(exc).__name__}: {exc}")
        for signum, handler in previous_signal_handlers.items():
            try:
                signal.signal(signum, handler)
            except (OSError, ValueError):
                LOG.debug("Could not restore signal handler %s", signum)
        _print_session_summary(
            store.base.resolve(),
            status,
            shutdown_reason,
            capture.stats if capture else None,
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
