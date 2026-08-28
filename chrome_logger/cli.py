from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

from .cdp import CDPCapture
from .chrome import (
    cleanup_profile_locks,
    find_chrome,
    find_free_port,
    kill_profile_chrome_processes,
    launch_chrome,
    wait_for_cdp,
)
from .config import CaptureConfig
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Chrome Network Logger v3 — application-layer capture through browser-level CDP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--output-dir", help="Parent directory for the timestamped session")
    parser.add_argument("--profile-dir", default="capture_profile", help="Dedicated Chrome profile directory")
    parser.add_argument("--chrome-path", help="Explicit Chrome/Chromium executable")
    parser.add_argument("--body-mode", choices=("none", "api", "all"), default="api")
    parser.add_argument("--max-body-mb", type=float, default=32.0, help="Maximum stored bytes per body; 0 means unlimited")
    parser.add_argument("--sensitive", choices=("safe", "raw"), default="safe", help="Redact secrets or preserve raw values")
    parser.add_argument("--no-interactions", action="store_true", help="Disable click/input/form timeline capture")
    parser.add_argument("--capture-clipboard", action="store_true", help="Capture paste payloads; redacted in safe mode")
    parser.add_argument("--no-console", action="store_true", help="Disable console/log/exception files")
    parser.add_argument("--no-storage", action="store_true", help="Disable cookie and Web Storage snapshots")
    parser.add_argument("--no-text-compression", action="store_true", help="Do not gzip textual bodies")
    parser.add_argument("--proxy", metavar="N|random|none", help="Select a proxy from proxy.txt")
    parser.add_argument("--proxy-prompt", action="store_true", help="Prompt for a proxy")
    parser.add_argument("--proxy-file", default="proxy.txt", help="Proxy list path")
    parser.add_argument("--proxy-insecure-tls", action="store_true", help="Disable certificate verification for HTTPS upstream proxies")
    parser.add_argument("--keep-chrome", action="store_true", help="Leave the dedicated Chrome window open after capture")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt for folders or first-run confirmation")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser


def main(argv: list[str] | None = None) -> None:
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
        capture_interactions=not args.no_interactions,
        capture_clipboard=args.capture_clipboard,
        capture_console=not args.no_console,
        capture_storage=not args.no_storage,
        compress_text_bodies=not args.no_text_compression,
        log_level=args.log_level,
    )
    config.validate()

    chrome_path = find_chrome(Path(args.chrome_path) if args.chrome_path else None)
    first_run = not (profile_dir / "Default").exists()
    profile_dir.mkdir(parents=True, exist_ok=True)
    killed = kill_profile_chrome_processes(profile_dir)
    if killed:
        LOG.info("Stopped %s orphan Chrome process(es) using the dedicated profile", killed)
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
    if proxy:
        store.set_manifest(proxy={"enabled": True, "upstream": proxy.label(), "relay": bool(relay)})
    else:
        store.set_manifest(proxy={"enabled": False})

    chrome = None
    capture = None
    capture_connected = False
    keyboard_stop = threading.Event()
    stop_requested = threading.Event()
    shutdown_reason = "user"

    def request_stop(signum=None, _frame=None) -> None:
        nonlocal shutdown_reason
        shutdown_reason = f"signal:{signum}" if signum is not None else "user"
        stop_requested.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            signal.signal(signum, request_stop)

    try:
        port = find_free_port()
        chrome = launch_chrome(chrome_path, profile_dir, port, proxy_args)
        version = wait_for_cdp(chrome)
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
        if config.sensitive_mode == "raw":
            print("WARNING: raw mode stores credentials, cookies and tokens without redaction.")

        while not stop_requested.wait(0.5):
            if chrome.process.poll() is not None:
                shutdown_reason = "chromeExited"
                break
            if capture.connection_closed.is_set():
                shutdown_reason = "cdpDisconnected"
                store.add_warning("The browser-level CDP WebSocket closed unexpectedly")
                break
    except KeyboardInterrupt:
        shutdown_reason = "keyboardInterrupt"
    except BaseException as exc:
        shutdown_reason = f"error:{type(exc).__name__}"
        LOG.exception("Capture failed: %s", exc)
        store.add_warning(f"Capture terminated with {type(exc).__name__}: {exc}")
        if isinstance(exc, (SystemExit, KeyboardInterrupt)):
            raise
    finally:
        keyboard_stop.set()
        if capture and capture_connected:
            try:
                capture.snapshot("end")
                if not capture.wait_for_snapshots(config.shutdown_wait_seconds):
                    store.add_warning("Timed out while waiting for final cookie/storage snapshots")
            except Exception as exc:
                store.add_warning(f"Final snapshot failed: {exc}")
            try:
                if not capture.wait_for_pending_data(config.shutdown_wait_seconds):
                    store.add_warning("Timed out while waiting for pending response/request bodies")
                if not capture.quiesce(config.shutdown_wait_seconds):
                    store.add_warning("Timed out while waiting for CDP instrumentation teardown")
                capture.flush_open(shutdown_reason)
            finally:
                capture.stop()
        if relay:
            relay.stop()
        if chrome and not args.keep_chrome:
            chrome.terminate()
        if capture and not capture_connected:
            capture.stop()
        if shutdown_reason.startswith("error:"):
            status = "error"
        elif shutdown_reason == "cdpDisconnected" or (capture and capture.stats.get("incompleteFlushed", 0)):
            status = "partial"
        else:
            status = "complete"
        store.close(status=status, stats=capture.stats if capture else None)
        print(f"Session finalized: {store.base.resolve()}")


if __name__ == "__main__":
    main(sys.argv[1:])
