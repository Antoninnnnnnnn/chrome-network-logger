from __future__ import annotations

import copy
import json
import logging
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import websocket

from .browser_capture import BrowserCaptureMixin
from .chrome import fetch_json
from .client_storage import ClientStorageMixin
from .config import CaptureConfig
from .constants import PAGE_TYPES, SESSION_GONE_CODES, SESSION_GONE_MARKERS, TARGET_TYPES
from .models import PendingCommand
from .network_capture import NetworkCaptureMixin
from .realtime_capture import RealtimeCaptureMixin
from .registry import RequestRegistry
from .state_capture import StateCaptureMixin
from .storage import CaptureStore
from .timestamps import TimestampMapper

LOG = logging.getLogger(__name__)


class CDPCapture(
    NetworkCaptureMixin,
    RealtimeCaptureMixin,
    BrowserCaptureMixin,
    StateCaptureMixin,
    ClientStorageMixin,
):
    def __init__(self, port: int, config: CaptureConfig, store: CaptureStore):
        self.port = port
        self.config = config
        self.store = store
        self.ws: websocket.WebSocket | None = None
        self.running = threading.Event()
        self.running.set()
        self.connection_closed = threading.Event()
        self.failure = threading.Event()
        self.fatal_error: BaseException | None = None
        self.thread: threading.Thread | None = None
        self.send_lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.message_id = 0
        self.pending: dict[int, PendingCommand] = {}
        self.registry = RequestRegistry()
        self.targets: dict[str, dict[str, Any]] = {}
        self.target_sessions: dict[str, str] = {}
        self.attached_targets: set[str] = set()
        self.attach_attempts: dict[str, int] = {}
        self.discovered_targets: dict[str, tuple[float, dict[str, Any]]] = {}
        self.enabled_sessions: set[str] = set()
        self.finalize_deadlines: dict[str, tuple[float, float, str | None]] = {}
        self.open_websockets: dict[str, dict[str, Any]] = {}
        self.paused_fetches: dict[str, tuple[str | None, str | None]] = {}
        self._quiescing = False
        self.webtransports: dict[str, dict[str, Any]] = {}
        self.timestamps = TimestampMapper()
        self.binding_name = "__cnl_" + secrets.token_hex(8)
        self.install_marker = "__cnl_installed_" + secrets.token_hex(8)
        self.world_name = "__cnl_world_" + secrets.token_hex(8)
        self.interaction_script_ids: dict[str, str] = {}
        self.interaction_contexts: dict[str, set[int]] = {}
        self._snapshot_condition = threading.Condition(self.state_lock)
        self._quiesce_condition = threading.Condition(self.state_lock)
        self._quiesce_pending = 0
        self._snapshot_pending = 0
        self._protocol_warnings: set[str] = set()
        # Event-sourced cookie and Web Storage state; see StateCaptureMixin.
        self._cookie_state: dict[str, dict[str, Any]] = {}
        self._cookie_sync_reasons: set[str] = set()
        self._cookie_sync_inflight = False
        self._cookie_sync_earliest = 0.0
        self._cookie_baseline_written = False
        self._dom_storage: dict[str, dict[str, Any]] = {}
        # IndexedDB and Cache Storage dumps, keyed by the scope that changed.
        self._client_storage_origins: set[str] = set()
        self._client_storage_requests: dict[tuple[str, str, str | None, str | None, str | None], str] = {}
        self._client_storage_earliest = 0.0
        self.stats = {
            "requests": 0,
            "responses": 0,
            "bodies": 0,
            "bodyErrors": 0,
            "failures": 0,
            "redirects": 0,
            "webSocketFrames": 0,
            "sseMessages": 0,
            "webTransports": 0,
            "userEvents": 0,
            "droppedUserEvents": 0,
            "eventErrors": 0,
            "protocolErrors": 0,
            "droppedExtraInfo": 0,
            "incompleteFlushed": 0,
            "detachedSessionCommands": 0,
            "cookieSyncs": 0,
            "cookieChanges": 0,
            "storageChanges": 0,
            "storageFlushes": 0,
            "droppedStorageFlushes": 0,
            "interceptionBypassed": 0,
            "idbEntries": 0,
            "cacheEntries": 0,
            "clientStorageErrors": 0,
            "clientStorageSkipped": 0,
        }

    def _fail_capture(self, message: str, error: BaseException | None = None) -> None:
        if self.failure.is_set():
            return
        self.fatal_error = error or RuntimeError(message)
        self.failure.set()
        try:
            self.store.add_warning(message)
        except Exception:
            LOG.exception("Could not persist capture failure warning")

    def _session_is_gone(self, session_id: str | None, error: Any = None) -> bool:
        """Report whether a session-scoped command failed because its target died.

        Short-lived iframes, workers and blob workers routinely detach between
        the moment a setup command is written to the socket and the moment
        Chrome answers it. Those replies come back as -32001 "Session with
        given id not found", which is a race, not a capture-wide fault.
        Browser-level commands (no session id) stay fatal.
        """
        if not session_id:
            return False
        with self.state_lock:
            if session_id not in self.enabled_sessions:
                return True
        if isinstance(error, dict):
            if error.get("code") in SESSION_GONE_CODES:
                return True
            message = str(error.get("message") or "").lower()
            return any(marker in message for marker in SESSION_GONE_MARKERS)
        return False

    def _handle_required_failure(self, data: dict[str, Any], error: Any, *, timed_out: bool = False) -> None:
        method = str(data.get("method") or "unknown")
        session_id = data.get("sessionId")
        self.stats["protocolErrors"] += 1
        detached = self._session_is_gone(session_id, error)
        self.store.write_jsonl(
            "browser/protocol_errors.jsonl",
            {
                "time": self.timestamps.normalize(),
                "method": method,
                "sessionId": session_id,
                "required": True,
                "timedOut": timed_out,
                "sessionDetached": detached,
                "error": error,
            },
            redact=True,
        )
        if detached:
            self.stats["detachedSessionCommands"] += 1
            LOG.debug("Ignoring %s failure for detached session %s: %s", method, session_id, error)
            return
        if timed_out:
            self._fail_capture(f"Required CDP command timed out: {method}", TimeoutError(method))
        else:
            self._fail_capture(f"Required CDP command failed: {method}: {error}", RuntimeError(str(error)))

    def connect(self) -> bool:
        try:
            version = fetch_json(self.port, "/json/version")
            initial_targets = fetch_json(self.port, "/json")
            debugger_url = str(version["webSocketDebuggerUrl"])
            parsed = urlsplit(debugger_url)
            if (
                parsed.scheme != "ws"
                or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed.port != self.port
            ):
                raise RuntimeError(f"Chrome returned an unsafe debugger URL: {debugger_url!r}")
            self.ws = websocket.create_connection(debugger_url, timeout=0.2, suppress_origin=True)
        except Exception as exc:
            LOG.error("Could not connect to browser-level CDP: %s", exc)
            return False

        self.store.set_manifest(
            chrome={
                "browser": version.get("Browser"),
                "protocolVersion": version.get("Protocol-Version"),
                "userAgent": version.get("User-Agent"),
                "v8Version": version.get("V8-Version"),
                "webKitVersion": version.get("WebKit-Version"),
            }
        )
        target_filter = [{"type": item} for item in sorted(TARGET_TYPES)]
        self.send(
            "Target.setDiscoverTargets",
            {"discover": True, "filter": target_filter},
            pending=PendingCommand(
                "required_command",
                {"method": "Target.setDiscoverTargets", "sessionId": None},
                time.monotonic(),
            ),
        )
        self.send(
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": target_filter,
            },
            pending=PendingCommand(
                "required_command",
                {"method": "Target.setAutoAttach", "sessionId": None},
                time.monotonic(),
            ),
        )
        for target in initial_targets:
            if target.get("type") in TARGET_TYPES and target.get("id"):
                self._attach_target(str(target["id"]))
        self.thread = threading.Thread(target=self.loop, name="cdp-reader", daemon=True)
        self.thread.start()
        return True

    def next_id(self) -> int:
        with self.send_lock:
            self.message_id += 1
            return self.message_id

    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        pending: PendingCommand | None = None,
    ) -> int:
        message_id = self.next_id()
        message: dict[str, Any] = {"id": message_id, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id
        if pending:
            with self.state_lock:
                self.pending[message_id] = pending
        if not self.ws:
            failed = None
            with self.state_lock:
                failed = self.pending.pop(message_id, None)
            if failed:
                self._handle_send_failure(
                    failed,
                    {"code": -1, "message": f"CDP WebSocket is not connected ({method})"},
                )
            return message_id
        try:
            encoded = json.dumps(message, separators=(",", ":"))
            with self.send_lock:
                self.ws.send(encoded)
        except Exception as exc:
            if isinstance(exc, websocket.WebSocketConnectionClosedException):
                self.connection_closed.set()
            with self.state_lock:
                failed = self.pending.pop(message_id, None)
            if failed:
                self._handle_send_failure(
                    failed,
                    {"code": -1, "message": f"CDP send failed ({method}): {exc}"},
                )
            if not self.is_live():
                # The browser went away; a dead socket is expected here and the
                # session is finalized from the data already on disk.
                LOG.debug("CDP send skipped after disconnect: %s (%s)", method, exc)
            elif self.running.is_set():
                LOG.exception("CDP send failed: %s", method)
        return message_id

    def is_live(self) -> bool:
        """Report whether commands can still reach the browser."""
        return bool(self.ws) and self.running.is_set() and not self.connection_closed.is_set()

    def _handle_send_failure(self, command: PendingCommand, error: dict[str, Any]) -> None:
        kind = command.kind
        data = command.data
        if kind == "response_body":
            key = str(data.get("key") or "")
            with self.state_lock:
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingResponseBody"] = False
                    entry["responseBodyError"] = error
                    self.stats["bodyErrors"] += 1
                    self._schedule_finalize(key, "bodySendFailed", delay=0.01)
        elif kind == "fetch_body":
            key = str(data.get("key") or "")
            fetch_id = str(data.get("fetchId") or "")
            with self.state_lock:
                self.paused_fetches.pop(fetch_id, None)
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingFetchBody"] = False
                    entry["fetchResponseBodyError"] = error
                    self.stats["bodyErrors"] += 1
                    if entry.get("_loadingComplete"):
                        self._request_network_body_fallback(key, "fetchBodySendFailed")
            if fetch_id:
                self.send("Fetch.continueResponse", {"requestId": fetch_id}, data.get("sessionId"))
        elif kind == "request_post_data":
            key = str(data.get("key") or "")
            with self.state_lock:
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingPostData"] = False
                    entry["requestPostDataError"] = error
                    if entry.get("_loadingComplete"):
                        self._schedule_finalize(key, "postDataSendFailed", delay=0.01)
        elif kind in {"snapshot_cookies", "snapshot_storage"}:
            self._handle_snapshot_response(kind, data, error, {})
        elif kind == "cookie_sync":
            self._handle_cookie_sync(data, error, {})
        elif kind in {"idb_names", "idb_database", "idb_data", "cache_names", "cache_entries"}:
            self._handle_client_storage_response(kind, data, error, {})
        elif kind == "interaction_script":
            self.store.write_jsonl(
                "browser/protocol_errors.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": "Page.addScriptToEvaluateOnNewDocument",
                    "sessionId": data.get("sessionId"),
                    "error": error,
                },
                redact=True,
            )
        elif kind == "quiesce":
            self._finish_quiesce_command(data, error)
        elif kind == "attach_target":
            target_id = str(data.get("targetId") or "")
            with self.state_lock:
                self.attached_targets.discard(target_id)
            self.store.write_jsonl(
                "browser/protocol_errors.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": "Target.attachToTarget",
                    "targetId": target_id,
                    "error": error,
                },
                redact=True,
            )
        elif kind == "capability":
            self.store.write_jsonl(
                "browser/protocol_capabilities.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": data.get("method"),
                    "sessionId": data.get("sessionId"),
                    "available": False,
                    "error": error,
                },
                redact=True,
            )
        elif kind == "optional_command":
            self.store.write_jsonl(
                "browser/protocol_errors.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": data.get("method"),
                    "optional": True,
                    "error": error,
                },
                redact=True,
            )
        elif kind == "required_command":
            self._handle_required_failure(data, error)
        elif kind == "interaction_binding":
            self.stats["protocolErrors"] += 1
            self.store.add_warning(f"Interaction capture binding failed for session {data.get('sessionId')}: {error}")

    def _attach_target(self, target_id: str) -> None:
        with self.state_lock:
            if target_id in self.attached_targets:
                return
            attempts = self.attach_attempts.get(target_id, 0)
            if attempts >= 3:
                return
            self.attach_attempts[target_id] = attempts + 1
            self.attached_targets.add(target_id)
        self.send(
            "Target.attachToTarget",
            {"targetId": target_id, "flatten": True},
            pending=PendingCommand("attach_target", {"targetId": target_id}, time.monotonic()),
        )

    def _interception_patterns(self) -> list[dict[str, Any]]:
        """Response-stage patterns for Fetch interception.

        A body taken while the response is paused is captured before the target
        can die, which is the only way to keep bodies for short-lived iframes,
        blob workers, and pages that close mid-request. `Network.getResponseBody`
        needs the target to still be attached when the body is requested.
        """
        if self.config.intercept_bodies == "all":
            return [{"urlPattern": "*", "requestStage": "Response"}]
        resource_types = ["Document"]
        if self.config.intercept_bodies == "api":
            resource_types = ["Document", "XHR", "Fetch"]
        return [
            {"urlPattern": "*", "requestStage": "Response", "resourceType": resource_type}
            for resource_type in resource_types
        ]

    def _enable_session(self, session_id: str, target_info: dict[str, Any]) -> None:
        target_id = str(target_info.get("targetId") or "")
        with self.state_lock:
            if session_id in self.enabled_sessions:
                return
            existing_session = self.target_sessions.get(target_id) if target_id else None
            if existing_session and existing_session != session_id:
                self.send("Target.detachFromTarget", {"sessionId": session_id})
                return
            self.enabled_sessions.add(session_id)
            self.targets[session_id] = copy.deepcopy(target_info)
            if target_id:
                self.target_sessions[target_id] = session_id
        # Durable messages are off by default: on Chrome 152 they make the
        # network service stop retaining response bodies, so every
        # Network.getResponseBody answers "No data found for resource with
        # given identifier" and no body is captured at all. Network.enable
        # below carries the same buffer sizes on stable parameters.
        if self.config.durable_messages:
            self.send(
                "Network.configureDurableMessages",
                {
                    "maxTotalBufferSize": self.config.max_total_buffer,
                    "maxResourceBufferSize": self.config.max_resource_buffer,
                },
                session_id,
                PendingCommand(
                    "capability",
                    {"method": "Network.configureDurableMessages", "sessionId": session_id},
                    time.monotonic(),
                ),
            )
        network_options = {
            "maxTotalBufferSize": self.config.max_total_buffer,
            "maxResourceBufferSize": self.config.max_resource_buffer,
            "maxPostDataSize": self.config.max_post_data,
        }
        self.send(
            "Network.enable",
            network_options,
            session_id,
            PendingCommand(
                "required_command",
                {"method": "Network.enable", "sessionId": session_id},
                time.monotonic(),
            ),
        )
        self.send(
            "Runtime.enable",
            session_id=session_id,
            pending=PendingCommand(
                "required_command",
                {"method": "Runtime.enable", "sessionId": session_id},
                time.monotonic(),
            ),
        )
        if self.config.capture_console:
            self.send("Log.enable", session_id=session_id)
        target_filter = [{"type": item} for item in sorted(TARGET_TYPES)]
        self.send(
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": target_filter,
            },
            session_id,
            PendingCommand(
                "required_command",
                {"method": "Target.setAutoAttach", "sessionId": session_id},
                time.monotonic(),
            ),
        )
        if target_info.get("type") in PAGE_TYPES and self.config.capture_storage:
            # Every localStorage/sessionStorage mutation arrives as an event;
            # the attach-time dump below is the baseline they apply to.
            self.send(
                "DOMStorage.enable",
                session_id=session_id,
                pending=PendingCommand(
                    "capability",
                    {"method": "DOMStorage.enable", "sessionId": session_id},
                    time.monotonic(),
                ),
            )
            self.snapshot("attach", sessions=[session_id], include_cookies=False)
            self.request_cookie_sync("targetAttached")
            if self.config.capture_client_storage:
                self.track_client_storage(session_id, target_info)
        if target_info.get("type") in PAGE_TYPES:
            self.send(
                "Page.enable",
                session_id=session_id,
                pending=PendingCommand(
                    "required_command",
                    {"method": "Page.enable", "sessionId": session_id},
                    time.monotonic(),
                ),
            )
            if self.config.body_mode != "none" and self.config.intercept_bodies != "none":
                self.send(
                    "Fetch.enable",
                    {
                        "patterns": self._interception_patterns(),
                        "handleAuthRequests": False,
                    },
                    session_id,
                    PendingCommand(
                        "required_command",
                        {"method": "Fetch.enable", "sessionId": session_id},
                        time.monotonic(),
                    ),
                )
            if self.config.capture_interactions:
                script = self._interaction_script()
                self.send(
                    "Runtime.addBinding",
                    {"name": self.binding_name, "executionContextName": self.world_name},
                    session_id,
                    PendingCommand("interaction_binding", {"sessionId": session_id}, time.monotonic()),
                )
                self.send(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": script, "worldName": self.world_name, "runImmediately": True},
                    session_id,
                    PendingCommand("interaction_script", {"sessionId": session_id}, time.monotonic()),
                )
        self.send(
            "Runtime.runIfWaitingForDebugger",
            {},
            session_id,
            PendingCommand("optional_command", {"method": "Runtime.runIfWaitingForDebugger"}, time.monotonic()),
        )
        self.store.write_jsonl(
            "browser/targets.jsonl",
            {
                "event": "attached",
                "sessionId": session_id,
                "target": target_info,
                "time": self.timestamps.normalize(),
            },
            redact=True,
        )
        LOG.info("Attached %s %s", target_info.get("type"), (target_info.get("url") or "")[:100])

    def _target(self, session_id: str | None) -> dict[str, Any] | None:
        target = self.targets.get(session_id or "")
        if not target:
            return None
        return {
            key: target.get(key)
            for key in ("targetId", "type", "url", "title", "browserContextId")
            if target.get(key) is not None
        }

    def loop(self) -> None:
        try:
            while self.running.is_set() and self.ws:
                try:
                    raw = self.ws.recv()
                    if raw:
                        self.handle(json.loads(raw))
                except websocket.WebSocketTimeoutException:
                    pass
                except websocket.WebSocketConnectionClosedException:
                    break
                except Exception as exc:
                    if self.running.is_set():
                        LOG.exception("CDP receive loop failed: %s", exc)
                self._process_pending_timeouts()
                self._process_target_fallbacks()
                self._process_finalize_deadlines()
                self._process_cookie_sync()
                self._process_client_storage()
        finally:
            if self.running.is_set():
                self.connection_closed.set()

    def handle(self, message: dict[str, Any]) -> None:
        if "id" in message:
            self._handle_command_response(message)
            return
        method = message.get("method")
        params = message.get("params") or {}
        session_id = message.get("sessionId")
        try:
            if method == "Target.attachedToTarget":
                new_session = params.get("sessionId")
                target_info = params.get("targetInfo") or {}
                target_id = target_info.get("targetId")
                if target_id:
                    with self.state_lock:
                        target_id_s = str(target_id)
                        self.attached_targets.add(target_id_s)
                        self.attach_attempts.pop(target_id_s, None)
                        self.discovered_targets.pop(target_id_s, None)
                if new_session and target_info.get("type") in TARGET_TYPES:
                    self._enable_session(str(new_session), target_info)
            elif method == "Target.targetCreated":
                info = params.get("targetInfo") or {}
                target_id = info.get("targetId")
                if target_id and info.get("type") in TARGET_TYPES:
                    with self.state_lock:
                        self.discovered_targets[str(target_id)] = (time.monotonic() + 0.5, copy.deepcopy(info))
            elif method == "Target.targetInfoChanged":
                self._target_info_changed(params.get("targetInfo") or {})
            elif method == "Target.detachedFromTarget":
                self._detached(str(params.get("sessionId") or ""), "targetDetached")
            elif method == "Target.targetDestroyed":
                target_id = str(params.get("targetId") or "")
                with self.state_lock:
                    self.discovered_targets.pop(target_id, None)
                    self.attached_targets.discard(target_id)
                    self.attach_attempts.pop(target_id, None)
                sid = self.target_sessions.get(target_id)
                if sid:
                    self._detached(sid, "targetDestroyed")
            elif method == "Network.requestWillBeSent":
                self._request_will_be_sent(session_id, params)
            elif method == "Network.requestWillBeSentExtraInfo":
                self._request_extra(session_id, params)
                self.stats["droppedExtraInfo"] = self.registry.dropped_extra
            elif method == "Network.responseReceived":
                self._response_received(session_id, params)
            elif method == "Network.responseReceivedExtraInfo":
                self._response_extra(session_id, params)
                self.stats["droppedExtraInfo"] = self.registry.dropped_extra
            elif method == "Network.responseReceivedEarlyHints":
                self._response_early_hints(session_id, params)
            elif method == "Network.requestServedFromCache":
                self._served_from_cache(session_id, params)
            elif method == "Network.loadingFinished":
                self._loading_finished(session_id, params)
            elif method == "Network.loadingFailed":
                self._loading_failed(session_id, params)
            elif method == "Fetch.requestPaused":
                self._fetch_paused(session_id, params)
            elif method == "Network.webSocketCreated":
                self._websocket_created(session_id, params)
            elif method == "Network.webSocketWillSendHandshakeRequest":
                self._websocket_handshake_request(session_id, params)
            elif method == "Network.webSocketHandshakeResponseReceived":
                self._websocket_handshake_response(session_id, params)
            elif method in {"Network.webSocketFrameSent", "Network.webSocketFrameReceived"}:
                self._websocket_frame(session_id, method, params)
            elif method == "Network.webSocketFrameError":
                self._websocket_error(session_id, params)
            elif method == "Network.webSocketClosed":
                self._websocket_closed(session_id, params)
            elif method == "Network.eventSourceMessageReceived":
                self._sse_message(session_id, params)
            elif method == "Network.webTransportCreated":
                self._webtransport_created(session_id, params)
            elif method == "Network.webTransportConnectionEstablished":
                self._webtransport_established(session_id, params)
            elif method == "Network.webTransportClosed":
                self._webtransport_closed(session_id, params)
            elif method == "Runtime.executionContextCreated":
                context = params.get("context") or {}
                if context.get("name") == self.world_name and context.get("id") is not None:
                    with self.state_lock:
                        self.interaction_contexts.setdefault(session_id or "", set()).add(int(context["id"]))
            elif method == "Runtime.executionContextDestroyed":
                context_id = params.get("executionContextId")
                if context_id is not None:
                    with self.state_lock:
                        self.interaction_contexts.setdefault(session_id or "", set()).discard(int(context_id))
            elif method == "Runtime.executionContextsCleared":
                with self.state_lock:
                    self.interaction_contexts.pop(session_id or "", None)
            elif method == "Runtime.bindingCalled" and params.get("name") == self.binding_name:
                self._binding_message(session_id, params)
            elif method and method.startswith("DOMStorage.") and self.config.capture_storage:
                self._dom_storage_event(session_id, method, params)
            elif method and method.startswith("Storage.") and self.config.capture_client_storage:
                self._storage_domain_event(session_id, method, params)
            elif method == "Runtime.consoleAPICalled" and self.config.capture_console:
                self._console_event(session_id, params)
            elif method == "Runtime.exceptionThrown" and self.config.capture_console:
                self._exception_event(session_id, params)
            elif method == "Log.entryAdded" and self.config.capture_console:
                self._log_entry(session_id, params)
            elif method == "Page.frameNavigated":
                self._navigation_event(session_id, "frameNavigated", params)
            elif method in {"Page.frameStartedLoading", "Page.frameStoppedLoading"}:
                self._navigation_event(session_id, method.rsplit(".", 1)[-1], params)
        except Exception as exc:
            self.stats["eventErrors"] += 1
            LOG.exception("Failed to handle CDP event %s", method)
            try:
                self.store.check_health()
            except Exception as store_exc:
                self._fail_capture("Capture storage failed while handling a CDP event", store_exc)
            if self.stats["eventErrors"] >= 25:
                self._fail_capture("Too many CDP event handler errors", exc)

    def _handle_command_response(self, message: dict[str, Any]) -> None:
        message_id = int(message["id"])
        with self.state_lock:
            pending = self.pending.pop(message_id, None)
        if not pending:
            if message.get("error"):
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {"time": self.timestamps.normalize(), "unmatched": True, "error": message.get("error")},
                    redact=True,
                )
            return
        kind = pending.kind
        data = pending.data
        error = message.get("error")
        result = message.get("result") or {}
        if kind == "capability":
            method = str(data.get("method"))
            self.store.write_jsonl(
                "browser/protocol_capabilities.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": method,
                    "sessionId": data.get("sessionId"),
                    "available": not bool(error),
                    "error": error,
                },
                redact=True,
            )
            return
        if kind == "optional_command":
            if error:
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": data.get("method"),
                        "optional": True,
                        "error": error,
                    },
                    redact=True,
                )
            return
        if kind == "required_command":
            if error:
                self._handle_required_failure(data, error)
            return
        if kind == "interaction_binding":
            if error:
                self.stats["protocolErrors"] += 1
                self.store.add_warning(f"Interaction binding unavailable for session {data.get('sessionId')}: {error}")
            return
        if kind == "interaction_script":
            session_id = str(data.get("sessionId") or "")
            identifier = result.get("identifier")
            if error or not identifier:
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": "Page.addScriptToEvaluateOnNewDocument",
                        "sessionId": session_id,
                        "error": error or {"code": -1, "message": "Chrome returned no script identifier"},
                    },
                    redact=True,
                )
            elif session_id:
                with self.state_lock:
                    self.interaction_script_ids[session_id] = str(identifier)
            return
        if kind == "cookie_sync":
            self._handle_cookie_sync(data, error, result)
            return
        if kind in {"idb_names", "idb_database", "idb_data", "cache_names", "cache_entries"}:
            self._handle_client_storage_response(kind, data, error, result)
            return
        if kind == "quiesce":
            self._finish_quiesce_command(data, error)
            return
        if kind == "attach_target":
            if error:
                target_id = str(data.get("targetId") or "")
                error_text = str(error).lower()
                with self.state_lock:
                    already_captured = target_id in self.target_sessions
                    if not already_captured:
                        self.attached_targets.discard(target_id)
                        if (
                            self.attach_attempts.get(target_id, 0) < 3
                            and "no target" not in error_text
                            and "closed" not in error_text
                        ):
                            self.discovered_targets[target_id] = (
                                time.monotonic() + 0.5,
                                {"targetId": target_id},
                            )
                if not already_captured and "already" not in error_text and "attached" not in error_text:
                    self.store.write_jsonl(
                        "browser/protocol_errors.jsonl",
                        {
                            "time": self.timestamps.normalize(),
                            "method": "Target.attachToTarget",
                            "targetId": target_id,
                            "attempt": self.attach_attempts.get(target_id),
                            "error": error,
                        },
                        redact=True,
                    )
            return
        if kind == "response_body":
            key = str(data["key"])
            with self.state_lock:
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingResponseBody"] = False
                    if error:
                        entry["responseBodyError"] = error
                        self.stats["bodyErrors"] += 1
                    else:
                        self._store_response_body(entry, result.get("body"), bool(result.get("base64Encoded")))
                    self._schedule_finalize(key, reason="loadingFinished")
            return
        if kind == "fetch_body":
            key = str(data["key"])
            fetch_id = str(data["fetchId"])
            session_id = data.get("sessionId")
            with self.state_lock:
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingFetchBody"] = False
                    if error:
                        entry["fetchResponseBodyError"] = error
                        self.stats["bodyErrors"] += 1
                    else:
                        self._store_response_body(
                            entry,
                            result.get("body"),
                            bool(result.get("base64Encoded")),
                            content_type=data.get("contentType"),
                        )
                        entry["_fetchBodyComplete"] = True
                    if entry.get("_loadingComplete"):
                        if error:
                            self._request_network_body_fallback(key, "fetchBodyError")
                        else:
                            self._schedule_finalize(key, reason="loadingFinished")
                self.paused_fetches.pop(fetch_id, None)
            self.send("Fetch.continueResponse", {"requestId": fetch_id}, session_id)
            return
        if kind == "request_post_data":
            key = str(data["key"])
            with self.state_lock:
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingPostData"] = False
                    if error:
                        entry["requestPostDataError"] = error
                    else:
                        self._store_request_body(
                            entry,
                            result.get("postData"),
                            bool(result.get("base64Encoded")),
                        )
                    if entry.get("_loadingComplete"):
                        self._schedule_finalize(key, reason="loadingFinished")
            return
        if kind in {"snapshot_cookies", "snapshot_storage"}:
            self._handle_snapshot_response(kind, data, error, result)

    def _process_pending_timeouts(self) -> None:
        now = time.monotonic()
        expired: list[tuple[int, PendingCommand]] = []
        with self.state_lock:
            for message_id, command in list(self.pending.items()):
                timeout = 15.0 if command.kind == "fetch_body" else 10.0
                if command.kind.startswith("snapshot_"):
                    timeout = max(3.0, self.config.shutdown_wait_seconds)
                elif command.kind == "quiesce":
                    timeout = max(1.0, self.config.shutdown_wait_seconds)
                if now - command.sent_at >= timeout:
                    expired.append((message_id, self.pending.pop(message_id)))
        for _, command in expired:
            kind = command.kind
            data = command.data
            error = {"code": -1, "message": f"CDP command timed out ({kind})"}
            if kind == "fetch_body":
                key = str(data["key"])
                with self.state_lock:
                    entry = self.registry.entries.get(key)
                    if entry:
                        entry["_pendingFetchBody"] = False
                        entry["fetchResponseBodyError"] = error
                        self.stats["bodyErrors"] += 1
                        if entry.get("_loadingComplete"):
                            self._request_network_body_fallback(key, "fetchBodyTimeout")
                fetch_id = str(data["fetchId"])
                with self.state_lock:
                    self.paused_fetches.pop(fetch_id, None)
                self.send("Fetch.continueResponse", {"requestId": fetch_id}, data.get("sessionId"))
            elif kind == "response_body":
                key = str(data["key"])
                with self.state_lock:
                    entry = self.registry.entries.get(key)
                    if entry:
                        entry["_pendingResponseBody"] = False
                        entry["responseBodyError"] = error
                        self.stats["bodyErrors"] += 1
                        self._schedule_finalize(key, "bodyTimeout", delay=0.01)
            elif kind == "request_post_data":
                key = str(data["key"])
                with self.state_lock:
                    entry = self.registry.entries.get(key)
                    if entry:
                        entry["_pendingPostData"] = False
                        entry["requestPostDataError"] = error
                        if entry.get("_loadingComplete"):
                            self._schedule_finalize(key, "postDataTimeout", delay=0.01)
            elif kind in {"snapshot_cookies", "snapshot_storage"}:
                self._handle_snapshot_response(kind, data, error, {})
            elif kind == "cookie_sync":
                self._handle_cookie_sync(data, error, {})
            elif kind in {"idb_names", "idb_database", "idb_data", "cache_names", "cache_entries"}:
                self._handle_client_storage_response(kind, data, error, {})
            elif kind == "interaction_script":
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": "Page.addScriptToEvaluateOnNewDocument",
                        "sessionId": data.get("sessionId"),
                        "error": error,
                    },
                    redact=True,
                )
            elif kind == "quiesce":
                self._finish_quiesce_command(data, error)
            elif kind == "attach_target":
                target_id = str(data.get("targetId") or "")
                with self.state_lock:
                    already_captured = target_id in self.target_sessions
                    if not already_captured:
                        self.attached_targets.discard(target_id)
                        if self.attach_attempts.get(target_id, 0) < 3:
                            self.discovered_targets[target_id] = (
                                time.monotonic() + 0.5,
                                {"targetId": target_id},
                            )
                if already_captured:
                    continue
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": "Target.attachToTarget",
                        "targetId": target_id,
                        "attempt": self.attach_attempts.get(target_id),
                        "error": error,
                    },
                    redact=True,
                )
            elif kind == "capability":
                self.store.write_jsonl(
                    "browser/protocol_capabilities.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": data.get("method"),
                        "sessionId": data.get("sessionId"),
                        "available": False,
                        "error": error,
                    },
                    redact=True,
                )
            elif kind == "optional_command":
                self.store.write_jsonl(
                    "browser/protocol_errors.jsonl",
                    {
                        "time": self.timestamps.normalize(),
                        "method": data.get("method"),
                        "optional": True,
                        "error": error,
                    },
                    redact=True,
                )
            elif kind == "required_command":
                self._handle_required_failure(data, error, timed_out=True)
            elif kind == "interaction_binding":
                self.stats["protocolErrors"] += 1
                self.store.add_warning(f"Interaction binding timed out for session {data.get('sessionId')}")

    def _process_target_fallbacks(self) -> None:
        now = time.monotonic()
        to_attach: list[str] = []
        with self.state_lock:
            for target_id, (deadline, _) in list(self.discovered_targets.items()):
                if target_id in self.target_sessions:
                    self.discovered_targets.pop(target_id, None)
                    continue
                if now >= deadline:
                    self.discovered_targets.pop(target_id, None)
                    if target_id not in self.attached_targets:
                        to_attach.append(target_id)
        for target_id in to_attach:
            self._attach_target(target_id)

    def _target_info_changed(self, info: dict[str, Any]) -> None:
        target_id = str(info.get("targetId") or "")
        session_id = self.target_sessions.get(target_id)
        if not session_id:
            return
        with self.state_lock:
            self.targets[session_id] = copy.deepcopy(info)

    def _detached(self, session_id: str, reason: str) -> None:
        if not session_id:
            return
        with self.state_lock:
            for key in self.registry.keys_for_session(session_id):
                entry = self.registry.entries.get(key)
                if entry:
                    entry["incomplete"] = True
                    entry["incompleteReason"] = reason
                    self.stats["incompleteFlushed"] += 1
                    self._finalize(key, reason)
            for key, connection in list(self.open_websockets.items()):
                if connection.get("sessionId") == session_id:
                    connection["incomplete"] = True
                    connection["incompleteReason"] = reason
                    connection["closed"] = self.timestamps.normalize()
                    self._write_websocket_connection(connection)
                    self.open_websockets.pop(key, None)
            for key, transport in list(self.webtransports.items()):
                if transport.get("sessionId") == session_id:
                    transport["incomplete"] = True
                    transport["incompleteReason"] = reason
                    self._write_webtransport(transport)
                    self.webtransports.pop(key, None)
            target = self.targets.pop(session_id, None)
            self.interaction_script_ids.pop(session_id, None)
            self.interaction_contexts.pop(session_id, None)
            self.enabled_sessions.discard(session_id)
            page_gone = bool(target and target.get("type") in PAGE_TYPES)
            if target and target.get("targetId"):
                target_id = str(target["targetId"])
                self.target_sessions.pop(target_id, None)
                self.attached_targets.discard(target_id)
        self.store.write_jsonl(
            "browser/targets.jsonl",
            {
                "event": "detached",
                "sessionId": session_id,
                "target": target,
                "reason": reason,
                "time": self.timestamps.normalize(),
            },
            redact=True,
        )
        if page_gone:
            # A closing page may have written cookies the jar still holds.
            self.request_cookie_sync("targetDetached")

    def wait_for_pending_data(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        data_kinds = {"response_body", "fetch_body", "request_post_data"}
        while time.monotonic() < deadline:
            with self.state_lock:
                if not any(command.kind in data_kinds for command in self.pending.values()):
                    return True
            time.sleep(0.05)
        return False

    def _finish_quiesce_command(self, data: dict[str, Any], error: Any) -> None:
        if error:
            self.store.write_jsonl(
                "browser/protocol_errors.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": data.get("method"),
                    "sessionId": data.get("sessionId"),
                    "phase": "quiesce",
                    "error": error,
                },
                redact=True,
            )
        with self._quiesce_condition:
            self._quiesce_pending = max(0, self._quiesce_pending - 1)
            self._quiesce_condition.notify_all()

    def _send_quiesce(self, method: str, params: dict[str, Any] | None = None, session_id: str | None = None) -> None:
        with self._quiesce_condition:
            self._quiesce_pending += 1
        self.send(
            method,
            params or {},
            session_id,
            PendingCommand(
                "quiesce",
                {"method": method, "sessionId": session_id},
                time.monotonic(),
            ),
        )

    def quiesce(self, timeout: float | None = None) -> bool:
        """Release pauses and remove instrumentation before disconnecting CDP."""
        self._quiescing = True
        teardown = (
            "(() => { try { const state = window["
            + json.dumps(self.install_marker)
            + "]; if (state && typeof state.abort === 'function') state.abort(); "
            + "delete window["
            + json.dumps(self.install_marker)
            + "]; } catch (_) {} })()"
        )
        with self.state_lock:
            paused = dict(self.paused_fetches)
            self.paused_fetches.clear()
            for message_id, command in list(self.pending.items()):
                if command.kind != "fetch_body":
                    continue
                self.pending.pop(message_id, None)
                key = str(command.data.get("key") or "")
                entry = self.registry.entries.get(key)
                if entry:
                    entry["_pendingFetchBody"] = False
                    entry.setdefault(
                        "responseBodyError",
                        {"code": -1, "message": "Capture stopped while Fetch response was paused"},
                    )
            sessions = list(self.targets.items())
            script_ids = dict(self.interaction_script_ids)
            interaction_contexts = {
                session_id: set(contexts) for session_id, contexts in self.interaction_contexts.items()
            }
        for fetch_id, (session_id, _) in paused.items():
            self._send_quiesce("Fetch.continueResponse", {"requestId": fetch_id}, session_id)
        auto_attach_off = {
            "autoAttach": False,
            "waitForDebuggerOnStart": False,
            "flatten": True,
        }
        for session_id, info in sessions:
            if info.get("type") in PAGE_TYPES:
                if self.config.body_mode != "none":
                    self._send_quiesce("Fetch.disable", {}, session_id)
                if self.config.capture_storage:
                    self._send_quiesce("DOMStorage.disable", {}, session_id)
                if self.config.capture_interactions:
                    for context_id in interaction_contexts.get(session_id, set()):
                        self._send_quiesce(
                            "Runtime.evaluate",
                            {"expression": teardown, "contextId": context_id},
                            session_id,
                        )
                    identifier = script_ids.get(session_id)
                    if identifier:
                        self._send_quiesce(
                            "Page.removeScriptToEvaluateOnNewDocument",
                            {"identifier": identifier},
                            session_id,
                        )
                    self._send_quiesce("Runtime.removeBinding", {"name": self.binding_name}, session_id)
            self._send_quiesce("Target.setAutoAttach", auto_attach_off, session_id)
        self._send_quiesce("Target.setAutoAttach", auto_attach_off)
        self._send_quiesce("Target.setDiscoverTargets", {"discover": False})

        deadline = time.monotonic() + (self.config.shutdown_wait_seconds if timeout is None else timeout)
        with self._quiesce_condition:
            while self._quiesce_pending > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._quiesce_condition.wait(timeout=remaining)
        return True

    def flush_open(self, reason: str = "shutdown") -> None:
        with self.state_lock:
            for key in list(self.registry.entries):
                entry = self.registry.entries.get(key)
                if entry:
                    entry["incomplete"] = True
                    entry["incompleteReason"] = reason
                    entry.setdefault("finished", self.timestamps.normalize())
                    self.stats["incompleteFlushed"] += 1
                    self._finalize(key, reason)
            for key, connection in list(self.open_websockets.items()):
                connection["incomplete"] = True
                connection["incompleteReason"] = reason
                connection["closed"] = self.timestamps.normalize()
                self._write_websocket_connection(connection)
                self.open_websockets.pop(key, None)
            for key, transport in list(self.webtransports.items()):
                transport["incomplete"] = True
                transport["incompleteReason"] = reason
                self._write_webtransport(transport)
                self.webtransports.pop(key, None)

    def stop(self) -> None:
        self.running.clear()
        if self.ws:
            try:
                self.ws.close()
            except Exception as exc:
                LOG.debug("Could not close the CDP WebSocket cleanly: %s", exc)
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)
