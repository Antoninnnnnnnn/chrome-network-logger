from __future__ import annotations

import copy
import json
import time
from typing import Any

from .models import PendingCommand

COOKIE_SYNC_DEBOUNCE_SECONDS = 0.2
DOM_STORAGE_CHANGES = {
    "DOMStorage.domStorageItemAdded": "added",
    "DOMStorage.domStorageItemUpdated": "updated",
    "DOMStorage.domStorageItemRemoved": "removed",
    "DOMStorage.domStorageItemsCleared": "cleared",
}


class StateCaptureMixin:
    """Record cookie and Web Storage state from events instead of samples.

    Cookies and Web Storage live inside the browser, so closing the window
    destroys everything that was not read yet. Sampling on a timer loses every
    change made between two samples, so state is captured as it changes:

    * `DOMStorage` events give every localStorage/sessionStorage mutation, with
      an attach-time dump as the baseline the events are applied to.
    * The cookie jar is re-read after each event that can change it (Set-Cookie
      response, navigation, target attach/detach, injected flush) and stored as
      a diff, coalesced so a burst costs one read.
    * The injected script flushes a full dump on `pagehide`, `freeze`, and
      `visibilitychange`, which is the last moment a dying page is readable.

    The reconstructed final state is therefore already in memory when the
    browser exits and needs no live connection to be written out.
    """

    # ------------------------------------------------------------------ cookies

    def request_cookie_sync(self, reason: str) -> None:
        """Ask for a cookie-jar read; bursts collapse into a single read."""
        if not self.config.capture_storage or not self.is_live():
            return
        with self.state_lock:
            self._cookie_sync_reasons.add(reason)

    def _process_cookie_sync(self) -> None:
        if not self.config.capture_storage or self._quiescing:
            return
        now = time.monotonic()
        with self.state_lock:
            if not self._cookie_sync_reasons or self._cookie_sync_inflight:
                return
            if now < self._cookie_sync_earliest:
                return
            reasons = sorted(self._cookie_sync_reasons)
            self._cookie_sync_reasons.clear()
            self._cookie_sync_inflight = True
            self._cookie_sync_earliest = now + COOKIE_SYNC_DEBOUNCE_SECONDS
        self.send(
            "Storage.getCookies",
            {},
            pending=PendingCommand("cookie_sync", {"reasons": reasons}, time.monotonic()),
        )

    @staticmethod
    def _cookie_identity(cookie: dict[str, Any]) -> str:
        partition = cookie.get("partitionKey")
        if not isinstance(partition, (str, type(None))):
            partition = json.dumps(partition, sort_keys=True, default=str)
        return json.dumps(
            [cookie.get("name"), cookie.get("domain"), cookie.get("path"), partition],
            sort_keys=True,
            default=str,
        )

    def _handle_cookie_sync(self, data: dict[str, Any], error: Any, result: dict[str, Any]) -> None:
        with self.state_lock:
            self._cookie_sync_inflight = False
        reasons = list(data.get("reasons") or [])
        if error:
            self.store.write_jsonl(
                "browser/protocol_errors.jsonl",
                {
                    "time": self.timestamps.normalize(),
                    "method": "Storage.getCookies",
                    "phase": "cookieSync",
                    "reasons": reasons,
                    "error": error,
                },
                redact=True,
            )
            return
        cookies = [copy.deepcopy(cookie) for cookie in result.get("cookies") or []]
        current = {self._cookie_identity(cookie): cookie for cookie in cookies}
        with self.state_lock:
            previous = self._cookie_state
            self._cookie_state = current
            baseline = not self._cookie_baseline_written
            self._cookie_baseline_written = True
        self.stats["cookieSyncs"] += 1
        changes: list[dict[str, Any]] = []
        for identity, cookie in current.items():
            before = previous.get(identity)
            if before is None:
                changes.append({"change": "added", "cookie": cookie})
            elif before != cookie:
                changes.append({"change": "updated", "cookie": cookie, "previous": before})
        for identity, cookie in previous.items():
            if identity not in current:
                changes.append({"change": "removed", "cookie": cookie})
        if not changes:
            return
        self.stats["cookieChanges"] += len(changes)
        self.store.write_jsonl(
            "storage/cookie_changes.jsonl",
            {
                "time": self.timestamps.normalize(),
                "reasons": reasons,
                "baseline": baseline,
                "cookieCount": len(cookies),
                "changes": changes,
            },
            redact=True,
        )

    def note_response_cookies(self, session_id: str | None, headers: dict[str, Any] | None) -> None:
        """Trigger a cookie read when a response carried Set-Cookie."""
        if not headers:
            return
        for name in headers:
            if str(name).lower() == "set-cookie":
                self.request_cookie_sync("setCookieHeader")
                return

    def _binding_message(self, session_id: str | None, params: dict[str, Any]) -> None:
        """Route an injected-script message to storage or interaction capture."""
        try:
            payload = json.loads(str(params.get("payload") or ""))
        except Exception:
            payload = None
        if isinstance(payload, dict) and payload.get("event") == "storage_state":
            self._storage_flush(session_id, params, payload)
            return
        self._user_event(session_id, params)

    # ------------------------------------------------------------- web storage

    @staticmethod
    def _dom_storage_key(origin: str, is_local: bool) -> str:
        return json.dumps([str(origin or "").rstrip("/"), bool(is_local)])

    def _dom_storage_mirror(self, key: str, storage_id: dict[str, Any], source: str) -> dict[str, Any]:
        mirror = self._dom_storage.get(key)
        if mirror is None:
            mirror = {"storageId": storage_id, "values": {}, "sources": []}
            self._dom_storage[key] = mirror
        if source not in mirror["sources"]:
            mirror["sources"].append(source)
        return mirror

    def _dom_storage_event(self, session_id: str | None, method: str, params: dict[str, Any]) -> None:
        change = DOM_STORAGE_CHANGES.get(method)
        if not change:
            return
        storage_id = copy.deepcopy(params.get("storageId") or {})
        origin = storage_id.get("storageKey") or storage_id.get("securityOrigin") or ""
        is_local = bool(storage_id.get("isLocalStorage"))
        key = self._dom_storage_key(str(origin), is_local)
        item_key = params.get("key")
        with self.state_lock:
            mirror = self._dom_storage_mirror(key, storage_id, "events")
            values = mirror["values"]
            if change == "cleared":
                values.clear()
            elif change == "removed":
                values.pop(str(item_key), None)
            else:
                values[str(item_key)] = params.get("newValue")
        self.stats["storageChanges"] += 1
        self.store.write_jsonl(
            "storage/dom_storage_events.jsonl",
            {
                "time": self.timestamps.normalize(),
                "sessionId": session_id,
                "target": self._target(session_id),
                "change": change,
                "storageId": storage_id,
                "isLocalStorage": is_local,
                "key": item_key,
                "newValue": params.get("newValue"),
                "oldValue": params.get("oldValue"),
            },
            redact=True,
        )

    def seed_dom_storage(self, origin: str, dump: dict[str, Any] | None, source: str) -> None:
        """Apply a full page dump as the baseline the events build on."""
        if not isinstance(dump, dict):
            return
        for field, is_local in (("localStorage", True), ("sessionStorage", False)):
            section = dump.get(field)
            if not isinstance(section, dict) or not section.get("ok"):
                continue
            values = section.get("values")
            if not isinstance(values, dict):
                continue
            key = self._dom_storage_key(origin, is_local)
            storage_id = {"securityOrigin": origin, "isLocalStorage": is_local}
            with self.state_lock:
                mirror = self._dom_storage_mirror(key, storage_id, source)
                mirror["values"].update({str(name): value for name, value in values.items()})

    def _storage_flush(self, session_id: str | None, params: dict[str, Any], payload: dict[str, Any]) -> None:
        """Store the dump the injected script sends when a page is going away."""
        payload_size = len(str(params.get("payload") or "").encode("utf-8", errors="replace"))
        if payload_size > self.config.max_storage_payload_bytes:
            self.stats["droppedStorageFlushes"] += 1
            self.store.add_warning(
                f"Dropped an oversized storage flush ({payload_size} bytes; "
                f"limit {self.config.max_storage_payload_bytes})"
            )
            return
        context_id = params.get("executionContextId")
        if context_id is not None:
            with self.state_lock:
                allowed = int(context_id) in self.interaction_contexts.get(session_id or "", set())
            if not allowed:
                self.stats["droppedStorageFlushes"] += 1
                return
        origin = str(payload.get("origin") or "")
        trigger = str(payload.get("trigger") or "unknown")
        self.seed_dom_storage(origin, payload, f"flush:{trigger}")
        self.stats["storageFlushes"] += 1
        self.store.write_jsonl(
            "storage/page_flushes.jsonl",
            {
                "time": self.timestamps.from_epoch_ms(payload.get("ts")),
                "sessionId": session_id,
                "target": self._target(session_id),
                "trigger": trigger,
                "url": payload.get("url"),
                "origin": origin,
                "localStorage": payload.get("localStorage"),
                "sessionStorage": payload.get("sessionStorage"),
                "cookie": payload.get("cookie"),
            },
            redact=True,
        )
        # The jar is browser-level, so it survives the page and can still be read.
        self.request_cookie_sync(f"pageFlush:{trigger}")

    # -------------------------------------------------------------- final state

    def write_final_state(self) -> None:
        """Write the reconstructed end state; needs no live browser."""
        if not self.config.capture_storage:
            return
        with self.state_lock:
            cookies = [copy.deepcopy(cookie) for cookie in self._cookie_state.values()]
            origins = []
            for key, mirror in self._dom_storage.items():
                origins.append(
                    {
                        "key": json.loads(key),
                        "storageId": copy.deepcopy(mirror["storageId"]),
                        "sources": list(mirror["sources"]),
                        "values": dict(mirror["values"]),
                    }
                )
        self.store.write_json(
            "snapshots/cookies_final.json",
            {
                "time": self.timestamps.normalize(),
                "source": "eventStream",
                "cookieCount": len(cookies),
                "cookies": cookies,
            },
            redact=True,
        )
        self.store.write_json(
            "snapshots/dom_storage_final.json",
            {
                "time": self.timestamps.normalize(),
                "source": "attachDumpPlusEvents",
                "originCount": len(origins),
                "origins": origins,
            },
            redact=True,
        )
