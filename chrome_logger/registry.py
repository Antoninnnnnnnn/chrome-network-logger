from __future__ import annotations

from typing import Any


class RequestRegistry:
    """Keep request IDs unique across sessions and redirect hops.

    ``requestWillBeSentExtraInfo`` and ``responseReceivedExtraInfo`` can arrive
    before or after their companion events. ExtraInfo is therefore queued per
    ``(sessionId, requestId)`` and only matched when the target hop is known.
    """

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.active: dict[str, str] = {}
        self.hops: dict[str, int] = {}
        self.keys_by_base: dict[str, list[str]] = {}
        self.pending_request_extra: dict[str, list[dict[str, Any]]] = {}
        self.pending_response_extra: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def base_key(session_id: str | None, request_id: str) -> str:
        return f"{session_id or 'root'}::{request_id}"

    def current(self, session_id: str | None, request_id: str) -> tuple[str | None, dict[str, Any] | None]:
        base = self.base_key(session_id, request_id)
        key = self.active.get(base)
        return key, self.entries.get(key) if key else None

    def create(self, session_id: str | None, request_id: str, entry: dict[str, Any]) -> str:
        base = self.base_key(session_id, request_id)
        hop = self.hops.get(base, -1) + 1
        self.hops[base] = hop
        key = f"{base}::hop{hop}"
        entry["id"] = key
        entry["hop"] = hop
        self.entries[key] = entry
        self.active[base] = key
        self.keys_by_base.setdefault(base, []).append(key)
        self._drain_request_extra(base)
        self._drain_response_extra(base)
        return key

    def pop(self, key: str) -> dict[str, Any] | None:
        entry = self.entries.pop(key, None)
        if not entry:
            return None
        base = self.base_key(entry.get("sessionId"), str(entry.get("requestId")))
        keys = self.keys_by_base.get(base)
        if keys and key in keys:
            keys.remove(key)
            if not keys:
                self.keys_by_base.pop(base, None)
                self.pending_request_extra.pop(base, None)
                self.pending_response_extra.pop(base, None)
        if self.active.get(base) == key:
            self.active.pop(base, None)
        return entry

    def _assign(self, key: str, side: str, payload: dict[str, Any]) -> None:
        entry = self.entries[key]
        entry.setdefault("extraInfo", {})[side] = payload
        if side == "response":
            entry["_responseExtraSeen"] = True

    def _drain_request_extra(self, base: str) -> list[str]:
        queue = self.pending_request_extra.get(base)
        if not queue:
            return []
        assigned: list[str] = []
        for key in self.keys_by_base.get(base, []):
            entry = self.entries.get(key)
            if not entry or "request" in entry.get("extraInfo", {}):
                continue
            self._assign(key, "request", queue.pop(0))
            assigned.append(key)
            if not queue:
                break
        if not queue:
            self.pending_request_extra.pop(base, None)
        return assigned

    def _drain_response_extra(self, base: str) -> list[str]:
        queue = self.pending_response_extra.get(base)
        if not queue:
            return []
        assigned: list[str] = []
        for key in self.keys_by_base.get(base, []):
            entry = self.entries.get(key)
            if not entry:
                continue
            # Do not guess while responseReceived/redirectHasExtraInfo has not
            # told us whether this hop expects an ExtraInfo event.
            if entry.get("_expectedResponseExtra") is not True:
                continue
            if "response" in entry.get("extraInfo", {}):
                continue
            self._assign(key, "response", queue.pop(0))
            assigned.append(key)
            if not queue:
                break
        if not queue:
            self.pending_response_extra.pop(base, None)
        return assigned

    def assign_extra(
        self,
        session_id: str | None,
        request_id: str,
        side: str,
        payload: dict[str, Any],
    ) -> str | None:
        base = self.base_key(session_id, request_id)
        if side == "request":
            self.pending_request_extra.setdefault(base, []).append(payload)
            assigned = self._drain_request_extra(base)
        elif side == "response":
            self.pending_response_extra.setdefault(base, []).append(payload)
            assigned = self._drain_response_extra(base)
        else:
            raise ValueError(f"Unknown ExtraInfo side: {side}")
        return assigned[0] if assigned else None

    def set_response_extra_expected(self, key: str, expected: bool) -> list[str]:
        entry = self.entries.get(key)
        if not entry:
            return []
        entry["_expectedResponseExtra"] = bool(expected)
        base = self.base_key(entry.get("sessionId"), str(entry.get("requestId")))
        return self._drain_response_extra(base)

    def keys_for_session(self, session_id: str) -> list[str]:
        return [key for key, entry in self.entries.items() if entry.get("sessionId") == session_id]
