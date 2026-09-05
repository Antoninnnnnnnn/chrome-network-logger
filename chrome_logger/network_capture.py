from __future__ import annotations

import copy
import time
from typing import Any

from .constants import API_TYPES, REDIRECT_CODES, STREAMING_CONTENT_TYPES, WRITE_METHODS
from .models import PendingCommand


class NetworkCaptureMixin:
    def _request_will_be_sent(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        request_id = str(request_id)
        request = copy.deepcopy(params.get("request") or {})
        redirect_response = params.get("redirectResponse")
        with self.state_lock:
            previous_key, previous = self.registry.current(session_id, request_id)
            if redirect_response is not None and previous_key and previous:
                previous["response"] = copy.deepcopy(redirect_response)
                previous["isRedirect"] = True
                previous["redirectTo"] = request.get("url")
                previous["responseBodyUnavailableReason"] = "CDP does not expose redirect response bodies"
                assigned = self.registry.set_response_extra_expected(
                    previous_key,
                    bool(params.get("redirectHasExtraInfo")),
                )
                previous["finished"] = self.timestamps.normalize(params.get("timestamp"))
                self.stats["redirects"] += 1
                self.stats["responses"] += 1
                self._schedule_finalize(previous_key, reason="redirect", delay=0.15, hard_delay=2.0)
                for assigned_key in assigned:
                    if assigned_key in self.finalize_deadlines:
                        self._schedule_finalize(assigned_key, reason="redirect", delay=0.05)

            started = self.timestamps.normalize(params.get("timestamp"), params.get("wallTime"))
            entry: dict[str, Any] = {
                "schemaVersion": 3,
                "requestId": request_id,
                "sessionId": session_id,
                "target": self._target(session_id),
                "started": started,
                "type": params.get("type", "Other"),
                "loaderId": params.get("loaderId"),
                "frameId": params.get("frameId"),
                "documentURL": params.get("documentURL"),
                "initiator": copy.deepcopy(params.get("initiator")),
                "request": request,
            }
            key = self.registry.create(session_id, request_id, entry)
            self.stats["requests"] += 1
            post_data = entry["request"].pop("postData", None)
            post_entries = entry["request"].pop("postDataEntries", None)
            capture_request_body = self.config.body_mode != "none"
            if capture_request_body and post_data is not None:
                self._store_request_body(entry, post_data, False)
            if capture_request_body and post_entries:
                self._store_request_body_entries(entry, post_entries)
            if capture_request_body and post_data is None and request.get("hasPostData"):
                entry["_pendingPostData"] = True
                self.send(
                    "Network.getRequestPostData",
                    {"requestId": request_id},
                    session_id,
                    PendingCommand("request_post_data", {"key": key}, time.monotonic()),
                )
        self.store.timeline(
            "request_started",
            started,
            id=key,
            sessionId=session_id,
            type=entry.get("type"),
            method=request.get("method"),
            url=request.get("url"),
        )

    def _request_extra(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        payload = {
            "headers": copy.deepcopy(params.get("headers") or {}),
            "associatedCookies": copy.deepcopy(params.get("associatedCookies") or []),
            "connectTiming": copy.deepcopy(params.get("connectTiming")),
            "clientSecurityState": copy.deepcopy(params.get("clientSecurityState")),
            "siteHasCookieInOtherPartition": params.get("siteHasCookieInOtherPartition"),
        }
        with self.state_lock:
            self.registry.assign_extra(session_id, str(request_id), "request", payload)

    def _response_received(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        with self.state_lock:
            key, entry = self.registry.current(session_id, str(request_id))
            if not key or not entry:
                return
            previous_response = entry.get("response") or {}
            body_reference = previous_response.get("body")
            entry["response"] = copy.deepcopy(params.get("response") or {})
            if body_reference is not None:
                entry["response"]["body"] = body_reference
            entry["type"] = params.get("type", entry.get("type"))
            assigned = self.registry.set_response_extra_expected(key, bool(params.get("hasExtraInfo")))
            self.stats["responses"] += 1
            for assigned_key in assigned:
                if assigned_key in self.finalize_deadlines:
                    self._schedule_finalize(assigned_key, reason=self.finalize_deadlines[assigned_key][2], delay=0.05)
        self.note_response_cookies(session_id, (params.get("response") or {}).get("headers"))

    def _response_extra(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        payload = {
            "statusCode": params.get("statusCode"),
            "headers": copy.deepcopy(params.get("headers") or {}),
            "headersText": params.get("headersText"),
            "blockedCookies": copy.deepcopy(params.get("blockedCookies") or []),
            "resourceIPAddressSpace": params.get("resourceIPAddressSpace"),
            "cookiePartitionKey": copy.deepcopy(params.get("cookiePartitionKey")),
            "cookiePartitionKeyOpaque": params.get("cookiePartitionKeyOpaque"),
            "exemptedCookies": copy.deepcopy(params.get("exemptedCookies") or []),
        }
        with self.state_lock:
            key = self.registry.assign_extra(session_id, str(request_id), "response", payload)
            if key and key in self.finalize_deadlines:
                self._schedule_finalize(key, reason=self.finalize_deadlines[key][2], delay=0.05)
        self.note_response_cookies(session_id, payload["headers"])

    def _response_early_hints(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        with self.state_lock:
            _, entry = self.registry.current(session_id, str(request_id))
            if entry:
                entry.setdefault("earlyHints", []).append(
                    {
                        "headers": copy.deepcopy(params.get("headers") or {}),
                        "time": self.timestamps.normalize(params.get("timestamp")),
                    }
                )

    def _served_from_cache(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        with self.state_lock:
            _, entry = self.registry.current(session_id, str(request_id))
            if entry:
                entry["servedFromCache"] = True

    def _loading_finished(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        with self.state_lock:
            key, entry = self.registry.current(session_id, str(request_id))
            if not key or not entry:
                return
            entry["encodedDataLength"] = params.get("encodedDataLength")
            entry["finished"] = self.timestamps.normalize(params.get("timestamp"))
            entry["_loadingComplete"] = True
            if (
                entry.get("_fetchBodyComplete")
                or not self._should_capture_body(entry)
                or not self._response_can_have_body(entry)
            ):
                self._schedule_finalize(key, reason="loadingFinished")
                return
            if entry.get("_pendingFetchBody"):
                return
            if entry.get("_pendingResponseBody"):
                return
            entry["_pendingResponseBody"] = True
            self.send(
                "Network.getResponseBody",
                {"requestId": str(request_id)},
                session_id,
                PendingCommand("response_body", {"key": key}, time.monotonic()),
            )

    def _loading_failed(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        with self.state_lock:
            key, entry = self.registry.current(session_id, str(request_id))
            if not key or not entry:
                return
            entry["failure"] = {
                field: copy.deepcopy(params.get(field))
                for field in ("timestamp", "type", "errorText", "canceled", "blockedReason", "corsErrorStatus")
            }
            entry["finished"] = self.timestamps.normalize(params.get("timestamp"))
            entry["_loadingComplete"] = True
            self.stats["failures"] += 1
            self._schedule_finalize(key, reason="loadingFailed", delay=0.05)

    def _fetch_paused(self, session_id: str | None, params: dict[str, Any]) -> None:
        fetch_id = params.get("requestId")
        network_id = params.get("networkId")
        if not fetch_id:
            return
        fetch_id = str(fetch_id)
        if self._quiescing:
            method = (
                "Fetch.continueResponse"
                if (params.get("responseStatusCode") is not None or params.get("responseErrorReason") is not None)
                else "Fetch.continueRequest"
            )
            self.send(method, {"requestId": fetch_id}, session_id)
            return
        if params.get("responseStatusCode") is None and params.get("responseErrorReason") is None:
            self.send("Fetch.continueRequest", {"requestId": fetch_id}, session_id)
            return
        status = params.get("responseStatusCode")
        if params.get("responseErrorReason") or status in REDIRECT_CODES or status in {204, 205, 304} or not network_id:
            self.send("Fetch.continueResponse", {"requestId": fetch_id}, session_id)
            return
        headers = params.get("responseHeaders") or []
        header_value = {str(item.get("name", "")).lower(): str(item.get("value", "")) for item in headers}
        content_type = header_value.get("content-type")
        with self.state_lock:
            key, entry = self.registry.current(session_id, str(network_id))
            if not key or not entry:
                self.send("Fetch.continueResponse", {"requestId": fetch_id}, session_id)
                return
            if not self._should_capture_body(entry) or self._body_must_stream(content_type, header_value):
                # Taking the body here would buffer the whole response inside
                # Chrome, which stalls streamed responses and large downloads.
                # Let it flow and rely on Network.getResponseBody instead.
                self.stats["interceptionBypassed"] += 1
                self.send("Fetch.continueResponse", {"requestId": fetch_id}, session_id)
                return
            entry["_pendingFetchBody"] = True
            self.paused_fetches[fetch_id] = (session_id, key)
            self.send(
                "Fetch.getResponseBody",
                {"requestId": fetch_id},
                session_id,
                PendingCommand(
                    "fetch_body",
                    {
                        "key": key,
                        "fetchId": fetch_id,
                        "sessionId": session_id,
                        "contentType": content_type,
                    },
                    time.monotonic(),
                ),
            )

    def _body_must_stream(self, content_type: str | None, headers: dict[str, str]) -> bool:
        """Report whether pausing for the body would break or bloat the response."""
        normalized = (content_type or "").lower()
        if any(marker in normalized for marker in STREAMING_CONTENT_TYPES):
            return True
        length = headers.get("content-length")
        limit = self.config.max_body_bytes
        if limit and length and length.isdigit() and int(length) > limit:
            return True
        return False

    def _content_type(self, entry: dict[str, Any], request: bool = False) -> str | None:
        container = entry.get("request") if request else entry.get("response")
        headers = (container or {}).get("headers") or {}
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
        extra_side = "request" if request else "response"
        extra_headers = ((entry.get("extraInfo") or {}).get(extra_side) or {}).get("headers") or {}
        for key, value in extra_headers.items():
            if str(key).lower() == "content-type":
                return str(value)
        return None

    def _request_network_body_fallback(self, key: str, reason: str) -> None:
        entry = self.registry.entries.get(key)
        if not entry:
            return
        if entry.get("_pendingResponseBody"):
            return
        if not self._should_capture_body(entry) or not self._response_can_have_body(entry):
            self._schedule_finalize(key, reason=reason, delay=0.01)
            return
        entry["_pendingResponseBody"] = True
        self.send(
            "Network.getResponseBody",
            {"requestId": str(entry.get("requestId"))},
            entry.get("sessionId"),
            PendingCommand("response_body", {"key": key}, time.monotonic()),
        )

    def _store_request_body(self, entry: dict[str, Any], body: Any, base64_encoded: bool) -> None:
        if body is None:
            return
        reference = self.store.store_body(
            body,
            base64_encoded=base64_encoded,
            content_type=self._content_type(entry, request=True),
            role="request",
        )
        if reference:
            entry.setdefault("request", {})["body"] = reference

    def _store_request_body_entries(self, entry: dict[str, Any], parts: Any) -> None:
        if not isinstance(parts, list):
            return
        stored: list[dict[str, Any]] = []
        for index, part in enumerate(parts):
            if not isinstance(part, dict):
                continue
            item = {key: copy.deepcopy(value) for key, value in part.items() if key != "bytes"}
            encoded = part.get("bytes")
            if encoded is not None:
                reference = self.store.store_body(
                    str(encoded),
                    base64_encoded=True,
                    content_type=self._content_type(entry, request=True),
                    role=f"request-part-{index}",
                )
                if reference:
                    item["body"] = reference
            stored.append(item)
        if stored:
            entry.setdefault("request", {})["postDataEntries"] = stored

    def _store_response_body(
        self,
        entry: dict[str, Any],
        body: Any,
        base64_encoded: bool,
        content_type: str | None = None,
    ) -> None:
        reference = self.store.store_body(
            body,
            base64_encoded=base64_encoded,
            content_type=content_type or self._content_type(entry),
            role="response",
        )
        if reference:
            entry.setdefault("response", {})["body"] = reference
            self.stats["bodies"] += 1

    def _should_capture_body(self, entry: dict[str, Any]) -> bool:
        if self.config.body_mode == "none":
            return False
        resource_type = str(entry.get("type") or "Other")
        if self.config.body_mode == "all":
            return resource_type not in {"WebSocket", "EventSource"}
        return resource_type in {"XHR", "Fetch", "Document"}

    @staticmethod
    def _response_can_have_body(entry: dict[str, Any]) -> bool:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        method = str(request.get("method") or "GET").upper()
        status = int(response.get("status") or 0)
        if method == "HEAD" or status in {204, 205, 304} or status in REDIRECT_CODES:
            return False
        return bool(response)

    def _schedule_finalize(
        self,
        key: str,
        reason: str | None,
        delay: float | None = None,
        hard_delay: float = 2.0,
    ) -> None:
        now = time.monotonic()
        soft = now + (self.config.finalize_grace_seconds if delay is None else delay)
        hard = now + hard_delay
        current = self.finalize_deadlines.get(key)
        if current:
            soft = min(soft, current[0])
            hard = max(hard, current[1])
            reason = reason or current[2]
        self.finalize_deadlines[key] = (soft, hard, reason)

    def _process_finalize_deadlines(self) -> None:
        now = time.monotonic()
        with self.state_lock:
            for key, (soft, hard, reason) in list(self.finalize_deadlines.items()):
                if now < soft:
                    continue
                entry = self.registry.entries.get(key)
                if not entry:
                    self.finalize_deadlines.pop(key, None)
                    continue
                waiting_command = bool(
                    entry.get("_pendingPostData") or entry.get("_pendingResponseBody") or entry.get("_pendingFetchBody")
                )
                if waiting_command:
                    # The matching command timeout handler owns the deadline.
                    # Finalizing here would silently discard a slow body/postData
                    # response before its documented 10–15 second timeout.
                    self.finalize_deadlines[key] = (now + 0.1, hard, reason)
                    continue
                waiting_extra = bool(entry.get("_expectedResponseExtra") and not entry.get("_responseExtraSeen"))
                if waiting_extra and now < hard:
                    self.finalize_deadlines[key] = (now + 0.1, hard, reason)
                    continue
                if waiting_extra:
                    entry["extraInfoIncomplete"] = True
                self._finalize(key, reason)

    def _is_api(self, entry: dict[str, Any]) -> bool:
        request = entry.get("request") or {}
        method = str(request.get("method") or "").upper()
        resource_type = str(entry.get("type") or "")
        if resource_type in API_TYPES or method in WRITE_METHODS:
            return True
        content_type = (self._content_type(entry, request=True) or "").lower()
        return "json" in content_type or "graphql" in content_type

    def _finalize(self, key: str, reason: str | None = None) -> None:
        entry = self.registry.pop(key)
        self.finalize_deadlines.pop(key, None)
        if not entry:
            return
        entry["isApi"] = self._is_api(entry)
        if reason:
            entry["finalizeReason"] = reason
        started_ms = (entry.get("started") or {}).get("epochMs")
        finished_ms = (entry.get("finished") or {}).get("epochMs")
        if started_ms is not None and finished_ms is not None:
            entry["durationMs"] = max(0, finished_ms - started_ms)
        for private_key in [key_name for key_name in entry if key_name.startswith("_")]:
            entry.pop(private_key, None)
        self.store.write_jsonl("network/requests.jsonl", entry, redact=True)
        self.store.timeline(
            "request_finished",
            entry.get("finished") or self.timestamps.normalize(),
            id=entry.get("id"),
            type=entry.get("type"),
            isApi=entry.get("isApi"),
            status=(entry.get("response") or {}).get("status"),
            failed=bool(entry.get("failure")),
        )
