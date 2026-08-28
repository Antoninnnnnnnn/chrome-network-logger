from __future__ import annotations

import base64
import copy
from typing import Any


class RealtimeCaptureMixin:
    def _websocket_key(self, session_id: str | None, request_id: str) -> str:
        return f"{session_id or 'root'}::{request_id}"

    def _websocket_created(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        key = self._websocket_key(session_id, str(request_id))
        entry = {
            "id": key,
            "requestId": request_id,
            "sessionId": session_id,
            "target": self._target(session_id),
            "type": "WebSocket",
            "url": params.get("url"),
            "initiator": copy.deepcopy(params.get("initiator")),
            "created": self.timestamps.normalize(params.get("timestamp")),
            "frameCount": 0,
            "errorCount": 0,
        }
        with self.state_lock:
            self.open_websockets[key] = entry
        self.stats["requests"] += 1
        self.store.timeline("websocket_created", entry["created"], id=key, url=entry.get("url"))

    def _websocket_handshake_request(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if request_id:
            key = self._websocket_key(session_id, str(request_id))
            with self.state_lock:
                if key in self.open_websockets:
                    self.open_websockets[key]["handshakeRequest"] = copy.deepcopy(params.get("request") or {})

    def _websocket_handshake_response(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if request_id:
            key = self._websocket_key(session_id, str(request_id))
            with self.state_lock:
                if key in self.open_websockets:
                    self.open_websockets[key]["handshakeResponse"] = copy.deepcopy(params.get("response") or {})
                    self.stats["responses"] += 1

    def _websocket_frame(self, session_id: str | None, method: str, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        key = self._websocket_key(session_id, str(request_id))
        frame = copy.deepcopy(params.get("response") or {})
        payload = frame.pop("payloadData", None)
        opcode = frame.get("opcode")
        if payload is not None:
            payload_text = str(payload)
            binary_payload = opcode != 1
            if binary_payload:
                try:
                    estimated_bytes = len(base64.b64decode(payload_text, validate=False))
                except Exception:
                    estimated_bytes = len(payload_text)
            else:
                estimated_bytes = len(payload_text.encode("utf-8", errors="replace"))
            frame["payloadBytes"] = estimated_bytes
            if self.config.body_mode == "none":
                frame["payloadOmitted"] = True
            else:
                inline_limit = self.config.websocket_inline_limit
                if self.config.max_body_bytes:
                    inline_limit = min(inline_limit, self.config.max_body_bytes)
                if estimated_bytes > inline_limit or binary_payload:
                    frame["payload"] = self.store.store_body(
                        payload_text,
                        base64_encoded=binary_payload,
                        content_type="application/octet-stream" if binary_payload else "text/plain",
                        role="websocket-frame",
                    )
                else:
                    frame["payloadData"] = self.store.redactor.body_text(payload_text, "text/plain")
        timestamp = self.timestamps.normalize(params.get("timestamp"))
        event = {
            "connectionId": key,
            "sessionId": session_id,
            "direction": "sent" if method.endswith("Sent") else "received",
            "time": timestamp,
            **frame,
        }
        with self.state_lock:
            connection = self.open_websockets.get(key)
            if connection:
                connection["frameCount"] = int(connection.get("frameCount", 0)) + 1
        self.stats["webSocketFrames"] += 1
        self.store.write_jsonl("realtime/websocket_frames.jsonl", event, redact=True)

    def _websocket_error(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        key = self._websocket_key(session_id, str(request_id))
        event = {
            "connectionId": key,
            "sessionId": session_id,
            "time": self.timestamps.normalize(params.get("timestamp")),
            "errorMessage": params.get("errorMessage"),
        }
        with self.state_lock:
            connection = self.open_websockets.get(key)
            if connection:
                connection["errorCount"] = int(connection.get("errorCount", 0)) + 1
        self.store.write_jsonl("realtime/websocket_errors.jsonl", event, redact=True)

    def _websocket_closed(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        key = self._websocket_key(session_id, str(request_id))
        with self.state_lock:
            entry = self.open_websockets.pop(key, None)
        if entry:
            entry["closed"] = self.timestamps.normalize(params.get("timestamp"))
            self._write_websocket_connection(entry)
            self.store.timeline("websocket_closed", entry["closed"], id=key)

    def _write_websocket_connection(self, entry: dict[str, Any]) -> None:
        self.store.write_jsonl("realtime/websocket_connections.jsonl", entry, redact=True)
        network_entry = {
            "schemaVersion": 3,
            "id": entry.get("id"),
            "requestId": entry.get("requestId"),
            "sessionId": entry.get("sessionId"),
            "target": entry.get("target"),
            "type": "WebSocket",
            "isApi": True,
            "started": entry.get("created"),
            "finished": entry.get("closed"),
            "url": entry.get("url"),
            "request": {
                "method": "GET",
                "url": entry.get("url"),
                **(entry.get("handshakeRequest") or {}),
            },
            "response": entry.get("handshakeResponse") or {},
            "realtime": {
                "connectionsFile": "realtime/websocket_connections.jsonl",
                "framesFile": "realtime/websocket_frames.jsonl",
                "frameCount": entry.get("frameCount", 0),
                "errorCount": entry.get("errorCount", 0),
            },
        }
        if entry.get("incomplete"):
            network_entry["incomplete"] = True
            network_entry["incompleteReason"] = entry.get("incompleteReason")
        self.store.write_jsonl("network/requests.jsonl", network_entry, redact=True)

    def _sse_message(self, session_id: str | None, params: dict[str, Any]) -> None:
        request_id = str(params.get("requestId") or "")
        data = str(params.get("data") or "")
        data_bytes = len(data.encode("utf-8", errors="replace"))
        event = {
            "connectionId": self._websocket_key(session_id, request_id),
            "sessionId": session_id,
            "time": self.timestamps.normalize(params.get("timestamp")),
            "eventName": params.get("eventName"),
            "eventId": params.get("eventId"),
            "dataBytes": data_bytes,
        }
        if self.config.body_mode == "none":
            event["dataOmitted"] = True
        else:
            inline_limit = self.config.websocket_inline_limit
            if self.config.max_body_bytes:
                inline_limit = min(inline_limit, self.config.max_body_bytes)
            if data_bytes > inline_limit:
                event["dataBody"] = self.store.store_body(
                    data,
                    content_type="text/event-stream",
                    role="sse-message",
                )
            else:
                event["data"] = self.store.redactor.body_text(data, "text/event-stream")
        self.stats["sseMessages"] += 1
        self.store.write_jsonl("realtime/sse_messages.jsonl", event, redact=True)

    def _transport_key(self, session_id: str | None, transport_id: str) -> str:
        return f"{session_id or 'root'}::{transport_id}"

    def _webtransport_created(self, session_id: str | None, params: dict[str, Any]) -> None:
        transport_id = params.get("transportId")
        if not transport_id:
            return
        key = self._transport_key(session_id, str(transport_id))
        with self.state_lock:
            self.webtransports[key] = {
                "id": key,
                "transportId": transport_id,
                "sessionId": session_id,
                "target": self._target(session_id),
                "url": params.get("url"),
                "initiator": copy.deepcopy(params.get("initiator")),
                "created": self.timestamps.normalize(params.get("timestamp")),
                "payloadCapture": "CDP Network exposes lifecycle only",
            }
            self.stats["webTransports"] += 1

    def _webtransport_established(self, session_id: str | None, params: dict[str, Any]) -> None:
        transport_id = params.get("transportId")
        if transport_id:
            with self.state_lock:
                entry = self.webtransports.get(self._transport_key(session_id, str(transport_id)))
                if entry:
                    entry["established"] = self.timestamps.normalize(params.get("timestamp"))

    def _webtransport_closed(self, session_id: str | None, params: dict[str, Any]) -> None:
        transport_id = params.get("transportId")
        if not transport_id:
            return
        with self.state_lock:
            entry = self.webtransports.pop(self._transport_key(session_id, str(transport_id)), None)
        if entry:
            entry["closed"] = self.timestamps.normalize(params.get("timestamp"))
            self._write_webtransport(entry)

    def _write_webtransport(self, entry: dict[str, Any]) -> None:
        self.store.write_jsonl("realtime/webtransport.jsonl", entry, redact=True)
        network_entry = {
            "schemaVersion": 3,
            "id": entry.get("id"),
            "sessionId": entry.get("sessionId"),
            "target": entry.get("target"),
            "type": "WebTransport",
            "isApi": True,
            "started": entry.get("created"),
            "finished": entry.get("closed"),
            "url": entry.get("url"),
            "request": {"method": "CONNECT", "url": entry.get("url")},
            "initiator": entry.get("initiator"),
            "realtime": {
                "lifecycleFile": "realtime/webtransport.jsonl",
                "payloadCapture": entry.get("payloadCapture"),
            },
        }
        if entry.get("established"):
            network_entry["response"] = {"connected": True, "established": entry.get("established")}
        if entry.get("incomplete"):
            network_entry["incomplete"] = True
            network_entry["incompleteReason"] = entry.get("incompleteReason")
        self.store.write_jsonl("network/requests.jsonl", network_entry, redact=True)

