from __future__ import annotations

TARGET_TYPES = {"page", "iframe", "webview", "worker", "service_worker", "shared_worker"}
PAGE_TYPES = {"page", "iframe", "webview"}
API_TYPES = {"XHR", "Fetch", "Document", "WebSocket", "EventSource", "Ping"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
# CDP errors that mean the target behind a session id is already gone.
SESSION_GONE_CODES = {-32001}
SESSION_GONE_MARKERS = (
    "session with given id not found",
    "target closed",
    "no target with given id",
    "not attached to an active page",
    "inspected target navigated or closed",
)
# Response types that must keep flowing: pausing them to take the body stalls
# the stream inside Chrome until it ends, which never happens for live feeds.
STREAMING_CONTENT_TYPES = (
    "text/event-stream",
    "multipart/x-mixed-replace",
    "application/grpc",
    "application/x-ndjson",
)
