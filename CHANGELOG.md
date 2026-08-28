# Changelog

All notable changes to Chrome Network Logger are documented here.

## 3.0.0 — 2026-08-26

### Capture reliability

- Connect to the browser-level CDP endpoint and attach independent tabs, popups, iframes, webviews, and workers.
- Namespace request state by CDP session, request ID, and redirect hop.
- Preserve each redirect hop and associate out-of-order request/response `ExtraInfo` with the correct hop.
- Wait for pending response/request bodies before finalization, fall back from Fetch to Network body retrieval, and mark unavailable data explicitly.
- Flush open HTTP, WebSocket, SSE, and WebTransport state during graceful shutdown.
- Detect unexpected browser-CDP disconnection instead of leaving the logger running indefinitely.
- Quiesce Fetch, target discovery/auto-attach, Runtime bindings, and injected listeners before disconnecting, including `--keep-chrome` sessions.

### Storage and analysis

- Replace duplicated `full`/`filtered` output with canonical `network/requests.jsonl` and an `isApi` field.
- Store bodies externally, compress text, enforce a configurable size limit, and deduplicate by SHA-256.
- Stream WebSocket frames and SSE messages to disk instead of retaining unbounded lists in memory.
- Normalize epoch, ISO, and CDP monotonic timestamps into a shared timeline.
- Add cookie/Web Storage snapshots, browser logs, protocol diagnostics, CSV/text reports, and escaped interaction HTML.

### Security

- Redact sensitive headers, cookies, URL parameters/fragments, JSON, form bodies, storage, and interaction/form values by default.
- Use a random per-session HMAC key for comparison fingerprints; the key is never persisted.
- Preserve an explicit `raw` mode for authorized debugging that requires unredacted values.
- Restrict Chrome's remote-debugging origin to the loopback CDP origin rather than a wildcard.

### Proxy and maintainability

- Rewrite the local HTTP(S) relay with proper socket tracking, upstream TLS verification, Basic proxy authentication, IPv6 parsing, and deterministic direct/proxy switching.
- Reject unsupported authenticated SOCKS proxies explicitly.
- Split the former monolith into focused capture, registry, storage, redaction, proxy, Chrome, and CLI modules.
- Add unit/integration-style loopback tests and a Linux/Windows GitHub Actions matrix for Python 3.10 and 3.12.

### Compatibility

- Keep `python chrome_network_logger.py` as the historical entry point.
- Add the installable `chrome-network-logger` console command.
