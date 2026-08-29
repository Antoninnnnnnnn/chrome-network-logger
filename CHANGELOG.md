# Changelog

All notable changes to Chrome Network Logger are documented here.

## 3.0.1 — 2026-08-29

### Security hardening

- Require TLS 1.2 or newer when connecting to an HTTPS upstream proxy, including when certificate verification is explicitly disabled.
- Document the intentionally fast, randomly keyed per-session HMAC fingerprint so static analysis does not confuse it with password storage.
- Add regression coverage for verified and intentionally unverified HTTPS upstream contexts (83 tests total).

## 3.0.0 — 2026-08-29

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
- Let Chrome allocate its debugging port atomically, validate the returned loopback WebSocket URL, and reject unsafe endpoints.
- Install interaction capture in an isolated JavaScript world; redact all form-control values, form data, `outerHTML`, sensitive attributes, and inline `data:`/`javascript:` URLs before they reach storage.
- Bound interaction messages, pending protocol metadata, proxy connections, writer tasks, and total body storage.
- Preserve declared UTF-8/UTF-16/Latin-1/Windows-1252 body encodings while redacting textual captures.
- Neutralize spreadsheet formulas in generated CSV reports.

### Proxy and maintainability

- Rewrite the local HTTP(S) relay with proper socket tracking, upstream TLS verification, Basic proxy authentication, IPv6 parsing, and deterministic direct/proxy switching.
- Reject unsupported authenticated SOCKS proxies explicitly.
- Split the former monolith into focused capture, registry, storage, redaction, proxy, Chrome, and CLI modules.
- Add unit/integration-style loopback tests and a Linux/Windows GitHub Actions matrix for Python 3.10 and 3.12.
- Expand to 81 tests with enforced branch coverage; validate Python 3.10–3.14 on Linux, Windows, and macOS.
- Add pinned GitHub Actions, package build/Twine checks, CodeQL, Dependabot, typed-package metadata, contribution guidance, a capture schema, and a threat model.
- Propagate fatal CDP, Chrome, proxy-relay, and writer failures through the manifest and process exit code.

### Compatibility

- Keep `python chrome_network_logger.py` as the historical entry point.
- Add the installable `chrome-network-logger` console command.
- Add `--duration`, `--version`, a validated `--start-url`, and a 2 GiB default session-wide body limit; keep direct routing and `about:blank` as quiet defaults.
