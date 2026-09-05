# Changelog

All notable changes to Chrome Network Logger are documented here.

## 3.1.1 — 2026-09-05

### Fixed — response bodies were never stored

- Stop configuring CDP durable messages. On Chrome 152 that call makes the network service drop retained response bodies, so every `Network.getResponseBody` returned `No data found for resource with given identifier` and no body was captured. A local reproduction went from 0/30 to 30/30 bodies once the call was removed.
- Add `--durable-messages` for anyone who wants the old behaviour, documented as breaking body retrieval.

### Event-sourced cookie and Web Storage capture

- Record every `localStorage`/`sessionStorage` mutation from `DOMStorage` events into `storage/dom_storage_events.jsonl`, using the attach-time page dump as the baseline they apply to.
- Re-read the cookie jar after each event that can change it (Set-Cookie response, navigation, target attach/detach, page flush) and store the diff in `storage/cookie_changes.jsonl`. Bursts coalesce into a single read.
- Flush a full `localStorage`/`sessionStorage`/cookie dump from the injected script on `pagehide`, `freeze`, `unload`, `beforeunload`, and `visibilitychange` — the last moment a dying page is readable — into `storage/page_flushes.jsonl`. Safe mode exports cookie names only.
- Write `snapshots/cookies_final.json` and `snapshots/dom_storage_final.json` from that in-memory state at shutdown, so a session ended by closing the browser keeps its final state without a live connection.
- Turn the periodic snapshot into an optional extra (`--snapshot-interval`, now `0` by default) instead of the mechanism state capture relies on.

### Browser shutdown

- Skip the final snapshot and CDP teardown when the browser is already gone instead of retrying on a dead socket, and report it as a single warning rather than four `WebSocketConnectionClosedException` tracebacks.
- Mark the CDP connection as closed as soon as a send hits a closed socket.

### Fixed

- Stop aborting the capture when a required session-scoped CDP command fails because its target already detached. Short-lived iframes and blob workers routinely disappear before Chrome answers `Network.enable`, `Page.enable`, or `Target.setAutoAttach`, which returned `-32001 Session with given id not found` and killed the whole session.
- Record those races in `browser/protocol_errors.jsonl` with `sessionDetached: true` and count them in the new `detachedSessionCommands` statistic. Browser-level required commands (no session id) remain fatal.
- Treat required-command timeouts for sessions that are no longer attached as non-fatal for the same reason.

## 3.1.0 — 2026-08-29

### Managed Chrome fallback

- Create the dedicated profile directory before browser discovery so a missing local Chrome no longer prevents profile setup.
- Download and cache the official Stable Chrome for Testing build when no system Chrome/Chromium is available.
- Resolve the platform from the host architecture and support Google's `win32`, `win64`, `linux64`, `mac-x64`, and `mac-arm64` archives.
- Validate fixed HTTPS hosts and archive paths, require TLS 1.2+, bound compressed/expanded sizes and member counts, reject traversal and unsafe archive entries, extract to a temporary directory, and publish the installation atomically.
- Persist locally computed archive/executable SHA-256 values and managed distribution details, then recheck the executable before cache reuse.
- Add `--managed-chrome-dir`, `--no-download-chrome`, and `--refresh-managed-chrome` controls.
- Document that this remains a genuine visible Chrome process without WebDriver, but does not promise invisibility to website fingerprinting.
- Select a non-zero ephemeral loopback debugging port before launch because Chrome sets `navigator.webdriver=true` specifically for `--remote-debugging-port=0`; retain strict loopback endpoint validation.
- Expand the suite to 96 tests, including managed-install caching/integrity, platform and CDP-port selection, URL allow-listing, archive traversal rejection, CLI fallback, and opt-out behavior.

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
