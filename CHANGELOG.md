# Changelog

All notable changes to Chrome Network Logger are documented here.

## Unreleased

### Security and privacy

- The proxy relay only serves the Chrome the logger launched: each connection is matched to the process that opened it, and other local processes — which could otherwise use the upstream proxy with your credentials — are refused and reported. Where processes cannot be inspected, the relay says so and accepts local connections.
- The relay refuses origin-form requests and requests aimed at itself: a web page could make it connect to itself in a loop until no connection slot was left.
- The selected proxy is checked before Chrome starts (reachable, TLS, credentials) without contacting any third-party host; `--no-proxy-check` skips it.
- An upstream `407` becomes a `502` with an explanation: Chrome asked for a login in a loop that could never succeed. Unreachable upstreams and TLS failures are reported once (with the `--proxy-insecure-tls` hint) in the log and manifest warnings instead of at debug level.
- IndexedDB is never read in the page's own world, where the page could observe or alter the read; with `--no-interactions` it used to be. A dump waits for the isolated world, then is recorded as `skipped`.
- Safe mode also redacts: camelCase secret names (`authToken`, `userSecret`, `privateKey`), an application `sessionId` in Web Storage and IndexedDB, JSON stored inside strings, Socket.IO frames, URL-encoded values with harmless names (a JWT, a JSON document), JWTs in URL paths, text parts of multipart bodies, and the `urlFragment` field. Values under a sensitive name keep their structure; `Basic plan` is no longer redacted; URL parts that need no redaction keep their original text.

### Capture

- Events inside open shadow roots name the element actually used, and `change` and form submissions in shadow roots are captured.
- Cookies written by page script (`document.cookie`, `cookieStore.set`) trigger a cookie-jar read, so they appear when they are written (`pageScript:` reasons, `stats.cookieHints`).
- With `--no-interactions`, the isolated-world script is still installed for storage capture: page storage dumps on `pagehide`/`freeze`/hidden and script-written cookies were silently missing.

### Sessions easier to analyse

- Write `reports/overview.md`, a bounded digest of the session: pages visited (with single-page-application route changes), HTTP errors, network failures, incomplete requests, console errors and uncaught exceptions, API endpoints grouped by method and path with identifiers collapsed, the requests that followed each click, submit, change or key press in the same tab, and hosts. Every row names the record `id` to look up. Its headline numbers are stored in `manifest.json` under `analysis`, shown in `INDEX.md`, and `INDEX.md` sends readers to the overview first.
- Sort `timeline.jsonl` by time when the capture ends, with bounded memory. It was in processing order — a request was written after its body arrived — although `INDEX.md` described it as time-ordered.
- Add console errors and warnings (redacted before being shortened), uncaught exceptions, cookie changes (names), Web Storage changes (keys), renderer crashes, and a readable `label` per user action (`click button#go "Log in"`) to the timeline; `request_finished` lines now carry the method, URL and duration.
- Record single-page-application navigations (`Page.navigatedWithinDocument`: `history.pushState`, fragment changes) in `browser/navigations.jsonl` and the timeline. They were not captured.
- `reports/summary.txt` and `reports/requests.csv` are in start order and show the start time and duration; `stats.txt` counts HTTP errors.
- Interaction events carry `frameId`, `trusted` (`isTrusted`), and element `testId` and `label`; form submissions name the `submitter`. Requests carry Chrome's `hasUserGesture`, WebSocket records their `initiator`.
- Renderer crashes (`Target.targetCrashed`) are recorded in `browser/targets.jsonl` with a manifest warning.
- `--note TEXT` records what the capture is about (scenario, account, bug) in `manifest.json` and at the top of `INDEX.md`, the context an analyst cannot infer from the traffic.

### Fixed — capture correctness

- A streamed response (chunked `text/plain` or JSON without `Content-Length`, as many chat interfaces use) was paused by Fetch interception until its last byte, so the page showed nothing until the stream ended — 3 s instead of 4 ms on a local test. Such `XHR`/`Fetch` responses, downloads, JSON Lines/NDJSON variants and React Server Components payloads now flow and their body is read once loaded.
- A paused response was never released if storing its body raised (for example deeply nested JSON in safe mode), leaving the page's request hanging until shutdown. One failing timed-out command no longer skips the paused responses after it.
- A redirect hop still inside its ExtraInfo grace window at shutdown was written as `incomplete` and made the session `partial`.
- A request that failed before any response (CORS, blocked) lost the raw response headers Chrome had reported.
- A body that failed at the Fetch stage was labelled "no response was received" even for a `200`, and was counted twice when the fallback also failed; a fallback that succeeds no longer counts as a lost body.
- Timestamps never recovered after the system slept: every later `finished` time was off by the sleep duration. The clock relation is re-anchored once two samples agree, and `durationMs` uses Chrome's monotonic clock.
- A page or CDP timestamp the platform cannot convert raised inside the event handler.

### Fixed — injected script

- Stop listening to `unload`: Chrome logged a permissions-policy violation on every page (a false error in `browser/log.jsonl`) and it could keep pages out of the back/forward cache. `pagehide` already covers it.
- Form submissions are read from the form controls instead of `new FormData(form)`, which fired a `formdata` event the page's own listeners received. The form's `elements`, `action` and `method` are read through the prototype getters, so a control named `action` no longer hides them; form-associated custom elements, whose value the isolated world cannot read, are marked as such.
- An event on `<body>` or a large container serialized the whole page (`innerText`, `outerHTML`); text is read with a bounded walk and large elements keep only their opening tag, rebuilt from the attributes (cloning would run a custom element's constructor). Auto-repeated keys are ignored.
- Characters typed through AltGr (`@`, `#`, `{` on many layouts), macOS Option or an IME were recorded as key presses; contenteditable editors are treated as typed text in safe mode.

### Fixed — safe-mode redaction

- `Referer`, `Location` and `Content-Location` are redacted as URLs (an OAuth `code` travelled on in `Referer`).
- `cookieLine` of blocked and exempted cookies, list-shaped headers (Cache Storage entries) and `requestURL` are redacted.
- Web Storage change events redact their values according to the storage key, as snapshots already did.

### Proxy

- `--proxy-prompt` did not prompt: `--proxy` defaulted to `none`, which returned before the prompt, so the capture silently went direct.
- A transient `accept()` error (connection aborted, descriptor table full) ended the relay thread while its port stayed open, so every later request hung.
- A proxy line with an invalid port logged the line, password included.
- A password containing `@` in the `host:port:user:password` and space-separated formats was parsed as a URL and the proxy was skipped.
- With a proxy, WebRTC is restricted to proxied routes (`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`) so it cannot reveal the real IP address.

### Managed Chrome

- A truncated download is reported as such instead of as an invalid ZIP.
- `--refresh-managed-chrome` uses the cached build when the metadata endpoint cannot be reached.
- Two runs installing the same version at once, or an antivirus holding the new directory, no longer fail the install at the final rename.

### Development

- Tests import the package from the checkout (`pythonpath = ["."]`), not from another installed copy.

## 3.2.0 — 2026-11-07

### Sessions ready for automated analysis

- Write `INDEX.md` at the root of every session: outcome and its meaning, why the capture stopped, sensitive mode, warnings, key numbers, a table of every file with size and record count, how to open gzip bodies, and what CDP cannot see. It is the entry point for a reader — or an AI agent — that has never seen the format.
- Record a `files` inventory (path, bytes, JSONL record count, body blob totals) in `manifest.json`.
- Export `reports/session.har` (HAR 1.2) from the canonical stream, with bodies inlined up to 1 MiB and the capture id, failures and incompleteness kept in `_`-prefixed fields. `--no-har` turns it off.
- Keep small binary WebSocket frames inline as `payloadBase64` (plus `payloadText` when printable) in raw mode instead of one body file per frame.

### Fixed — capture correctness

- `--start-url` lost the start page's first requests (document, login, bootstrap API calls): Chrome began loading the URL from its command line before the logger had attached. Chrome now always starts on `about:blank`, and the logger navigates to the start URL once the first tab has answered its Network/Runtime/Page/Fetch setup and the interaction script is installed. Verified against a local site: 0 of 4 page requests were captured before, 4 of 4 after.
- IndexedDB and Cache Storage were never captured for a tab that attached on `about:blank` (the default start page) and then navigated: tracking only started for a URL known at attach time. It now starts whenever a page reaches a new origin, along with a baseline Web Storage read, and is registered per session so closing the first tab of an origin no longer stops events for the others.
- Requests that had finished loading but were still inside their ExtraInfo grace window, or waiting for a body, were written as `incomplete` at shutdown and turned a clean stop into `partial`. They are now written as complete, with `extraInfoIncomplete` or a `responseBodyError` naming what was not returned.
- Requests cut off because their own tab, iframe or worker closed are counted in the new `incompleteDetached` statistic and no longer make the session `partial`; `incompleteFlushed` keeps only requests in flight at shutdown.
- IndexedDB dumps ran in whichever isolated context had the highest id, which could be a child iframe of another origin. They now run in the context of the origin being read, preferring the main frame.
- An IndexedDB dump could create an empty database that the application had just deleted, or delay the application's own version upgrade. Dumps now skip missing databases, abort any upgrade, and close on `versionchange`.
- A full storage dump replaces the reconstructed content of its area instead of merging, so keys deleted while no event was observed no longer survive in `dom_storage_final.json`. `sessionStorage` is kept per tab.
- Web Storage snapshots are read with `DOMStorage.getDOMStorageItems` instead of JavaScript evaluated in the page's main world, so the page cannot observe them; pages without a web origin are skipped.

### Fixed — stability

- Starting a capture with `--profile-dir profiles/a` stopped any Chrome running on `profiles/ab`: processes were matched on a substring of their command line. The exact `--user-data-dir` path is now compared.
- Chrome is closed with the DevTools `Browser.close` command. The previous `CTRL_BREAK_EVENT` never reached Chrome on Windows (it has no console), so every stop waited 5 seconds and then killed the browser, leaving an unclean profile. Signals and a hard kill remain fallbacks.
- Orphan Chrome processes of the profile are terminated together and awaited once instead of up to 2 seconds each.
- An exception in the CDP reader's housekeeping killed the reader thread and was reported as an ordinary browser disconnect (`partial`). Each task is now isolated; repeated failures or a failed writer make the capture fail explicitly.
- `os.replace` is retried on Windows sharing violations (antivirus, indexers, open viewers) for the manifest, snapshots and bodies instead of failing the capture.
- The writer queue is bounded in bytes (256 MiB) as well as in tasks, so a slow disk cannot pile up gigabytes of bodies in memory.
- Manifest warnings are capped at 200 distinct messages (`warningsSuppressed` counts the rest); repeated oversized-payload warnings no longer create a new message each time.
- Finished request ids no longer keep a hop counter for the whole session.

### Proxy

- Authenticated SOCKS5 proxies are supported through the loopback relay (RFC 1928/1929), with host names resolved on the proxy. Unauthenticated SOCKS stays a direct Chrome setting; authenticated SOCKS4 is still rejected.
- **P** toggles the upstream on Linux and macOS too when the logger runs in an interactive terminal; the terminal mode is always restored. On Windows, the Down arrow no longer toggles the proxy.
- The relay tunnel uses `selectors` instead of `select()`, which failed above 1024 file descriptors on Linux, and forwards data buffered inside TLS upstream sockets.
- Bytes an HTTP upstream sends right after its `CONNECT` 200 are forwarded instead of dropped; a failure after the tunnel opened no longer writes a stray 502 into it.
- `--proxy-prompt` with a closed stdin is a clear usage error.

### Managed Chrome

- The Chrome for Testing download reports its progress (every 10 %, or every 16 MiB without a known size).

### CLI

- Invalid configuration values are reported as usage errors (exit code 2) instead of tracebacks; `--max-idb-entries` and `--max-cache-entries` must be positive integers.
- Prompts no longer crash when stdin is closed (pipes, services, CI).
- Warn on Windows when the profile path exceeds 120 characters: Chrome then hits the 260-character path limit inside the profile and sites fail to use Cache Storage or IndexedDB (`UnknownError: Unexpected internal error`).
- The stop summary names the signal that ended the capture and points to `INDEX.md`.
- `Fetch.disable` is only sent when Fetch interception was enabled.

### Documentation

- README (EN/FR), threat model and capture schema now match the code: raw is the default mode, Fetch interception covers `Document`, `XHR` and `Fetch` by default, and the new files, fields and statistics are documented.

## 3.1.1 — 2026-09-05

### Fixed — response bodies were never stored

- Stop configuring CDP durable messages. On Chrome 152 that call makes the network service drop retained response bodies, so every `Network.getResponseBody` returned `No data found for resource with given identifier` and no body was captured. A local reproduction went from 0/30 to 30/30 bodies once the call was removed.
- Add `--durable-messages` for anyone who wants the old behaviour, documented as breaking body retrieval.

### Fixed — body errors that were not errors

- Stop counting a failed body command as a lost body when the response could never carry one. A cancelled request, a `HEAD`, a `204`/`304` or a redirect has no body to fetch, so `Fetch.getResponseBody` answering `Invalid InterceptionId.` for an aborted request was not a capture failure.
- Those cases now set `responseBodyUnavailableReason` on the entry and count in the new `bodiesUnavailable` statistic; `bodyErrors` keeps only real losses. Replaying a 3 764-request capture that reported 36 `bodyErrors` gives 0 real losses and 36 responses that never had a body.
- The end-of-session summary distinguishes both: "bodies lost to errors" and a separate line for responses with no body to capture.

### Raw capture by default

- `--sensitive` now defaults to `raw`: bodies, cookies, tokens and form values are stored as captured, so a session is directly usable for debugging the application that produced it. Redaction becomes opt-in with `--sensitive safe`.
- Warn on every raw session that the directory holds credentials in clear text and name the flag that redacts them.
- `.gitignore` already excludes `session_*/`, `captures/`, `profiles/`, and `capture_profile/` at any depth, so captures stay out of commits. Files copied out of a session directory are not covered.

### Clean stop

- Print a plain end-of-session summary that says why the capture stopped, that the data was written, how many requests and bodies were kept, and where to start reading. `partial` no longer looks like data loss.
- Stop printing a `ConnectionResetError` traceback when the browser window is closed; a reset socket is an ordinary end of capture.
- Handle `SIGBREAK` (Ctrl+Break) and `SIGHUP` like `SIGINT`, so those also finalize instead of killing the process.
- Verified end to end: Ctrl+C with the browser alive finalizes in ~6s as `complete` with exit code 0 and no traceback; closing the browser finalizes immediately as `partial` with reason `chromeExited`, one warning, and no traceback.

### IndexedDB and Cache Storage capture

- Capture IndexedDB and Cache Storage, which never appear in network traffic and vanish with the browser. Chrome's `Storage` events say which database, object store, or cache changed, and only that scope is re-dumped.
- Store IndexedDB database lists, object-store schemas, and records in `storage/indexeddb.jsonl`; store cache lists and entry metadata in `storage/cache_storage.jsonl`.
- Read object-store records from the page instead of `IndexedDB.requestData`, which only answers with `RemoteObject` references and never inlines the values.
- Bound every dump with `--max-idb-entries` (500) and `--max-cache-entries` (200), and add `--no-client-storage` to switch the whole feature off.

### Bodies for targets that die mid-request

- Take response bodies during Fetch interception for XHR and Fetch, not just documents (`--intercept-bodies none|document|api|all`, default `api`). A body taken while the response is paused no longer depends on the target still being attached when the body is requested.
- Never pause for the body of a streamed response (`text/event-stream`, `multipart/x-mixed-replace`, `application/grpc`, `application/x-ndjson`) or one whose `Content-Length` exceeds the per-body limit; those continue immediately and fall back to `Network.getResponseBody`.
- Record how the session ended in `manifest.json` as `shutdownReason`, instead of leaving only `status`.
- Note: a request cancelled because its iframe or worker was destroyed has no response at all, so no body can be recovered for it. Those stay `incomplete`.

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
