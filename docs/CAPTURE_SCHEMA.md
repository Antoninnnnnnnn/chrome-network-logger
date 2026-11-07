# Capture schema v3

Every session is created under a unique `session_YYYYMMDD_HHMMSS_mmm_PID_RANDOM` directory. Paths stored in records are POSIX-style and relative to that session directory.

## Stability

`schemaVersion: 3` is the compatibility boundary for canonical network records. New optional fields may be added within v3. Existing fields are not silently repurposed. Consumers must tolerate unknown fields and files that are absent because a capture option disabled them or Chrome did not expose the data.

## Session index

`INDEX.md` is written at the end of the capture and is the intended entry point for any reader, including an
automated or AI analyst. It is derived from the manifest: status and its meaning, stop reason, sensitive mode,
warnings, key statistics, a table of every file present (size, JSONL record count, purpose), how to open gzip
bodies, and the caveats below. It is a guide, not a canonical input.

## Manifest

`manifest.json` is updated atomically and contains:

- logger version, start/end timestamps, and `running`, `complete`, `partial`, or `error` status;
- effective capture configuration and proxy route state;
- warnings, capture statistics, writer health, and body-storage totals;
- Chrome and protocol versions after a successful CDP connection;
- `browserInstall`, identifying a system/explicit browser or the managed Stable version, platform, and locally computed archive/executable SHA-256 values;
- `note`: the operator's `--note` text, when given;
- `analysis`: headline numbers of `reports/overview.md` (`httpErrors`, `networkFailures`, `cancelledRequests`, `consoleErrors`, `exceptions`, `apiEndpoints`, `pagesVisited`, `userActions`, `hosts`);
- `files`: every session file except body blobs as `{path, bytes, records?}` (`records` = line count of a JSONL file), plus one `network/bodies/` entry with the blob count and total size;
- `warnings` (at most 200 distinct messages) and `warningsSuppressed` when more were dropped;
- `writer.queuedBytesHighWatermark`, the peak amount of data waiting for the disk.

An `error` status or non-zero process exit means the capture must not be treated as complete. A `partial` status indicates an unexpected browser/CDP close or requests still in flight at shutdown (`stats.incompleteFlushed`). Requests cut off because their own tab, iframe or worker closed are ordinary browsing; they are counted in `stats.incompleteDetached` and do not make a session partial.

## Canonical network stream

`network/requests.jsonl` contains one JSON object per HTTP redirect hop, WebSocket connection, or WebTransport connection. Important HTTP fields include:

- `id`, `sessionId`, `requestId`, and redirect-hop identity;
- normalized `started`/`finished` timestamps and optional `durationMs`;
- `type`, `isApi`, `request`, `response`, `extraInfo`, and `failure`;
- explicit incompleteness, missing `ExtraInfo`, body error, and finalization reasons.

`incomplete: true` (with `incompleteReason`) is set only on a request that never finished loading. A request that
had finished but was still waiting for its `ExtraInfo` or body when its target or the capture ended is written as
complete, with `extraInfoIncomplete: true` and/or a `responseBodyError` / `requestPostDataError` explaining what was
not returned.

`hasUserGesture` is Chrome's own flag for a request started by a user action. `durationMs` is measured on Chrome's monotonic clock when both ends carry `cdpMonotonicSeconds`. A request that failed before any response (CORS, blocked) keeps the raw response headers Chrome reported in `extraInfo.response`. WebSocket records carry their `initiator`.

`network/requests.jsonl` is written in completion order; sort on `started.epochMs` for start order.

Private implementation fields beginning with `_` are removed before final records are written.

## Body references

Bodies are stored under `network/bodies/` and referenced rather than embedded. A reference can include:

- `path`, `sha256`, `storedSha256`, and `role`;
- `originalBytes`, `processedBytes`, and `storedBytes`;
- `contentType`, `encoding`, `textual`, `compressed`, `truncated`, and `redacted`;
- a small textual `preview` when allowed by the inline limit.

If the session body limit is reached, the record instead has `omitted: true`, `omittedReason: "sessionBodyLimit"`, `storedBytes: 0`, and `wouldStoreBytes`; it intentionally has no `path`. A decode error is explicit in `decodeError`.

`responseBodyUnavailableReason` explains entries whose response could not carry a body (cancelled request, `HEAD`, `204`/`304`, redirect). Those count in `bodiesUnavailable`, not in `bodyErrors`, which counts only bodies that were lost while they did exist.

## Other streams

- `timeline.jsonl`: one compact event per line, sorted by `time.epochMs` when the capture ends (a line without a time keeps the position of the line before it). `kind` is one of `request_started`, `request_finished` (with `method`, `url`, `status`, `durationMs`), `websocket_created`, `websocket_closed`, `user_event` (with a readable `label`), `navigation` (including `navigatedWithinDocument` for single-page-application route changes), `console` (levels `error`, `warning` and `assert` only, text truncated), `exception`, `cookie_change` (names only), `storage_change` (keys only) and `target_crashed`. Values stay in the dedicated files.
- `realtime/`: WebSocket frames/errors/connections, SSE messages, and WebTransport lifecycle. Text frames carry `payloadData`; in raw mode a binary frame up to the inline limit carries `payloadBase64` (plus `payloadText` when it is printable UTF-8) instead of a body file; larger frames carry a body reference in `payload`.
- `interactions/`: user and form events from the isolated interaction world. Each event has `frameId` (joins to the requests of the same frame), `trusted` (`isTrusted`: false when a script dispatched it) and a `target` description with `testId` (`data-testid`/`data-test`/`data-cy`/`data-qa`) and `label` (the associated `<label>` or `aria-labelledby` text). `form_submit` events also describe the `submitter` button.
- `browser/`: targets, navigation, console, exceptions, logs, protocol diagnostics, and proxy toggles.
- `snapshots/`: start/end/attach/navigation cookie and Web Storage dumps (Web Storage is read with `DOMStorage.getDOMStorageItems`, `source` names it, and pages without a web origin are skipped), plus `cookies_final.json` and `dom_storage_final.json` rebuilt from the event stream. A full dump replaces the reconstructed content of its area. `sessionStorage` belongs to one tab, so each tab has its own entry with a `sessionId` and a three-element `key`.
- `storage/indexeddb.jsonl` and `storage/cache_storage.jsonl`: IndexedDB database lists, object-store schemas and bounded record dumps, plus Cache Storage cache lists and entry metadata, each line naming the `reason` that triggered the dump.
- `storage/`: every state mutation as it happened — `cookie_changes.jsonl` (added/updated/removed cookies with the event that triggered the read), `dom_storage_events.jsonl` (localStorage/sessionStorage changes), and `page_flushes.jsonl` (full dumps sent by the injected script when a page is hidden, frozen, or unloaded).
- `reports/overview.md`: a bounded digest for analysts — pages visited, HTTP errors, network failures (cancellations counted apart), incomplete requests, console errors, uncaught exceptions, API endpoints grouped by method and path (numeric, UUID, hex and token-like segments collapsed to `{id}`), the requests that followed each user action in the same tab within 2 s and before the next action (a heuristic), and hosts. Its headline numbers are also recorded in `manifest.json` under `analysis`.
- `reports/`: derived human-readable text (`summary.txt` in start order with time and duration), CSV (with `started` and `duration_ms` columns), escaped HTML, and `session.har` (HAR 1.2, bodies inlined up to 1 MiB, custom `_`-prefixed fields keep the capture `id`, failures and incompleteness); these are not canonical inputs.

See the README for CDP visibility limitations and `docs/THREAT_MODEL.md` for confidentiality boundaries.
