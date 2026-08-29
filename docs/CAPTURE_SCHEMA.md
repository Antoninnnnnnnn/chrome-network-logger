# Capture schema v3

Every session is created under a unique `session_YYYYMMDD_HHMMSS_mmm_PID_RANDOM` directory. Paths stored in records are POSIX-style and relative to that session directory.

## Stability

`schemaVersion: 3` is the compatibility boundary for canonical network records. New optional fields may be added within v3. Existing fields are not silently repurposed. Consumers must tolerate unknown fields and files that are absent because a capture option disabled them or Chrome did not expose the data.

## Manifest

`manifest.json` is updated atomically and contains:

- logger version, start/end timestamps, and `running`, `complete`, `partial`, or `error` status;
- effective capture configuration and proxy route state;
- warnings, capture statistics, writer health, and body-storage totals;
- Chrome and protocol versions after a successful CDP connection.

An `error` status or non-zero process exit means the capture must not be treated as complete. A `partial` status indicates an unexpected browser/CDP close or incomplete flushed requests.

## Canonical network stream

`network/requests.jsonl` contains one JSON object per HTTP redirect hop, WebSocket connection, or WebTransport connection. Important HTTP fields include:

- `id`, `sessionId`, `requestId`, and redirect-hop identity;
- normalized `started`/`finished` timestamps and optional `durationMs`;
- `type`, `isApi`, `request`, `response`, `extraInfo`, and `failure`;
- explicit incompleteness, missing `ExtraInfo`, body error, and finalization reasons.

Private implementation fields beginning with `_` are removed before final records are written.

## Body references

Bodies are stored under `network/bodies/` and referenced rather than embedded. A reference can include:

- `path`, `sha256`, `storedSha256`, and `role`;
- `originalBytes`, `processedBytes`, and `storedBytes`;
- `contentType`, `encoding`, `textual`, `compressed`, `truncated`, and `redacted`;
- a small textual `preview` when allowed by the inline limit.

If the session body limit is reached, the record instead has `omitted: true`, `omittedReason: "sessionBodyLimit"`, `storedBytes: 0`, and `wouldStoreBytes`; it intentionally has no `path`. A decode error is explicit in `decodeError`.

## Other streams

- `timeline.jsonl`: normalized cross-domain summary events.
- `realtime/`: WebSocket frames/errors/connections, SSE messages, and WebTransport lifecycle.
- `interactions/`: user and form events from the isolated interaction world.
- `browser/`: targets, navigation, console, exceptions, logs, protocol diagnostics, and proxy toggles.
- `snapshots/`: start/end cookie and Web Storage snapshots.
- `reports/`: derived human-readable text, CSV, and escaped HTML; these are not canonical inputs.

See the README for CDP visibility limitations and `docs/THREAT_MODEL.md` for confidentiality boundaries.
