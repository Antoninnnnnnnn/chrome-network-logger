# Chrome Network Logger v3

[🇫🇷 Version française](README.fr.md)

Python toolkit for capturing **Chrome application-layer traffic** through the Chrome DevTools Protocol (CDP), without Selenium or Playwright. It launches a dedicated Chrome profile, connects to the **browser target**, and attaches each tab, popup, iframe and worker through its own CDP session.

> This is not a packet sniffer. Raw DNS/TCP/TLS/QUIC and WebRTC media/DataChannel payloads are outside CDP; multipart bytes are available only when Chrome exposes them explicitly.

## What changed in v3

- One entry point: `python chrome_network_logger.py`, or `chrome-network-logger` after installation.
- Browser-level CDP attachment for independent tabs and popups.
- Request identity namespaced by `sessionId`, `requestId`, and redirect hop.
- Every 3xx hop is retained separately, including its `ExtraInfo` data.
- Graceful shutdown flushes in-flight requests and open WebSocket/WebTransport connections as `incomplete`.
- Bodies are external, compressed, size-limited, and SHA-256 deduplicated instead of duplicated in multiple JSONL files.
- WebSocket frames and SSE messages are streamed to disk rather than accumulated indefinitely in RAM.
- One canonical source: `network/requests.jsonl`.
- Normalized timestamps (`epochMs`, local ISO time, and CDP monotonic time when available).
- Start/end cookie and localStorage/sessionStorage snapshots.
- Dedicated browser console, exception, log, navigation, and target files.
- A single interaction script with a stable installation marker; generated HTML escapes captured markup.
- Sensitive values are redacted by default while retaining their length and a per-session HMAC.
- Rewritten proxy relay with correct socket lifecycle, IPv6, HTTP(S) upstream support, and live direct/proxy switching on Windows.
- Modular package, unit tests, and Windows/Linux CI.

## Installation

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e .[dev]
python -m pytest
python -m ruff check .
```

Requires Python 3.10+ and Chrome or Chromium.

## Usage

```bash
python chrome_network_logger.py
```

On first run, an isolated profile is created at `./capture_profile`. Your normal Chrome profile is not used.

Examples:

```bash
# XHR/Fetch/Document bodies, secrets redacted — defaults
python chrome_network_logger.py --body-mode api --sensitive safe

# Wider body capture
python chrome_network_logger.py --body-mode all

# Metadata, headers and timings only
python chrome_network_logger.py --body-mode none

# Raw credentials, cookies and tokens are preserved
python chrome_network_logger.py --sensitive raw

# Explicit output/profile locations
python chrome_network_logger.py --output-dir captures/example --profile-dir profiles/example

# Automation without prompts
python chrome_network_logger.py --non-interactive --output-dir captures
```

Important options:

| Option | Effect |
|---|---|
| `--body-mode none\|api\|all` | HTTP body and WebSocket/SSE payload policy |
| `--max-body-mb 32` | Maximum stored bytes per body; `0` means unlimited |
| `--sensitive safe\|raw` | Default redaction or raw preservation |
| `--no-interactions` | Disable injected clicks, inputs, forms, and SPA navigation events |
| `--capture-clipboard` | Capture pasted text; redacted in safe mode |
| `--no-console` | Disable console, exceptions, and Log-domain files |
| `--no-storage` | Disable cookie and Web Storage snapshots |
| `--keep-chrome` | Leave Chrome open after disabling Fetch, auto-attach, and injected listeners |
| `--chrome-path PATH` | Explicit Chrome/Chromium executable |

## Output

```text
session_YYYYMMDD_HHMMSS_mmm/
├── manifest.json
├── timeline.jsonl
├── network/
│   ├── requests.jsonl
│   └── bodies/<sha256>.*[.gz]
├── realtime/
├── interactions/
├── browser/                 # includes protocol_capabilities.jsonl
├── snapshots/
└── reports/
    ├── summary.txt
    ├── stats.txt
    ├── requests.csv
    └── interactions.html
```

`network/requests.jsonl` is canonical. The `isApi` field provides filtering without maintaining duplicate `full` and `filtered` bodies.

Each body reference records its relative path, SHA-256, original/stored size, MIME type, compression, truncation, and redaction state.

## Sensitive-data handling

The default `--sensitive safe` mode redacts authorization and cookie headers, passwords, secrets, API keys, access/refresh/ID tokens, OTP/PIN/CVV-like values, sensitive URL parameters, structured JSON/form fields, password inputs, sensitive form fields, and clipboard payloads.

A redacted value looks like:

```text
<redacted len=123 hmac=4ab31c8702ef>
```

The HMAC uses a random key created for each capture: equal values can be compared **within one session**, but not across sessions. The key is not written to the logs. Sensitive input and form values are instead redacted inside the page as `<redacted len=N source=browser>`: the raw value never crosses the CDP binding, and this length-only marker is not an equality fingerprint. Raw mode must be selected explicitly.

Safe mode is a protective default, not a guarantee that every possible secret will be recognized. A proprietary format, binary payload, or sensitive field with an unusual name may remain visible, so every capture should still be treated as confidential.

## Proxy support

Supported `proxy.txt` examples:

```text
host:port
host:port:user:password
user:password@host:port
http://host:port
https://user:password@host:port
socks5://host:port
[2001:db8::1]:8080
host port user password
```

```bash
python chrome_network_logger.py --proxy random
python chrome_network_logger.py --proxy 2
python chrome_network_logger.py --proxy none
python chrome_network_logger.py --proxy-prompt
```

HTTP(S) upstreams use a loopback relay that injects proxy authentication and supports **P** to switch between the upstream and direct routing on Windows. Active sockets are closed during a switch. Unauthenticated SOCKS proxies are passed directly to Chrome; authenticated SOCKS is rejected clearly rather than pretending to support it. HTTPS upstream certificate verification is enabled unless `--proxy-insecure-tls` is explicitly used.

## CDP scope and limitations

- `Network.getRequestPostData` omits uploaded file bytes in multipart requests. When Chrome separately exposes `postDataEntries.bytes`, the logger externalizes them, but availability still depends on what CDP provides for that request.
- Network-domain WebTransport events expose lifecycle, not stream/datagram payloads.
- Very large or streaming responses may exceed CDP buffers or the configured body limit.
- Redirect response bodies are not exposed by `Fetch.getResponseBody`; redirect metadata and headers are still retained per hop.
- Raw packet traffic and WebRTC media/DataChannel data remain out of scope.
- Fetch interception is limited to response-stage `Document` requests instead of pausing every browser request.
- Experimental or unavailable Chrome commands are recorded in `browser/protocol_capabilities.jsonl`; one unsupported capability does not automatically mark the entire session as failed.

Official references: [Network](https://chromedevtools.github.io/devtools-protocol/tot/Network/), [Target](https://chromedevtools.github.io/devtools-protocol/tot/Target/), and [Fetch](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/).

## Code architecture

```text
chrome_logger/
├── cli.py                 # program lifecycle
├── cdp.py                 # CDP client, targets, pending commands, shutdown
├── network_capture.py     # HTTP, redirects, ExtraInfo, and bodies
├── realtime_capture.py    # WebSocket, SSE, and WebTransport
├── browser_capture.py     # interactions, console, navigation, snapshots
├── registry.py            # session/request/hop identity and ExtraInfo ordering
├── storage.py             # writer thread, JSONL, bodies, and reports
├── redaction.py           # contextual redaction
├── proxy.py               # parsing and HTTP(S) relay
└── chrome.py              # dedicated-profile launch and cleanup
```

`chrome_network_logger.py` remains a compatible wrapper. Tests cover registries, CDP handlers, timestamps, storage, redaction, proxy behavior, and the injected interaction script.

## Security and authorization

Use this tool only for applications, accounts, and systems you own or are authorized to inspect. Even safe-mode captures can contain private URLs and session metadata. `session_*`, `capture_profile`, and `proxy.txt` are excluded by Git.

## License

MIT
