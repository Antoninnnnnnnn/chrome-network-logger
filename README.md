# Chrome Network Logger v3

[![Tests](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/tests.yml/badge.svg)](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/tests.yml)
[![CodeQL](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/codeql.yml/badge.svg)](https://github.com/Antoninnnnnnnn/chrome-network-logger/actions/workflows/codeql.yml)

[🇫🇷 Version française](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/README.fr.md)

Python toolkit for capturing **Chrome application-layer traffic** through the Chrome DevTools Protocol (CDP), without Selenium or Playwright. It launches a dedicated Chrome profile, connects to the **browser target**, and attaches every supported page, popup, out-of-process iframe, webview, and worker target exposed by Chrome.

> This is not a packet sniffer. Raw DNS/TCP/TLS/QUIC and WebRTC media/DataChannel payloads are outside CDP; multipart bytes are available only when Chrome exposes them explicitly.

## What changed in v3

- One entry point: `python chrome_network_logger.py`, or `chrome-network-logger` after installation.
- Browser-level CDP attachment for independent tabs and popups.
- Request identity namespaced by `sessionId`, `requestId`, and redirect hop.
- Every 3xx hop is retained separately, including its `ExtraInfo` data.
- Graceful shutdown flushes in-flight requests and open WebSocket/WebTransport connections as `incomplete`.
- Bodies are external, compressed, per-body/session-size-limited, and SHA-256 deduplicated instead of duplicated in multiple JSONL files.
- WebSocket frames and SSE messages are streamed to disk rather than accumulated indefinitely in RAM.
- One canonical source: `network/requests.jsonl`.
- Normalized timestamps (`epochMs`, local ISO time, and CDP monotonic time when available).
- Start/end cookie and localStorage/sessionStorage snapshots.
- Dedicated browser console, exception, log, navigation, and target files.
- A single interaction script installed in an isolated JavaScript world; safe mode redacts every form-control value and never exports raw `outerHTML`.
- Sensitive values are redacted by default while retaining their length and a per-session HMAC.
- Rewritten proxy relay with correct socket lifecycle, IPv6, HTTP(S) upstream support, and live direct/proxy switching on Windows.
- Fatal CDP/writer failures produce an error manifest and non-zero process exit code instead of a false success.
- Bounded interaction payloads, pending `ExtraInfo`, proxy connections, and writer queue prevent unbounded memory growth.
- Modular typed package, 96 tests, coverage enforcement, package validation, Dependabot, CodeQL, and Windows/Linux/macOS CI on Python 3.10–3.14.
- Automatic official Stable Chrome for Testing download and caching when no local Chrome is available, without ChromeDriver.

## Installation

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e .[dev]
python -m ruff check .
python -m ruff format --check .
python -m bandit -q -r chrome_logger chrome_network_logger.py -s B404,B603
python -m pytest --cov=chrome_logger
python -m build
python -m twine check dist/*
```

Requires Python 3.10+. An installed Chrome/Chromium is preferred; otherwise the [official Stable Chrome for Testing build](https://googlechromelabs.github.io/chrome-for-testing/) is fetched.

## Usage

```bash
python chrome_network_logger.py
```

On first run, a persistent isolated profile is created at `./capture_profile`. Your normal Chrome profile is not used. If Chrome is missing, the official Stable browser is downloaded once into the user cache (`%LOCALAPPDATA%\chrome-network-logger` on Windows) and can then be reused offline. ChromeDriver, Selenium, and Playwright are not installed.

This is a genuine visible Chrome process launched without headless mode, WebDriver, or `--enable-automation`, and with a non-zero loopback CDP port so Chrome does not force `navigator.webdriver=true`. That avoids Selenium/Playwright-specific markers, but it **does not guarantee invisibility**: a website may still infer a fresh profile, CDP instrumentation, extensions, network traits, or other environmental signals.

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

# Automation without prompts, finalized after 60 seconds
python chrome_network_logger.py --non-interactive --output-dir captures --duration 60
```

Important options:

| Option | Effect |
|---|---|
| `--body-mode none\|api\|all` | HTTP body and WebSocket/SSE payload policy |
| `--max-body-mb 32` | Maximum stored bytes per body; `0` means unlimited |
| `--max-session-body-mb 2048` | Maximum total unique stored body bytes per session; `0` means unlimited |
| `--sensitive safe\|raw` | Default redaction or raw preservation |
| `--no-interactions` | Disable injected clicks, inputs, forms, and SPA navigation events |
| `--capture-clipboard` | Capture pasted text; redacted in safe mode |
| `--no-console` | Disable console, exceptions, and Log-domain files |
| `--no-storage` | Disable cookie and Web Storage snapshots |
| `--keep-chrome` | Leave Chrome open after disabling Fetch, auto-attach, and injected listeners |
| `--duration SECONDS` | Stop and finalize automatically; must be finite and non-negative |
| `--start-url URL` | Initial page; defaults to `about:blank` to avoid unsolicited new-tab traffic |
| `--proxy N\|random\|none` | Use an explicitly selected proxy; `none`/direct is the default |
| `--chrome-path PATH` | Explicit Chrome/Chromium executable |
| `--managed-chrome-dir PATH` | Cache location for the official managed Stable browser |
| `--no-download-chrome` | Fail instead of downloading Chrome when no browser is installed |
| `--refresh-managed-chrome` | Check for a newer managed Stable build when the fallback is used |
| `--version` | Print the installed logger version |

## Output

```text
session_YYYYMMDD_HHMMSS_mmm_PID_RANDOM/
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

Each body reference records its SHA-256, original/processed/stored size, MIME type, detected text encoding, compression, truncation, and redaction state. When the session-wide limit is reached, metadata is retained with `omittedReason: "sessionBodyLimit"` and no misleading file path.

See [the capture schema](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/docs/CAPTURE_SCHEMA.md) for stability guarantees and field definitions.

## Sensitive-data handling

The default `--sensitive safe` mode redacts authorization and cookie headers, passwords, secrets, API keys, access/refresh/ID tokens, OTP/PIN/CVV-like values, sensitive URL parameters (including `data:`/`javascript:` URLs), structured JSON/form fields, every form-control value, form data, sensitive HTML attributes, storage values, and clipboard payloads.

A redacted value looks like:

```text
<redacted len=123 hmac=4ab31c8702ef>
```

The HMAC uses a random key created for each capture: equal values can be compared **within one session**, but not across sessions. The key is not written to the logs. Input and form values are redacted inside the isolated page world as `<redacted len=N source=browser>`: the raw value never crosses the CDP binding, and this length-only marker is not an equality fingerprint. Safe-mode element markup is replaced by a tag-only placeholder. Raw mode must be selected explicitly.

Safe mode is a protective default, not a guarantee that every possible secret will be recognized. A proprietary format, binary payload, encrypted application payload, or sensitive field with an unusual name may remain visible, so every capture should still be treated as confidential. See the [threat model](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/docs/THREAT_MODEL.md).

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

Merely having a `proxy.txt` file never enables a proxy: routing remains direct until `--proxy`, `--proxy-prompt`, or another explicit selector is used. The relay also limits concurrent connections and returns `503` when saturated.

## CDP scope and limitations

- `Network.getRequestPostData` omits uploaded file bytes in multipart requests. When Chrome separately exposes `postDataEntries.bytes`, the logger externalizes them, but availability still depends on what CDP provides for that request.
- Network-domain WebTransport events expose lifecycle, not stream/datagram payloads.
- Very large or streaming responses may exceed CDP buffers or the configured body limit.
- Redirect response bodies are not exposed by `Fetch.getResponseBody`; redirect metadata and headers are still retained per hop.
- Raw packet traffic and WebRTC media/DataChannel data remain out of scope.
- Fetch interception is limited to response-stage `Document` requests instead of pausing every browser request.
- Optional experimental capabilities are recorded in `browser/protocol_capabilities.jsonl`. Failure or timeout of a required domain (`Network`, `Runtime`, `Page`, `Fetch`, or target auto-attach) marks the capture unhealthy and returns a non-zero exit code.

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
├── managed_chrome.py      # official download/cache and safe extraction
└── chrome.py              # dedicated-profile launch and cleanup
```

`chrome_network_logger.py` remains a compatible wrapper. Tests cover registries, CDP handlers and security boundaries, HTTP/Fetch/realtime lifecycles, timestamps, storage health and limits, redaction, proxy behavior, managed Chrome installation, CLI failure codes, and the injected interaction script. See [CONTRIBUTING.md](https://github.com/Antoninnnnnnnn/chrome-network-logger/blob/main/CONTRIBUTING.md) before submitting a change.

## Security and authorization

Use this tool only for applications, accounts, and systems you own or are authorized to inspect. Even safe-mode captures can contain private URLs and session metadata. `session_*`, `capture_profile`, and `proxy.txt` are excluded by Git.

## License

MIT
