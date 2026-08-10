# Chrome Network Logger

[🇫🇷 Version française](README.fr.md)

A dependency-light Python toolkit for capturing **application-layer Chrome traffic** through the Chrome DevTools Protocol (CDP), without Selenium or Playwright. It uses a dedicated Chrome profile so your normal browser profile is not touched.

The repository now has two entry points:

- `chrome_network_logger.py` — general/full capture with user interactions.
- `api_network_logger.py` — **recommended for API analysis**: cleaner output, stronger multi-tab handling, richer request/response metadata and shutdown snapshots.

## API analysis mode

```bash
pip install websocket-client psutil
python api_network_logger.py
```

The API mode reuses the same `capture_profile` and proxy helpers as the main logger.

### What the API mode captures

| Category | Details |
|---|---|
| **HTTP(S)** | URL, method, normal headers, CDP `ExtraInfo` headers, initiator, target/tab context |
| **Request bodies** | `postData` plus `Network.getRequestPostData` fallback when Chrome omits it from the event |
| **Responses** | Status, headers, body, protocol/timing/cache/service-worker/security fields exposed by CDP |
| **Failures** | Network errors, blocked reason, cancellation and CORS error status |
| **Redirects** | Every redirect hop is preserved instead of being overwritten by the next request |
| **Cookies** | Sent/received cookie information plus a final full browser cookie snapshot |
| **Storage** | Final `localStorage` and `sessionStorage` snapshots for attached pages |
| **WebSocket** | Handshake plus frames sent/received and frame errors |
| **SSE / EventSource** | Messages with event name, ID and data |
| **WebTransport** | Creation / connection / close lifecycle; CDP does not expose stream/datagram payloads through these Network events |
| **Tabs / workers** | Browser-level CDP target discovery for independent tabs/popups, then recursive attachment to iframes/workers/service workers |
| **Console errors** | Exceptions and warning/error/assert console messages, kept separately from network logs |

The `api/requests.jsonl` view keeps XHR, Fetch, Document, WebSocket, EventSource, Ping/beacon-like requests, write methods and CORS preflights. `full/requests.jsonl` retains the broader CDP request stream.

## Important reliability changes in API mode

- Request IDs are namespaced by CDP session, avoiding collisions between tabs/workers.
- Response bodies use larger buffers and CDP durable-message storage when supported.
- API-relevant response interception is limited to `Document`, `XHR` and `Fetch`; the logger no longer pauses every static asset just to inspect its request.
- Open WebSockets, SSE streams and in-flight requests are flushed on shutdown instead of silently disappearing.
- Body-capture failures are written as errors in the entry instead of looking like successful empty bodies.
- `requestWillBeSentExtraInfo` / `responseReceivedExtraInfo` data is preserved, including blocked cookies and client security state.

## Output

```text
session_api_YYYYMMDD_HHMMSS/
├── full/
│   ├── requests.jsonl
│   └── summary.txt
├── api/
│   ├── requests.jsonl
│   ├── summary.txt
│   └── webtransport.jsonl        # only created when used
└── meta/
    ├── cookies_shutdown.json
    ├── storage_shutdown.jsonl
    └── console_errors.jsonl      # only created when relevant
```

## General capture mode

```bash
python chrome_network_logger.py
```

The original mode is still useful when you want the network capture **plus a detailed user-interaction timeline** (clicks, input/change, forms, navigation, etc.).

## Proxy support

Drop a `proxy.txt` next to the scripts. Supported input formats include:

```text
host:port
host:port:user:pass
user:pass@host:port
http://host:port
https://user:pass@host:port
socks5://host:port
host port user pass
```

Useful options:

```bash
python api_network_logger.py --proxy random
python api_network_logger.py --proxy 2
python api_network_logger.py --proxy none
python api_network_logger.py --proxy-prompt
python api_network_logger.py --proxy-file other.txt
```

## Scope and limitations

This is a **CDP application-layer logger**, not a packet sniffer. It intentionally does not mix raw DNS/TCP/TLS/QUIC packets into the API logs. WebRTC media/DataChannel payloads are also outside this capture path.

CDP itself also has limits: `Network.getRequestPostData` omits uploaded file bytes from multipart requests, very large/streaming resources can still be unavailable, and WebTransport Network events expose lifecycle rather than stream/datagram payloads.

For API reconstruction this is usually preferable to packet-level capture because HTTPS request/response content is available after Chrome has decrypted it.

## Security & legal notice

Captures can contain **passwords, bearer tokens, API keys, session cookies and storage tokens**. Use the tool only on applications/systems you own or are authorized to inspect. Keep capture folders private and never commit them to a public repository.

## License

MIT

---

> 🤖 **Full disclosure:** This project was built by [@Antoninnnnnnnn](https://github.com/Antoninnnnnnnn) with heavy AI pair-programming assistance.
