# Chrome Network Logger

[🇫🇷 Version française](README.fr.md)

A standalone, **dependency-light** Python script that captures **everything** happening inside a Chrome browser via the Chrome DevTools Protocol (CDP) — no Selenium, no Playwright. It uses a dedicated, isolated Chrome profile so your main browser is never touched.

## ✨ What it captures

| Category | Details |
|---|---|
| **HTTP requests** | URL, method, headers, `postData` (POST/PUT/form bodies) |
| **HTTP responses** | Status, headers, **full body** (JSON, HTML, images, binary…) |
| **Cookies** | Real `Set-Cookie` headers via `ExtraInfo`, outgoing `Cookie` headers, full cookie dump after login |
| **WebSocket** | Frames sent **and** received, opcode/binary flag, handshake request/response (cookies on upgrade), frame errors |
| **Server-Sent Events** | All SSE messages with event name & data |
| **User interactions** | Every `click`, `change` (checkboxes, radios, selects, dates), `input` (typed text including emails & passwords), special keys (`Enter`, `Tab`, `Esc`, Ctrl/Meta combos), `paste` & `copy` (clipboard content), `focus`, SPA navigation (`popstate`, `hashchange`, `beforeunload`) |
| **Form submits** | Full `FormData` serialized (login forms, etc.) |
| **JS errors & console** | All `console.log/warn/error`, uncaught exceptions |
| **Multi-tab / workers** | Auto-attach to new tabs, iframes, popups (recursive), workers and service workers |
| **Navigation events** | `Page.frameNavigated` for accurate timeline |

## 🥷 Stealth

- Dedicated Chrome profile (no interference with your main browser)
- User interactions go through a CDP **binding** with a random name (re-generated each run), not `console.log` → not detectable by classic anti-bot scripts that monitor the console
- The binding name is removed from `window` immediately after install
- `FORM_INTERCEPT_JS` also uses the binding (no `console.log` markers)

## 📦 Install

```bash
pip install websocket-client psutil
```

Chrome must be installed at one of the default Windows paths (the script auto-detects).

## 🚀 Usage

```bash
python chrome_network_logger.py
```

**First run**: the script creates an empty profile under `./capture_profile/`. Chrome opens, you log in to your target site, configure cookies, etc. Press `Ctrl+C` to save.

**Subsequent runs**: your profile + cookies/sessions are reused as-is.

You'll be prompted for a session subfolder name (useful to group sessions per site).

## 🌐 Proxy support

Drop a `proxy.txt` file next to the script. All these formats are auto-detected:

```
host:port
host:port:user:pass
user:pass@host:port
http://host:port
https://user:pass@host:port
socks5://host:port
socks4://user:pass@host:port
host port              (space/tab-separated)
host port user pass    (space/tab-separated, e.g. Decodo / Bright Data exports)
```

**Selection behaviour (multiple proxies):**

| Command | Behaviour |
|---|---|
| `python chrome_network_logger.py` | picks one **at random** |
| `--proxy-prompt` | shows a numbered list, prompts you to choose |
| `--proxy 2` | uses proxy #2 from the file |
| `--proxy random` | explicit random (same as default) |
| `--proxy none` | disables proxy even if `proxy.txt` exists |
| `--proxy-file other.txt` | loads proxies from a different file |

If credentials are present, a tiny unpacked Chrome extension is generated on the fly to feed them to `webRequest.onAuthRequired` (no auth prompt).

## 📁 Output layout

```
session_YYYYMMDD_HHMMSS/
├── README.txt                     # Auto-generated description
├── full/
│   ├── requests.jsonl             # EVERYTHING (CSS, fonts, images, XHR, WS…)
│   └── summary.txt                # Human-readable summary
├── filtered/
│   ├── requests.jsonl             # Only XHR/Fetch/Document/WebSocket/EventSource
│   └── summary.txt
├── events/
│   ├── full/events.jsonl          # All user interactions with FULL detail
│   │                              # (cssPath, xpath, attrs, outerHTML, value…)
│   └── summary/
│       ├── events.jsonl           # Slim version (event/ts/url/outerHTML)
│       └── events.html            # Browsable HTML view
├── form_submit_captured.json      # All submitted forms (FormData incl. password)
└── cookies_<label>.json           # Cookie dumps (auto post-login + manual)
```

## ⚠️ Security & Legal Notice

This tool captures **plaintext passwords, tokens, session cookies, and any text you type or paste**. It is intended for:

- Debugging your own web applications
- Reverse-engineering APIs you have permission to access
- Security research on your own systems

**Do not** use it on services you don't own or don't have explicit permission to inspect. Store the `session_*` folders on encrypted storage and never commit them to a public repo.

## 🛠️ How it works

1. Launches Chrome with `--remote-debugging-port=<free>` pointing at the dedicated profile
2. Connects to CDP over WebSocket
3. Enables: `Network`, `Page`, `Runtime`, `Fetch` (intercepts all URLs to grab `postData` on form navigations), `Target` (auto-attach to new tabs/workers)
4. Registers a `Runtime.addBinding` and injects JS to forward user interactions via that binding
5. Listens to all CDP events, writes one entry per request to JSONL

## 📜 License

MIT

---

> 🤖 **Full disclosure:** This project was built by [@Antoninnnnnnnn](https://github.com/Antoninnnnnnnn) who freely admits he doesn't understand a single line of this code. The real MVP here is AI pair programming. Turns out you don't need to know how to code to ship code. Welcome to 2026.
