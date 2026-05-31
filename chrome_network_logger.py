"""
Chrome Network Logger v2 - CDP direct avec profil dédié
========================================================
Stratégie : profil Chrome dédié à la capture (isolé de ton Chrome principal).
Tu l'initialises 1 fois (login sur le site cible), puis chaque relance c'est
ton profil + ses cookies/sessions, sans aucun conflit possible.

Capture TOUT via CDP direct (pas de Selenium, pas de Playwright) :
  - Requests, responses, headers
  - Request bodies (POST/PUT JSON, form data)
  - Response bodies (JSON API, HTML, etc.)
  - WebSocket frames (sent + received)
  - Console logs + JS errors
  - Multi-onglets (auto-attach)

Sortie :
  capture_profile/                    <- ton profil Chrome dédié (cookies, login)
  session_YYYYMMDD_HHMMSS/
    ├── full/                         <- TOUT (CSS, fonts, images, XHR...)
    │   ├── requests.jsonl
    │   └── summary.txt
    └── filtered/                     <- API uniquement (XHR/Fetch/WS/Document)
        ├── requests.jsonl
        └── summary.txt

Usage :
  pip install websocket-client requests psutil
  python chrome_logger_v2.py
"""

import argparse

import base64

import json

import os

import random

import socket

import subprocess

import sys

import threading

import time

import signal

import urllib.request

import urllib.error

from datetime import datetime

from pathlib import Path

try:

    import websocket                                

    import psutil                         

except ImportError:

    print("[!] Dépendances manquantes :")

    print("    pip install websocket-client psutil")

    sys.exit(1)

CHROME_PATHS = [

    r"C:\Program Files\Google\Chrome\Application\chrome.exe",

    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",

    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),

]

DEDICATED_PROFILE_DIR = str(Path.cwd() / "capture_profile")

PROXY_FILE = str(Path.cwd() / "proxy.txt")

FILTERED_TYPES = {"XHR", "Fetch", "Document", "WebSocket", "EventSource"}

import secrets as _secrets

USER_EVENT_BINDING = "__b_" + _secrets.token_hex(6)

USER_INTERACTION_JS = r"""
(function() {
    var BNAME = '__BINDING_NAME__';
    if (typeof window[BNAME] !== 'function') return;
    // Récupère le binding dans une closure puis supprime le global pour limiter
    // sa détection par scripts anti-bot qui énumèrent window.
    var send = window[BNAME];
    try { delete window[BNAME]; } catch(e) { try { window[BNAME] = undefined; } catch(_) {} }
    var INSTALLED = '__i_' + Math.random().toString(36).slice(2);
    if (window[INSTALLED]) return;
    Object.defineProperty(window, INSTALLED, {value: 1, enumerable: false, configurable: false});

    function cssPath(el) {
        if (!(el instanceof Element)) return '';
        var path = [];
        while (el && el.nodeType === 1 && path.length < 12) {
            var sel = el.nodeName.toLowerCase();
            if (el.id) { sel += '#' + CSS.escape(el.id); path.unshift(sel); break; }
            var sib = el, nth = 1;
            while ((sib = sib.previousElementSibling)) {
                if (sib.nodeName.toLowerCase() === el.nodeName.toLowerCase()) nth++;
            }
            sel += ':nth-of-type(' + nth + ')';
            path.unshift(sel);
            el = el.parentElement;
        }
        return path.join(' > ');
    }

    function xpath(el) {
        if (!(el instanceof Element)) return '';
        if (el.id) return '//*[@id="' + el.id + '"]';
        var parts = [];
        while (el && el.nodeType === 1) {
            var i = 1, sib = el.previousSibling;
            while (sib) {
                if (sib.nodeType === 1 && sib.nodeName === el.nodeName) i++;
                sib = sib.previousSibling;
            }
            parts.unshift(el.nodeName.toLowerCase() + '[' + i + ']');
            el = el.parentNode;
            if (!el || el.nodeType !== 1) break;
        }
        return '/' + parts.join('/');
    }

    function describe(el) {
        if (!(el instanceof Element)) return null;
        var r = el.getBoundingClientRect();
        var attrs = {};
        for (var i = 0; i < el.attributes.length; i++) {
            var a = el.attributes[i];
            attrs[a.name] = a.value;
        }
        var text = (el.innerText || el.textContent || '').trim().slice(0, 200);
        var outer = '';
        try { outer = (el.outerHTML || '').slice(0, 8000); } catch(e) {}
        return {
            tag: el.tagName.toLowerCase(),
            id: el.id || null,
            classes: el.className && el.className.toString ? el.className.toString() : null,
            name: el.getAttribute('name'),
            type: el.getAttribute('type'),
            role: el.getAttribute('role'),
            ariaLabel: el.getAttribute('aria-label'),
            placeholder: el.getAttribute('placeholder'),
            value: ('value' in el) ? String(el.value).slice(0, 500) : null,
            checked: ('checked' in el) ? el.checked : null,
            text: text,
            href: el.getAttribute('href'),
            attrs: attrs,
            rect: { x: r.x, y: r.y, w: r.width, h: r.height },
            cssPath: cssPath(el),
            xpath: xpath(el),
            outerHTML: outer
        };
    }

    function emit(payload) {
        try { send(JSON.stringify(payload)); } catch(e) {}
    }

    document.addEventListener('click', function(e) {
        emit({
            event: 'click',
            ts: Date.now(),
            url: location.href,
            button: e.button,
            x: e.clientX, y: e.clientY,
            target: describe(e.target),
            path: (e.composedPath ? e.composedPath() : []).slice(0, 5).map(describe).filter(Boolean)
        });
    }, true);

    document.addEventListener('change', function(e) {
        emit({ event: 'change', ts: Date.now(), url: location.href, target: describe(e.target) });
    }, true);

    var inputTimers = new WeakMap();
    document.addEventListener('input', function(e) {
        var el = e.target;
        if (!(el instanceof Element)) return;
        var prev = inputTimers.get(el);
        if (prev) clearTimeout(prev);
        var t = setTimeout(function() {
            emit({ event: 'input', ts: Date.now(), url: location.href, target: describe(el) });
        }, 400);
        inputTimers.set(el, t);
    }, true);

    // Touches spéciales / raccourcis (Enter, Tab, Escape, F-keys, Ctrl/Meta combos)
    document.addEventListener('keydown', function(e) {
        var k = e.key || '';
        var isSpecial = (k.length > 1) || e.ctrlKey || e.metaKey || e.altKey;
        if (!isSpecial) return;
        emit({
            event: 'keydown',
            ts: Date.now(),
            url: location.href,
            key: k,
            code: e.code,
            ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey,
            target: describe(e.target)
        });
    }, true);

    // Clipboard : paste capture le texte coll\u00e9 (utile pour cookies/tokens copi\u00e9s ailleurs)
    document.addEventListener('paste', function(e) {
        var data = '';
        try { data = (e.clipboardData || window.clipboardData).getData('text') || ''; } catch(_) {}
        emit({
            event: 'paste',
            ts: Date.now(),
            url: location.href,
            data: String(data).slice(0, 5000),
            target: describe(e.target)
        });
    }, true);

    document.addEventListener('copy', function(e) {
        var data = '';
        try { data = (e.clipboardData || window.clipboardData).getData('text') || ''; } catch(_) {}
        emit({
            event: 'copy',
            ts: Date.now(),
            url: location.href,
            data: String(data).slice(0, 5000),
            target: describe(e.target)
        });
    }, true);

    // Focus sur inputs/selects/buttons : utile pour reconstruire la s\u00e9quence
    document.addEventListener('focusin', function(e) {
        var el = e.target;
        if (!(el instanceof Element)) return;
        var tag = el.tagName.toLowerCase();
        if (tag !== 'input' && tag !== 'textarea' && tag !== 'select' && tag !== 'button') return;
        emit({ event: 'focus', ts: Date.now(), url: location.href, target: describe(el) });
    }, true);

    // Navigation SPA
    window.addEventListener('popstate', function() {
        emit({ event: 'popstate', ts: Date.now(), url: location.href });
    }, true);
    window.addEventListener('hashchange', function(e) {
        emit({ event: 'hashchange', ts: Date.now(), url: location.href, oldURL: e.oldURL, newURL: e.newURL });
    }, true);

    // D\u00e9part de page (souvent suivi d'une vraie nav ou fermeture)
    window.addEventListener('beforeunload', function() {
        emit({ event: 'beforeunload', ts: Date.now(), url: location.href });
    }, true);
})();
""".replace("__BINDING_NAME__", USER_EVENT_BINDING)

FORM_INTERCEPT_JS = r"""
(function() {
    var BNAME = '__BINDING_NAME__';
    if (typeof window[BNAME] !== 'function') return;
    var send = window[BNAME];
    var INST = '__fi_' + Math.random().toString(36).slice(2);
    if (window[INST]) return;
    Object.defineProperty(window, INST, {value: 1, enumerable: false, configurable: false});
    document.addEventListener('submit', function(e) {
        try {
            var form = e.target;
            var fd = new FormData(form);
            var obj = {};
            fd.forEach(function(v, k) { obj[k] = v; });
            send(JSON.stringify({
                event: 'form_submit',
                ts: Date.now(),
                url: location.href,
                action: form.action,
                method: form.method,
                data: obj
            }));
        } catch(err) {
            try { send(JSON.stringify({event: 'form_submit_err', error: String(err)})); } catch(_) {}
        }
    }, true);
})();
""".replace("__BINDING_NAME__", USER_EVENT_BINDING)

CREATE_NEW_PROCESS_GROUP = 0x00000200

DETACHED_PROCESS = 0x00000008

def find_chrome():

    for path in CHROME_PATHS:

        if os.path.exists(path):

            return path

    print("[!] Chrome introuvable.")

    sys.exit(1)

def parse_proxy_line(line):
    """Auto-detect proxy format. Returns dict or None.
    Supported separators: ':' OR whitespace (tab/space).
    Supported formats:
      scheme://host:port
      scheme://user:pass@host:port
      user:pass@host:port
      host:port
      host:port:user:pass
      host port            (whitespace)
      host port user pass  (whitespace)
    Schemes: http, https, socks4, socks5 (default: http).
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    scheme = "http"
    if "://" in s:
        scheme, _, s = s.partition("://")
        scheme = scheme.lower()
    user = pwd = None
    if "@" in s:
        creds, _, hostpart = s.rpartition("@")
        if ":" in creds:
            user, _, pwd = creds.partition(":")
        else:
            user = creds
        s = hostpart
    if any(c.isspace() for c in s):
        parts = s.split()
    else:
        parts = s.split(":")
    if len(parts) == 2:
        host, port = parts
    elif len(parts) == 4 and user is None:
        host, port, user, pwd = parts
    elif len(parts) == 3 and user is None:
        host, port, user = parts
    else:
        return None
    try:
        port = int(port)
    except ValueError:
        return None
    if scheme not in ("http", "https", "socks4", "socks5"):
        scheme = "http"
    return {"scheme": scheme, "host": host, "port": port, "user": user, "pass": pwd}

def load_all_proxies(path=PROXY_FILE):
    if not os.path.exists(path):
        return []
    proxies = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                proxy = parse_proxy_line(line)
                if proxy:
                    proxies.append(proxy)
    except OSError as e:
        print(f"[!] Lecture {path} impossible: {e}")
    return proxies

def _proxy_label(p):
    user = (p.get("user") or "")[:2] + "***" if p.get("user") else "-"
    return f"{p['scheme']}://{p['host']}:{p['port']}  user={user}"

def select_proxy(proxies, cli_index=None, prompt=False):
    """Return one proxy dict or None.
    cli_index: int (1-based) or 'random' or 'none' or None.
    prompt: ask interactively when True and cli_index is None.
    Default (no arg, no flag): random among available proxies.
    """
    if not proxies:
        return None
    if cli_index == "none":
        return None
    if cli_index == "random" or cli_index is None:
        if len(proxies) == 1 or not prompt:
            chosen = random.choice(proxies)
            if len(proxies) > 1:
                print(f"[+] Proxy sélectionné (aléatoire) : {_proxy_label(chosen)}")
            return chosen
    if isinstance(cli_index, int):
        idx = cli_index - 1
        if 0 <= idx < len(proxies):
            return proxies[idx]
        print(f"[!] Proxy #{cli_index} introuvable ({len(proxies)} dispo). Aléatoire.")
        return random.choice(proxies)
    print("\n[?] Proxies disponibles :")
    for i, p in enumerate(proxies, 1):
        print(f"    {i}. {_proxy_label(p)}")
    print(f"    0. Aucun (connexion directe)")
    while True:
        try:
            raw = input(f"Choix [0-{len(proxies)}] (Entrée = aléatoire) : ").strip()
            if raw == "":
                chosen = random.choice(proxies)
                print(f"[+] Proxy aléatoire : {_proxy_label(chosen)}")
                return chosen
            n = int(raw)
            if n == 0:
                return None
            if 1 <= n <= len(proxies):
                return proxies[n - 1]
        except ValueError:
            pass
        print(f"  Entrer un nombre entre 0 et {len(proxies)}.")

def _make_proxy_auth_header(user, pwd):
    token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    return f"Basic {token}"

_active_relays: list = []

class _LocalProxyRelay(threading.Thread):
    """Minimal local HTTP/HTTPS relay that injects Proxy-Authorization into every
    CONNECT tunnel and plain HTTP request so Chrome never sees a 407 popup.
    proxy_enabled can be toggled at runtime to switch between upstream proxy
    and direct connection without restarting Chrome."""

    def __init__(self, upstream_host, upstream_port, auth_header):
        super().__init__(daemon=True, name="ProxyRelay")
        self._up_host = upstream_host
        self._up_port = upstream_port
        self._auth = auth_header
        self._proxy_enabled = True
        self._active_sockets: set = set()
        self._sock_lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self.local_port = self._srv.getsockname()[1]
        self._srv.listen(256)

    @property
    def proxy_enabled(self):
        return self._proxy_enabled

    @proxy_enabled.setter
    def proxy_enabled(self, value):
        if bool(value) != self._proxy_enabled:
            self._proxy_enabled = bool(value)
            with self._sock_lock:
                for s in list(self._active_sockets):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        s.close()
                    except Exception:
                        pass
                self._active_sockets.clear()

    def run(self):
        while True:
            try:
                client, _ = self._srv.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except Exception:
                break

    def stop(self):
        try:
            self._srv.close()
        except Exception:
            pass

    @staticmethod
    def _recv_headers(sock, limit=131072):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > limit:
                break
        return buf

    @staticmethod
    def _tunnel(a, b):
        def _fwd(src, dst):
            try:
                while True:
                    d = src.recv(65536)
                    if not d:
                        break
                    dst.sendall(d)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
        t = threading.Thread(target=_fwd, args=(b, a), daemon=True)
        t.start()
        _fwd(a, b)
        t.join()

    def _handle(self, client):
        up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self._sock_lock:
            self._active_sockets.add(up)
            self._active_sockets.add(client)
        try:
            raw = self._recv_headers(client)
            if not raw or b"\r\n\r\n" not in raw:
                return
            sep = raw.index(b"\r\n\r\n")
            headers_raw = raw[:sep]
            leftover = raw[sep + 4:]
            first_line, _, header_rest = headers_raw.partition(b"\r\n")
            parts = first_line.split(b" ", 2)
            method = parts[0].upper()
            target = parts[1].decode("latin-1") if len(parts) > 1 else ""
            up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if method == b"CONNECT":
                if self.proxy_enabled:
                    up.connect((self._up_host, self._up_port))
                    auth_line = f"Proxy-Authorization: {self._auth}\r\n" if self._auth else ""
                    up.sendall(
                        f"CONNECT {target} HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"{auth_line}"
                        f"Proxy-Connection: keep-alive\r\n"
                        f"\r\n".encode()
                    )
                    resp = self._recv_headers(up)
                    status_line = resp.split(b"\r\n")[0].decode("latin-1") if resp else ""
                    if "200" in status_line:
                        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        self._tunnel(client, up)
                    else:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                else:
                    dhost, _, dport_s = target.rpartition(":")
                    up.connect((dhost, int(dport_s)))
                    client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    self._tunnel(client, up)
            else:
                if self.proxy_enabled:
                    clean_lines = [
                        l for l in header_rest.split(b"\r\n")
                        if not l.lower().startswith(b"proxy-authorization:")
                    ]
                    if self._auth:
                        clean_lines.append(f"Proxy-Authorization: {self._auth}".encode())
                    new_req = first_line + b"\r\n" + b"\r\n".join(clean_lines) + b"\r\n\r\n"
                    up.connect((self._up_host, self._up_port))
                    up.sendall(new_req)
                    if leftover:
                        up.sendall(leftover)
                    self._tunnel(client, up)
                else:
                    url_str = target
                    if url_str.startswith("http://"):
                        url_str = url_str[7:]
                    host_part, _, path_part = url_str.partition("/")
                    path = "/" + path_part
                    if ":" in host_part:
                        dhost, _, dport_s = host_part.rpartition(":")
                        dport = int(dport_s)
                    else:
                        dhost, dport = host_part, 80
                    clean_lines = [
                        l for l in header_rest.split(b"\r\n")
                        if not l.lower().startswith(b"proxy-authorization:")
                        and not l.lower().startswith(b"proxy-connection:")
                    ]
                    new_first = parts[0] + b" " + path.encode() + b" HTTP/1.1"
                    new_req = new_first + b"\r\n" + b"\r\n".join(clean_lines) + b"\r\n\r\n"
                    up.connect((dhost, dport))
                    up.sendall(new_req)
                    if leftover:
                        up.sendall(leftover)
                    self._tunnel(client, up)
        except Exception:
            pass
        finally:
            with self._sock_lock:
                self._active_sockets.discard(up)
                self._active_sockets.discard(client)
            try:
                client.close()
            except Exception:
                pass

def build_proxy_chrome_args(proxy):
    """Return Chrome CLI args for the given proxy dict. Starts relay thread if auth needed."""
    if not proxy:
        return []
    scheme = proxy["scheme"]
    host = proxy["host"]
    port = proxy["port"]
    if scheme in ("http", "https"):
        auth = _make_proxy_auth_header(proxy["user"], proxy.get("pass") or "") if proxy.get("user") else None
        relay = _LocalProxyRelay(host, port, auth)
        relay.start()
        _active_relays.append(relay)
        suffix = " (auth injectée)" if auth else ""
        print(f"[+] Relay local port {relay.local_port} → {host}:{port}{suffix} — [P] pour toggle")
        return [f"--proxy-server=http://127.0.0.1:{relay.local_port}"]
    else:
        server = f"{scheme}://{host}:{port}"
        return [f"--proxy-server={server}"]

def _start_proxy_keyboard_thread(relay, toggle_log_path, stop_event):
    """Background thread: press P to toggle proxy on/off while capture is running."""
    try:
        import msvcrt
    except ImportError:
        return
    def _loop():
        while not stop_event.is_set():
            try:
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b"p", b"P"):
                        relay.proxy_enabled = not relay.proxy_enabled
                        state = "enabled" if relay.proxy_enabled else "disabled"
                        ts = datetime.now().strftime("%H:%M:%S")
                        label = "\u2705 PROXY ON" if relay.proxy_enabled else "\u274c PROXY OFF (connexion directe)"
                        print(f"\n[{ts}] [PROXY TOGGLE] {label} ({relay._up_host}:{relay._up_port})")
                        try:
                            with open(toggle_log_path, "a", encoding="utf-8") as f:
                                f.write(json.dumps({
                                    "type": "proxy_toggle",
                                    "ts": datetime.now().isoformat(),
                                    "state": state,
                                    "proxy": f"{relay._up_host}:{relay._up_port}",
                                }) + "\n")
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(0.05)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t

def find_free_port(start=9222):

    for port in range(start, start + 100):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                s.bind(('127.0.0.1', port))

                return port

        except OSError:

            continue

    return start

def safe_append(path, text, retries=30, delay=0.05):

    """Append text to a file, retrying on PermissionError (antivirus, indexer Windows...).

    Évite la perte d'entrées quand un autre process verrouille brièvement le fichier.
    """

    last_err = None

    for _ in range(retries):

        try:

            with open(path, "a", encoding="utf-8") as f:

                f.write(text)

            return True

        except PermissionError as e:

            last_err = e

            time.sleep(delay)

        except OSError as e:

            last_err = e

            time.sleep(delay)

    print(f"[!] Écriture impossible après retries : {path} ({last_err})")

    return False

def _sanitize_folder_name(name: str) -> str:

    """Nettoie le nom pour qu'il soit utilisable comme nom de dossier."""

    name = name.strip()

    forbidden = '<>:"/\\|?*'

    cleaned = "".join("_" if c in forbidden else c for c in name)

    cleaned = cleaned.rstrip(". ")

    return cleaned

def prompt_session_subfolder() -> Path:

    """Demande à l'utilisateur le sous-dossier où sauvegarder la session.

    Retourne le Path du sous-dossier (créé si nécessaire). Si l'utilisateur
    laisse vide, on retombe sur le cwd (comportement historique).
    """

    print()

    print("Dans quel sous-dossier veux-tu sauvegarder cette session ?")

    print("  (ex: youtube, twitch, mysite... vide = dossier courant)")

    raw = input("> ").strip()

    if not raw:

        return Path.cwd()

    cleaned = _sanitize_folder_name(raw)

    if not cleaned:

        print("[!] Nom invalide, fallback dossier courant.")

        return Path.cwd()

    target = Path.cwd() / cleaned

    if target.exists():

        print(f"[+] Sous-dossier existant réutilisé : {target}")

    else:

        target.mkdir(parents=True, exist_ok=True)

        print(f"[+] Sous-dossier créé : {target}")

    return target

def setup_session_dirs(parent_dir=None):

    if parent_dir is None:

        parent_dir = Path.cwd()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    base = parent_dir / f"session_{timestamp}"

    full_dir = base / "full"

    filtered_dir = base / "filtered"

    events_full_dir = base / "events" / "full"

    events_summary_dir = base / "events" / "summary"

    full_dir.mkdir(parents=True, exist_ok=True)

    filtered_dir.mkdir(parents=True, exist_ok=True)

    events_full_dir.mkdir(parents=True, exist_ok=True)

    events_summary_dir.mkdir(parents=True, exist_ok=True)

    return base, full_dir, filtered_dir, (events_full_dir, events_summary_dir)

def kill_orphan_chromes_using_profile(profile_path):

    """Kill seulement les chrome.exe qui utilisent NOTRE profil dédié."""

    profile_path_lower = str(profile_path).lower()

    killed = 0

    for proc in psutil.process_iter(['name', 'cmdline']):

        try:

            name = (proc.info['name'] or '').lower()

            if name not in ('chrome.exe', 'google chrome'):

                continue

            cmdline = ' '.join(proc.info['cmdline'] or []).lower()

            if profile_path_lower in cmdline:

                proc.kill()

                killed += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied):

            pass

    if killed:

        print(f"[+] Tué {killed} processus Chrome orphelin(s) sur le profil dédié")

        time.sleep(1)

def cleanup_locks(profile_dir):

    """Supprime les fichiers de lock du profil dédié."""

    profile_path = Path(profile_dir)

    locks = [

        profile_path / "SingletonLock",

        profile_path / "SingletonCookie",

        profile_path / "SingletonSocket",

        profile_path / "Default" / "SingletonLock",

        profile_path / "Default" / "Lock",

    ]

    for lf in locks:

        try:

            lf.unlink(missing_ok=True)

        except OSError:

            pass

class CDPCapture:

    def __init__(self, full_dir, filtered_dir, debug_port, events_dirs=None):

        self.full_dir = full_dir

        self.filtered_dir = filtered_dir

        if events_dirs is None:

            self.events_full_dir = None

            self.events_summary_dir = None

        else:

            self.events_full_dir, self.events_summary_dir = events_dirs

        self.debug_port = debug_port

        self.requests_data = {}

        self.lock = threading.Lock()

        self.msg_id = 0

        self.id_lock = threading.Lock()

        self.ws: "websocket.WebSocket | None" = None

        self.running = True

        self.pending_body_requests = {}

        # Corps de réponse récupérés via Fetch au stade Response (fiable pour
        # les navigations Document souvent évincées avant getResponseBody).
        self.pending_fetch_bodies = {}

        # networkId dont le corps a déjà été capturé via Fetch → ne pas
        # re-tenter Network.getResponseBody sur loadingFinished.
        self.fetch_body_captured = set()

        self.pending_cookie_dumps = {}                   

        self.extra_info = {}                                   

        self.sessions_enabled = set()

        self.stats = {"requests": 0, "responses": 0, "bodies": 0, "ws_frames": 0, "cookie_dumps": 0}

    def next_id(self):

        with self.id_lock:

            self.msg_id += 1

            return self.msg_id

    def send(self, method, params=None, session_id=None):

        msg_id = self.next_id()

        msg = {"id": msg_id, "method": method, "params": params or {}}

        if session_id:

            msg["sessionId"] = session_id

        if self.ws is None:

            return msg_id

        try:

            self.ws.send(json.dumps(msg))

        except Exception as e:

            print(f"[!] Erreur envoi CDP : {e}")

        return msg_id

    def connect(self):

        try:

            r = urllib.request.urlopen(f"http://127.0.0.1:{self.debug_port}/json", timeout=3)

            targets = json.loads(r.read())

        except Exception as e:

            print(f"[!] Impossible de lister les targets : {e}")

            return False

        page_target = next((t for t in targets if t.get("type") == "page"), None)

        if not page_target:

            print("[!] Aucun onglet trouvé. Création d'un nouvel onglet...")

            try:

                urllib.request.urlopen(

                    urllib.request.Request(

                        f"http://127.0.0.1:{self.debug_port}/json/new?about:blank",

                        method="PUT"

                    ),

                    timeout=3

                )

                time.sleep(0.5)

                r = urllib.request.urlopen(f"http://127.0.0.1:{self.debug_port}/json", timeout=3)

                targets = json.loads(r.read())

                page_target = next((t for t in targets if t.get("type") == "page"), None)

            except Exception as e:

                print(f"[!] Échec création onglet : {e}")

                return False

        if not page_target:

            print("[!] Toujours aucun onglet apr\u00e8s tentative de cr\u00e9ation.")

            return False

        ws_url = page_target["webSocketDebuggerUrl"]

        print(f"[+] Connexion WebSocket CDP : {ws_url}")

        try:

            self.ws = websocket.create_connection(ws_url, timeout=None)

        except Exception as e:

            print(f"[!] WebSocket KO : {e}")

            return False

        self.send("Target.setDiscoverTargets", {"discover": True})

        self.send("Target.setAutoAttach", {

            "autoAttach": True,

            "waitForDebuggerOnStart": False,

            "flatten": True,

        })

        try:

            self.send("Target.setDiscoverTargets", {

                "discover": True,

                "filter": [

                    {"type": "page"}, {"type": "iframe"},

                    {"type": "worker"}, {"type": "service_worker"},

                    {"type": "shared_worker"}, {"type": "webview"},

                    {"type": "browser", "exclude": True},

                ],

            })

        except Exception:

            pass

        self.send("Network.enable", {

            "maxTotalBufferSize": 200_000_000,

            "maxResourceBufferSize": 100_000_000,

            "maxPostDataSize": 10_000_000,

        })

        self.send("Page.enable")

        self.send("Runtime.enable")

        self.send("Network.enableReportingApi", {"enable": True})

        self.send("Fetch.enable", {

            "patterns": [

                {"urlPattern": "*", "requestStage": "Request"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "Document"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "XHR"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "Fetch"},

            ],

            "handleAuthRequests": False,

        })

        self.send("Runtime.addBinding", {"name": USER_EVENT_BINDING})

        self.send("Page.addScriptToEvaluateOnNewDocument", {"source": USER_INTERACTION_JS})

        self.send("Runtime.evaluate", {"expression": USER_INTERACTION_JS})

        self.send("Page.addScriptToEvaluateOnNewDocument", {"source": FORM_INTERCEPT_JS})

        self.send("Runtime.evaluate", {"expression": FORM_INTERCEPT_JS})

        return True

    def dump_all_cookies(self, session_id=None, label=""):

        """Dump tous les cookies actifs dans un fichier cookies_<label>.json."""

        dump_id = self.send("Network.getAllCookies", {}, session_id=session_id)

        self.pending_cookie_dumps[dump_id] = label or f"dump_{int(time.time())}"

    def enable_on_session(self, session_id):

        if session_id in self.sessions_enabled:

            return

        self.sessions_enabled.add(session_id)

        self.send("Network.enable", {

            "maxTotalBufferSize": 200_000_000,

            "maxResourceBufferSize": 100_000_000,

            "maxPostDataSize": 10_000_000,

        }, session_id=session_id)

        self.send("Page.enable", session_id=session_id)

        self.send("Runtime.enable", session_id=session_id)

        self.send("Target.setAutoAttach", {

            "autoAttach": True,

            "waitForDebuggerOnStart": False,

            "flatten": True,

        }, session_id=session_id)

        self.send("Fetch.enable", {

            "patterns": [

                {"urlPattern": "*", "requestStage": "Request"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "Document"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "XHR"},

                {"urlPattern": "*", "requestStage": "Response", "resourceType": "Fetch"},

            ],

            "handleAuthRequests": False,

        }, session_id=session_id)

        self.send("Runtime.addBinding", {"name": USER_EVENT_BINDING}, session_id=session_id)

        self.send("Page.addScriptToEvaluateOnNewDocument", {"source": USER_INTERACTION_JS}, session_id=session_id)

        self.send("Runtime.evaluate", {"expression": USER_INTERACTION_JS}, session_id=session_id)

        self.send("Page.addScriptToEvaluateOnNewDocument", {"source": FORM_INTERCEPT_JS}, session_id=session_id)

        self.send("Runtime.evaluate", {"expression": FORM_INTERCEPT_JS}, session_id=session_id)

    def handle_message(self, msg):

        method = msg.get("method")

        params = msg.get("params", {})

        session_id = msg.get("sessionId")

        if method == "Fetch.requestPaused":

            fetch_req_id = params["requestId"]

            network_id = params.get("networkId", "")

            # ── Stade Response : capturer le corps de façon fiable ──
            # (params contient responseStatusCode/responseHeaders à ce stade).
            # Indispensable pour les navigations Document (POST 3DS, confirmation)
            # dont le corps serait sinon évincé avant Network.getResponseBody.
            if "responseStatusCode" in params or "responseErrorReason" in params:

                if params.get("responseErrorReason"):

                    # Échec réseau : laisser passer sans corps (ne pas bloquer la page)
                    try:

                        self.send("Fetch.continueResponse", {"requestId": fetch_req_id}, session_id=session_id)

                    except Exception:

                        pass

                    return

                body_msg_id = self.send("Fetch.getResponseBody", {"requestId": fetch_req_id}, session_id=session_id)

                self.pending_fetch_bodies[body_msg_id] = (network_id, fetch_req_id, session_id)

                return

            request = params.get("request", {})

            url = request.get("url", "")

            post_data = request.get("postData", "")

            method_str = request.get("method", "GET")

            resource_type = params.get("resourceType", "")

            print(f"[FETCH INTCP] {method_str} {url[:100]} postData_len={len(post_data)}")

            if post_data:

                print(f"[FETCH BODY ] {post_data[:2000]}")

                with self.lock:

                    target = self.requests_data.get(network_id)

                    if target is not None:

                        target["request"]["postData"] = post_data

                        target["fetch_intercepted"] = True

                    else:

                        entry = {

                            "requestId": f"fetch_{fetch_req_id}",

                            "network_id": network_id,

                            "session_id": session_id,

                            "type": resource_type or "Document",

                            "request": request,

                            "fetch_intercepted": True,

                        }

                        self._write_entry(entry)

            self.send("Fetch.continueRequest", {"requestId": fetch_req_id}, session_id=session_id)

            return

        if method == "Target.attachedToTarget":

            new_session = params.get("sessionId")

            target_info = params.get("targetInfo", {})

            target_type = target_info.get("type")

            target_url = target_info.get("url", "")

            print(f"[TARGET ATCH] type={target_type} url={target_url[:80]}")

            if target_type in ("page", "iframe", "webview"):

                self.enable_on_session(new_session)

            elif target_type in ("worker", "service_worker", "shared_worker"):

                if new_session not in self.sessions_enabled:

                    self.sessions_enabled.add(new_session)

                    self.send("Network.enable", {

                        "maxTotalBufferSize": 200_000_000,

                        "maxResourceBufferSize": 100_000_000,

                        "maxPostDataSize": 10_000_000,

                    }, session_id=new_session)

                    self.send("Runtime.enable", session_id=new_session)

                    self.send("Target.setAutoAttach", {

                        "autoAttach": True,

                        "waitForDebuggerOnStart": False,

                        "flatten": True,

                    }, session_id=new_session)

        elif method == "Network.requestWillBeSent":

            req_id = params["requestId"]

            req_url = params.get("request", {}).get("url", "")

            with self.lock:

                self.requests_data[req_id] = {

                    "requestId": req_id,

                    "session_id": session_id,

                    "timestamp": params.get("timestamp"),

                    "wallTime": params.get("wallTime"),

                    "type": params.get("type", "Other"),

                    "request": params.get("request", {}),

                    "initiator": params.get("initiator"),

                    "documentURL": params.get("documentURL"),

                    "frameId": params.get("frameId"),

                }

                self.stats["requests"] += 1

            method_str = params.get("request", {}).get("method", "GET")

            typ = params.get("type", "?")

            print(f"[REQ {typ:>10}] {method_str:6} {req_url[:100]}")

        elif method == "Network.responseReceived":

            req_id = params["requestId"]

            with self.lock:

                if req_id in self.requests_data:

                    self.requests_data[req_id]["response"] = params.get("response", {})

                    self.requests_data[req_id]["type"] = params.get("type", self.requests_data[req_id].get("type"))

                    self.stats["responses"] += 1

            status = params.get("response", {}).get("status", "?")

            url = params.get("response", {}).get("url", "")[:100]

            print(f"[RSP {status:>10}] {url}")

        elif method == "Network.loadingFinished":

            req_id = params["requestId"]

            with self.lock:

                if req_id in self.requests_data:

                    self.requests_data[req_id]["encodedDataLength"] = params.get("encodedDataLength")

                    sess = self.requests_data[req_id].get("session_id")

                else:

                    return

            # Corps déjà récupéré via Fetch (stade Response) → finaliser sans
            # re-tenter (Network.getResponseBody échouerait sur une navigation).
            if req_id in self.fetch_body_captured:

                self.fetch_body_captured.discard(req_id)

                with self.lock:

                    self._finalize(req_id)

                return

            body_msg_id = self.send("Network.getResponseBody",

                                    {"requestId": req_id},

                                    session_id=sess)

            self.pending_body_requests[body_msg_id] = req_id

        elif method == "Network.loadingFailed":

            req_id = params["requestId"]

            with self.lock:

                if req_id in self.requests_data:

                    self.requests_data[req_id]["failed"] = {

                        "errorText": params.get("errorText"),

                        "blockedReason": params.get("blockedReason"),

                    }

                    self._finalize(req_id)

        elif method == "Network.webSocketCreated":

            req_id = params["requestId"]

            with self.lock:

                self.requests_data[req_id] = {

                    "requestId": req_id,

                    "type": "WebSocket",

                    "url": params.get("url"),

                    "initiator": params.get("initiator"),

                    "ws_frames": [],

                }

            print(f"[WS    NEW   ] {params.get('url', '')[:100]}")

        elif method == "Network.webSocketWillSendHandshakeRequest":

            req_id = params["requestId"]

            with self.lock:

                entry = self.requests_data.get(req_id)

                if entry is not None:

                    entry["handshake_request"] = params.get("request", {})

        elif method == "Network.webSocketHandshakeResponseReceived":

            req_id = params["requestId"]

            resp = params.get("response", {})

            with self.lock:

                entry = self.requests_data.get(req_id)

                if entry is not None:

                    entry["handshake_response"] = resp

            print(f"[WS  HSHAKE ] status={resp.get('status', '?')} {resp.get('headersText', '')[:120]}")

        elif method in ("Network.webSocketFrameSent", "Network.webSocketFrameReceived"):

            req_id = params["requestId"]

            direction = "\u2192" if "Sent" in method else "\u2190"

            response = params.get("response", {})

            payload = response.get("payloadData", "")

            opcode = response.get("opcode")

            mask = response.get("mask")

            is_binary = opcode == 2

            with self.lock:

                if req_id in self.requests_data:

                    self.requests_data[req_id].setdefault("ws_frames", []).append({

                        "direction": "sent" if "Sent" in method else "received",

                        "timestamp": params.get("timestamp"),

                        "opcode": opcode,

                        "binary": is_binary,

                        "mask": mask,

                        "payloadData": payload,

                    })

                    self.stats["ws_frames"] += 1

            preview = "<binary>" if is_binary else str(payload)[:120]

            print(f"[WS    {direction}     ] op={opcode} {preview}")

        elif method == "Network.webSocketFrameError":

            req_id = params["requestId"]

            with self.lock:

                entry = self.requests_data.get(req_id)

                if entry is not None:

                    entry.setdefault("ws_errors", []).append({

                        "timestamp": params.get("timestamp"),

                        "errorMessage": params.get("errorMessage"),

                    })

            print(f"[WS    ERR  ] {params.get('errorMessage', '')[:120]}")

        elif method == "Network.webSocketClosed":

            req_id = params["requestId"]

            with self.lock:

                if req_id in self.requests_data:

                    self._finalize(req_id)

        elif method == "Network.eventSourceMessageReceived":

            req_id = params["requestId"]

            with self.lock:

                entry = self.requests_data.get(req_id)

                if entry is not None:

                    entry.setdefault("sse_messages", []).append({

                        "timestamp": params.get("timestamp"),

                        "eventName": params.get("eventName"),

                        "eventId": params.get("eventId"),

                        "data": params.get("data"),

                    })

            print(f"[SSE  MSG   ] {params.get('eventName', '?')} {str(params.get('data', ''))[:100]}")

        elif method == "Page.frameNavigated":

            frame = params.get("frame", {})

            print(f"[NAV       ] {frame.get('url', '')[:120]}")

        elif method == "Runtime.consoleAPICalled":

            args_text = " ".join(

                str(a.get("value", a.get("description", "")))

                for a in params.get("args", [])

            )

            level = params.get("type", "log")

            print(f"[CON  {level:>6}] {args_text[:500]}")

        elif method == "Runtime.exceptionThrown":

            exc = params.get("exceptionDetails", {})

            print(f"[JS ERROR  ] {exc.get('text', '')} {exc.get('exception', {}).get('description', '')}")

        elif method == "Runtime.bindingCalled" and params.get("name") == USER_EVENT_BINDING:

            payload_str = params.get("payload", "")

            try:

                payload = json.loads(payload_str)

            except Exception:

                payload = {"raw": payload_str}

            ev_type = payload.get("event", "?") if isinstance(payload, dict) else "?"

            if ev_type == "form_submit" and isinstance(payload, dict):

                print(f"[FORM SUBMIT] {payload_str[:2000]}")

                out_path = self.full_dir.parent / "form_submit_captured.json"

                safe_append(out_path, payload_str + "\n")

            tgt = payload.get("target", {}) if isinstance(payload, dict) else {}

            desc = tgt.get("tag", "?") if isinstance(tgt, dict) else "?"

            if isinstance(tgt, dict):

                if tgt.get("id"):

                    desc += "#" + tgt["id"]

                if tgt.get("text"):

                    desc += " \"" + str(tgt["text"])[:40] + "\""

            print(f"[USER {ev_type:>6}] {desc}")

            full_dir = self.events_full_dir or (self.full_dir.parent / "events" / "full")

            full_dir.mkdir(parents=True, exist_ok=True)

            safe_append(full_dir / "events.jsonl", json.dumps(payload, ensure_ascii=False) + "\n")

            summary_dir = self.events_summary_dir or (self.full_dir.parent / "events" / "summary")

            summary_dir.mkdir(parents=True, exist_ok=True)

            outer = tgt.get("outerHTML", "") if isinstance(tgt, dict) else ""

            slim = {

                "event": ev_type,

                "ts": payload.get("ts") if isinstance(payload, dict) else None,

                "url": payload.get("url") if isinstance(payload, dict) else None,

                "outerHTML": outer,

            }

            safe_append(summary_dir / "events.jsonl", json.dumps(slim, ensure_ascii=False) + "\n")

            safe_append(summary_dir / "events.html", f"<!-- {ev_type} @ {slim['ts']} {slim['url']} -->\n{outer}\n\n")

        elif method == "Network.responseReceivedExtraInfo":

            req_id = params.get("requestId")

            extra_headers = params.get("headers", {})

            set_cookies = {

                k: v for k, v in extra_headers.items()

                if k.lower() == "set-cookie"

            }

            if set_cookies or params.get("cookiePartitionKey"):

                with self.lock:

                    if req_id not in self.extra_info:

                        self.extra_info[req_id] = {}

                    self.extra_info[req_id]["response_set_cookie"] = set_cookies

                    self.extra_info[req_id]["extra_response_headers"] = extra_headers

                    if req_id in self.requests_data:

                        resp = self.requests_data[req_id].get("response", {})

                        existing = dict(resp.get("headers", {}))

                        existing.update(set_cookies)

                        resp["headers"] = existing

                        resp["_extraInfo_cookies"] = set_cookies

                cookie_names = list(set_cookies.keys())

                print(f"[COOKIE SET ] req={req_id[:12]} headers={cookie_names}")

        elif method == "Network.requestWillBeSentExtraInfo":

            req_id = params.get("requestId")

            extra_headers = params.get("headers", {})

            cookies_sent = {

                k: v for k, v in extra_headers.items()

                if k.lower() == "cookie"

            }

            if cookies_sent:

                with self.lock:

                    if req_id not in self.extra_info:

                        self.extra_info[req_id] = {}

                    self.extra_info[req_id]["request_cookie_header"] = cookies_sent

                    if req_id in self.requests_data:

                        req_h = self.requests_data[req_id].get("request", {}).get("headers", {})

                        req_h.update(cookies_sent)

        elif "id" in msg and msg["id"] in self.pending_fetch_bodies:

            network_id, fetch_req_id, sess = self.pending_fetch_bodies.pop(msg["id"])

            result = msg.get("result", {})

            body = result.get("body")

            with self.lock:

                target = self.requests_data.get(network_id)

                if target is not None and body is not None:

                    target["responseBody"] = body

                    target["responseBodyBase64"] = result.get("base64Encoded", False)

                    if network_id:

                        self.fetch_body_captured.add(network_id)

                    self.stats["bodies"] += 1

            # TOUJOURS relancer la réponse, sinon la page reste bloquée.
            try:

                self.send("Fetch.continueResponse", {"requestId": fetch_req_id}, session_id=sess)

            except Exception:

                pass

        elif "id" in msg and msg["id"] in self.pending_body_requests:

            req_id = self.pending_body_requests.pop(msg["id"])

            result = msg.get("result", {})

            with self.lock:

                if req_id in self.requests_data:

                    self.requests_data[req_id]["responseBody"] = result.get("body")

                    self.requests_data[req_id]["responseBodyBase64"] = result.get("base64Encoded", False)

                    if result.get("body"):

                        self.stats["bodies"] += 1

                    self._finalize(req_id)

        elif "id" in msg and msg["id"] in self.pending_cookie_dumps:

            label = self.pending_cookie_dumps.pop(msg["id"])

            cookies = msg.get("result", {}).get("cookies", [])

            out_path = self.full_dir.parent / f"cookies_{label}.json"

            with open(out_path, "w", encoding="utf-8") as f:

                json.dump(cookies, f, indent=2, ensure_ascii=False)

            self.stats["cookie_dumps"] += 1

            print(f"[COOKIE DUMP] {len(cookies)} cookies -> {out_path}")

    def _finalize(self, req_id):

        if req_id in self.requests_data:

            entry = self.requests_data.pop(req_id)

            extra = self.extra_info.pop(req_id, None)

            if extra:

                entry["_extra_info"] = extra

                set_cookies = extra.get("response_set_cookie")

                if set_cookies:

                    resp = entry.setdefault("response", {})

                    headers = dict(resp.get("headers", {}))

                    headers.update(set_cookies)

                    resp["headers"] = headers

                    resp["_extraInfo_cookies"] = set_cookies

                cookies_sent = extra.get("request_cookie_header")

                if cookies_sent:

                    req_h = entry.setdefault("request", {}).setdefault("headers", {})

                    req_h.update(cookies_sent)

            self._write_entry(entry)

    def _write_entry(self, entry):

        full_file = self.full_dir / "requests.jsonl"

        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"

        safe_append(full_file, line)

        if entry.get("type") in FILTERED_TYPES:

            filt_file = self.filtered_dir / "requests.jsonl"

            safe_append(filt_file, line)

    def loop(self):

        while self.running:

            if self.ws is None:

                break

            try:

                raw = self.ws.recv()

                if not raw:

                    continue

                msg = json.loads(raw)

                self.handle_message(msg)

            except websocket.WebSocketConnectionClosedException:

                if self.running:

                    print("[!] WebSocket fermée par Chrome.")

                break

            except Exception as e:

                if self.running:

                    err_str = str(e)

                    win_aborted = "10053" in err_str or "10054" in err_str or "WinError" in err_str

                    if win_aborted:

                        break

                    print(f"[!] Erreur loop : {e}")

    def write_summary(self):

        for label, directory in [("full", self.full_dir), ("filtered", self.filtered_dir)]:

            jsonl_path = directory / "requests.jsonl"

            if not jsonl_path.exists():

                continue

            entries = []

            with open(jsonl_path, encoding="utf-8") as f:

                for line in f:

                    try:

                        entries.append(json.loads(line))

                    except Exception:

                        pass

            summary_path = directory / "summary.txt"

            with open(summary_path, "w", encoding="utf-8") as f:

                f.write(f"=== Session {label} : {len(entries)} requêtes ===\n\n")

                for e in entries:

                    method = e.get("request", {}).get("method", "?")

                    url = e.get("request", {}).get("url") or e.get("url", "?")

                    status = e.get("response", {}).get("status", "—")

                    typ = e.get("type", "?")

                    has_body = "✓" if e.get("responseBody") else " "

                    f.write(f"[{has_body}] [{typ:>10}] {method:6} {status} {url}\n")

            print(f"[+] {label}: {len(entries)} requêtes -> {summary_path}")

    def stop(self):

        self.running = False

        if self.ws is None:

            return

        try:

            self.ws.close()

        except Exception:

            pass

def main():

    ap = argparse.ArgumentParser(
        description="Chrome Network Logger — CDP stealth capture",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument(
        "--proxy",
        metavar="N|random|none",
        default=None,
        help=(
            "Proxy selection:\n"
            "  --proxy random   pick one at random (default when proxy.txt has entries)\n"
            "  --proxy none     disable proxy even if proxy.txt exists\n"
            "  --proxy 2        use proxy #2 from proxy.txt\n"
            "  (omit flag)      random if silent, or prompt with --proxy-prompt"
        ),
    )
    ap.add_argument(
        "--proxy-prompt",
        action="store_true",
        help="Prompt interactively to choose a proxy from proxy.txt",
    )
    ap.add_argument(
        "--proxy-file",
        metavar="FILE",
        default=PROXY_FILE,
        help=f"Path to proxy list file (default: {PROXY_FILE})",
    )
    cli = ap.parse_args()

    proxy_cli_index = None
    if cli.proxy is not None:
        raw = cli.proxy.strip().lower()
        if raw == "random":
            proxy_cli_index = "random"
        elif raw == "none":
            proxy_cli_index = "none"
        else:
            try:
                proxy_cli_index = int(raw)
            except ValueError:
                ap.error(f"--proxy doit être un entier, 'random' ou 'none' (reçu: {cli.proxy!r})")

    print("=" * 70)

    print("  Chrome Network Logger v2 - CDP direct (stealth)")

    print("=" * 70)

    chrome_path = find_chrome()

    print(f"[+] Chrome : {chrome_path}")

    profile_dir = Path(DEDICATED_PROFILE_DIR)

    profile_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Profil dédié : {profile_dir.absolute()}")

    is_first_run = not (profile_dir / "Default").exists()

    if is_first_run:

        print()

        print("=" * 70)

        print("  PREMIÈRE UTILISATION DÉTECTÉE")

        print("=" * 70)

        print("  Ce profil est vide. Chrome va s'ouvrir, et tu vas devoir :")

        print("    1. Te logger sur le site cible")

        print("    2. Faire toutes tes configurations (cookies, etc.)")

        print("    3. Naviguer pour générer du trafic")

        print("    4. Ctrl+C ici pour sauvegarder")

        print()

        print("  Aux prochains lancements, ton profil sera réutilisé tel quel.")

        print("=" * 70)

        input("  Entrée pour continuer...")

    kill_orphan_chromes_using_profile(profile_dir)

    cleanup_locks(profile_dir)

    session_parent = prompt_session_subfolder()

    base, full_dir, filtered_dir, events_dirs = setup_session_dirs(session_parent)

    print(f"[+] Logs : {base.absolute()}")

    readme = base / "README.txt"

    readme.write_text(

        "Chrome Network Logger - Session capture\n"

        "========================================\n\n"

        "Arborescence :\n"

        "  full/requests.jsonl        Toutes les requ\u00eates r\u00e9seau (CSS, fonts, images, XHR, WS...)\n"

        "  full/summary.txt           R\u00e9sum\u00e9 lisible (m\u00e9thode/status/url)\n"

        "  filtered/requests.jsonl    Uniquement XHR/Fetch/Document/WebSocket/EventSource\n"

        "  filtered/summary.txt       R\u00e9sum\u00e9 lisible filtr\u00e9\n"

        "  events/full/events.jsonl   Toutes les interactions utilisateur (clics, change, input,\n"

        "                             keydown sp\u00e9ciales, paste/copy, focus, popstate, beforeunload)\n"

        "                             AVEC d\u00e9tails complets (cssPath, xpath, attrs, outerHTML, value)\n"

        "  events/summary/events.jsonl  M\u00eames \u00e9v\u00e9nements, version all\u00e9g\u00e9e (event/ts/url/outerHTML)\n"

        "  events/summary/events.html   Vue HTML lisible (un bloc par event)\n"

        "  form_submit_captured.json  Formulaires soumis (FormData s\u00e9rialis\u00e9e: email, mdp, etc.)\n"

        "  cookies_<label>.json       Dump de tous les cookies (auto post-login + manuel)\n\n"

        "Note : les champs `value` des inputs (y compris password) sont captur\u00e9s tels quels,\n"

        "ainsi que tout texte coll\u00e9 (paste). Conserve ces logs en lieu s\u00fbr.\n",

        encoding="utf-8",

    )

    print(f"[+] README \u00e9crit : {readme}")

    debug_port = find_free_port(9222)

    print(f"[+] Port debug : {debug_port}")

    args = [

        chrome_path,

        f"--remote-debugging-port={debug_port}",

        f"--user-data-dir={profile_dir}",

        "--remote-allow-origins=*",

        "--no-first-run",

        "--no-default-browser-check",

        "--disable-features=ChromeWhatsNewUI",

    ]

    proxies = load_all_proxies(cli.proxy_file)
    proxy = select_proxy(proxies, cli_index=proxy_cli_index, prompt=cli.proxy_prompt)
    if proxy:
        print(f"[+] Proxy utilisé : {_proxy_label(proxy)}")
        args.extend(build_proxy_chrome_args(proxy))
    else:
        if proxies:
            print("[+] Proxy désactivé (--proxy none)")
        else:
            print(f"[+] Aucun proxy ({cli.proxy_file} absent ou vide)")

    print("[+] Lancement Chrome (détaché)...")

    proc = subprocess.Popen(

        args,

        creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,

        close_fds=True,

    )

    print(f"[+] Attente port {debug_port}...")

    time.sleep(2)

    connected = False

    for attempt in range(1, 40):

        if proc.poll() is not None:

            print(f"[!] Chrome s'est fermé (code {proc.poll()})")

            sys.exit(1)

        try:

            r = urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/version", timeout=2)

            if r.status == 200:

                version = json.loads(r.read())

                print(f"[+] Connecté à : {version.get('Browser', '?')} (après {attempt}s)")

                connected = True

                break

        except Exception:

            pass

        time.sleep(1)

    if not connected:

        print("[!] Échec connexion port debug. Diagnostic :")

        netstat = subprocess.run(

            f'netstat -an | findstr :{debug_port}',

            shell=True, capture_output=True, text=True

        )

        print(f"    netstat:\n{netstat.stdout or '    (rien)'}")

        print(f"    Chrome PID : {proc.pid}, alive : {proc.poll() is None}")

        try:

            proc.kill()

        except Exception:

            pass

        sys.exit(1)

    capture = CDPCapture(full_dir, filtered_dir, debug_port, events_dirs=events_dirs)

    if not capture.connect():

        print("[!] Connexion capture KO")

        sys.exit(1)

    print()

    print("=" * 70)

    print("  CAPTURE ACTIVE - Navigue dans la fenêtre Chrome")

    print("  Ctrl+C ici pour arrêter et sauvegarder")

    print("=" * 70)

    print()

    cap_thread = threading.Thread(target=capture.loop, daemon=True)

    cap_thread.start()

    _kb_stop = threading.Event()
    if _active_relays:
        _relay = _active_relays[0]
        toggle_log = base / "proxy_toggles.jsonl"
        _start_proxy_keyboard_thread(_relay, toggle_log, _kb_stop)
        print("[+] Proxy toggle actif — appuie sur [P] pour activer/désactiver le proxy en live")
        print()

    def shutdown(*_):

        print("\n[+] Arrêt...")

        capture.stop()

        capture.write_summary()

        print(f"[+] Stats : {capture.stats}")

        print(f"[+] Logs : {base.absolute()}")

        try:

            pass

        except Exception:

            pass

        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)

    signal.signal(signal.SIGTERM, shutdown)

    last_stats = dict(capture.stats)

    try:

        while True:

            time.sleep(10)

            if proc.poll() is not None:

                print("[!] Chrome fermé.")

                shutdown()

            cur = dict(capture.stats)

            delta = {k: cur[k] - last_stats[k] for k in cur}

            if any(delta.values()):

                print(f"[STATS +10s] req:+{delta['requests']} resp:+{delta['responses']} bodies:+{delta['bodies']} ws:+{delta['ws_frames']}")

            last_stats = cur

    except KeyboardInterrupt:

        shutdown()

if __name__ == "__main__":

    main()
