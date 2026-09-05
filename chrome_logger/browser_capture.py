from __future__ import annotations

import copy
import json
import time
from typing import Any

from .constants import PAGE_TYPES
from .models import PendingCommand


class BrowserCaptureMixin:
    def _user_event(self, session_id: str | None, params: dict[str, Any]) -> None:
        payload_text = str(params.get("payload") or "")
        payload_size = len(payload_text.encode("utf-8", errors="replace"))
        if payload_size > self.config.max_interaction_payload_bytes:
            self.stats["droppedUserEvents"] += 1
            self.store.add_warning(
                f"Dropped an oversized interaction payload ({payload_size} bytes; "
                f"limit {self.config.max_interaction_payload_bytes})"
            )
            return
        context_id = params.get("executionContextId")
        if context_id is not None:
            with self.state_lock:
                allowed = int(context_id) in self.interaction_contexts.get(session_id or "", set())
            if not allowed:
                self.stats["droppedUserEvents"] += 1
                return
        try:
            payload = json.loads(payload_text)
        except Exception:
            payload = {"event": "invalid_payload", "raw": payload_text}
        if not isinstance(payload, dict):
            payload = {"event": "unknown", "value": payload}
        payload["sessionId"] = session_id
        payload["executionContextId"] = context_id
        payload["targetContext"] = self._target(session_id)
        timestamp = self.timestamps.from_epoch_ms(payload.get("ts"))
        payload["time"] = timestamp
        clean = self.store.redactor.interaction(payload)
        event_name = str(clean.get("event") or "unknown")
        relative = "interactions/forms.jsonl" if event_name == "form_submit" else "interactions/events.jsonl"
        self.stats["userEvents"] += 1
        self.store.write_jsonl(relative, clean, redact=False)
        self.store.timeline("user_event", timestamp, sessionId=session_id, event=event_name, target=clean.get("target"))

    def _console_event(self, session_id: str | None, params: dict[str, Any]) -> None:
        values = []
        for item in params.get("args") or []:
            values.append(item.get("value", item.get("unserializableValue", item.get("description"))))
        event = {
            "sessionId": session_id,
            "target": self._target(session_id),
            "time": self.timestamps.from_epoch_ms(params.get("timestamp")),
            "level": params.get("type"),
            "values": values,
            "args": copy.deepcopy(params.get("args") or []),
            "stackTrace": copy.deepcopy(params.get("stackTrace")),
            "executionContextId": params.get("executionContextId"),
        }
        self.store.write_jsonl("browser/console.jsonl", event, redact=True)

    def _exception_event(self, session_id: str | None, params: dict[str, Any]) -> None:
        details = copy.deepcopy(params.get("exceptionDetails") or {})
        event = {
            "sessionId": session_id,
            "target": self._target(session_id),
            "time": self.timestamps.from_epoch_ms(params.get("timestamp")),
            "details": details,
        }
        self.store.write_jsonl("browser/exceptions.jsonl", event, redact=True)

    def _log_entry(self, session_id: str | None, params: dict[str, Any]) -> None:
        entry = copy.deepcopy(params.get("entry") or {})
        event = {
            "sessionId": session_id,
            "target": self._target(session_id),
            "time": self.timestamps.from_epoch_ms(entry.get("timestamp")),
            "entry": entry,
        }
        self.store.write_jsonl("browser/log.jsonl", event, redact=True)

    def _navigation_event(self, session_id: str | None, event_name: str, params: dict[str, Any]) -> None:
        timestamp = self.timestamps.normalize(params.get("timestamp"))
        event = {
            "event": event_name,
            "sessionId": session_id,
            "target": self._target(session_id),
            "time": timestamp,
            "params": copy.deepcopy(params),
        }
        self.store.write_jsonl("browser/navigations.jsonl", event, redact=True)
        self.store.timeline("navigation", timestamp, event=event_name, sessionId=session_id, params=params)
        if event_name == "frameNavigated":
            self.request_cookie_sync("frameNavigated")

    def snapshot(
        self,
        label: str,
        *,
        sessions: list[str] | None = None,
        include_cookies: bool = True,
    ) -> None:
        if not self.config.capture_storage:
            return
        if include_cookies:
            with self.state_lock:
                self._snapshot_pending += 1
            self.send(
                "Storage.getCookies",
                {},
                pending=PendingCommand("snapshot_cookies", {"label": label}, time.monotonic()),
            )
        expression = """(() => {
            const dump = (name, storageFactory) => {
                try {
                    const storage = storageFactory();
                    const output = {};
                    for (let i = 0; i < storage.length; i++) {
                        const key = storage.key(i);
                        output[key] = storage.getItem(key);
                    }
                    return {ok: true, values: output};
                } catch (error) {
                    return {ok: false, error: String(error), name};
                }
            };
            return {
                url: location.href,
                origin: location.origin,
                localStorage: dump('localStorage', () => window.localStorage),
                sessionStorage: dump('sessionStorage', () => window.sessionStorage)
            };
        })()"""
        if sessions is None:
            with self.state_lock:
                sessions = [sid for sid, info in self.targets.items() if info.get("type") in PAGE_TYPES]
        for session_id in sessions:
            with self.state_lock:
                self._snapshot_pending += 1
            self.send(
                "Runtime.evaluate",
                {"expression": expression, "returnByValue": True},
                session_id,
                PendingCommand(
                    "snapshot_storage",
                    {"label": label, "sessionId": session_id, "target": self._target(session_id)},
                    time.monotonic(),
                ),
            )

    def _handle_snapshot_response(
        self,
        kind: str,
        data: dict[str, Any],
        error: Any,
        result: dict[str, Any],
    ) -> None:
        try:
            label = str(data.get("label") or "snapshot")
            if kind == "snapshot_cookies":
                payload: dict[str, Any] = {"time": self.timestamps.normalize(), "label": label}
                if error:
                    payload["error"] = error
                else:
                    payload["cookies"] = result.get("cookies") or []
                    # Keep the event-sourced jar aligned with explicit snapshots.
                    self._handle_cookie_sync({"reasons": [f"snapshot:{label}"]}, None, result)
                self.store.write_json(f"snapshots/cookies_{label}.json", payload, redact=True)
            else:
                payload = {
                    "time": self.timestamps.normalize(),
                    "label": label,
                    "sessionId": data.get("sessionId"),
                    "target": data.get("target"),
                }
                exception_details = result.get("exceptionDetails")
                if error:
                    payload["error"] = error
                elif exception_details:
                    payload["error"] = exception_details
                else:
                    remote = result.get("result") or {}
                    payload["storage"] = remote.get("value")
                    if remote.get("subtype") == "error":
                        payload["error"] = remote.get("description")
                    dump = remote.get("value")
                    if isinstance(dump, dict):
                        self.seed_dom_storage(str(dump.get("origin") or ""), dump, f"dump:{label}")
                self.store.write_jsonl(f"snapshots/storage_{label}.jsonl", payload, redact=True)
        finally:
            with self._snapshot_condition:
                self._snapshot_pending = max(0, self._snapshot_pending - 1)
                self._snapshot_condition.notify_all()

    def wait_for_snapshots(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._snapshot_condition:
            while self._snapshot_pending > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._snapshot_condition.wait(timeout=remaining)
        return True

    def _interaction_script(self) -> str:
        template = r"""
(() => {
  const BINDING = __BINDING__;
  const MARKER = __MARKER__;
  const SAFE = __SAFE__;
  const CAPTURE_CLIPBOARD = __CLIPBOARD__;
  if (window[MARKER]) return;
  const send = window[BINDING];
  if (typeof send !== 'function') return;

  const controller = new AbortController();
  Object.defineProperty(window, MARKER, {
    value: {abort: () => controller.abort()}, enumerable: false, configurable: true
  });
  const listenerOptions = {capture: true, signal: controller.signal};
  const sensitiveToken = /(?:^|[^a-z0-9])(?:password|passwd|pwd|secret|token|api.?key|authorization|cookie|session|credential|assertion|otp|pin|cvv|cvc|credit.?card|card.?number|cc)(?:$|[^a-z0-9])/i;
  const sensitiveFragments = [
    'password', 'passwd', 'clientsecret', 'apikey', 'accesstoken', 'refreshtoken',
    'idtoken', 'sessiontoken', 'sessionsecret', 'sessioncookie', 'csrf', 'xsrf',
    'credential', 'assertion', 'cardnumber', 'creditcard', 'authcode'
  ];
  const looksSensitive = (value) => {
    const text = String(value || '');
    const normalized = text.toLowerCase().replace(/[^a-z0-9]/g, '');
    return sensitiveToken.test(text) || sensitiveFragments.some((part) => normalized.includes(part));
  };
  const redact = (value) => `<redacted len=${String(value ?? '').length} source=browser>`;

  const cssPath = (el) => {
    if (!(el instanceof Element)) return '';
    const path = [];
    while (el && el.nodeType === 1 && path.length < 12) {
      let selector = el.nodeName.toLowerCase();
      if (el.id) { selector += '#' + CSS.escape(el.id); path.unshift(selector); break; }
      let sibling = el, index = 1;
      while ((sibling = sibling.previousElementSibling)) {
        if (sibling.nodeName === el.nodeName) index++;
      }
      selector += `:nth-of-type(${index})`;
      path.unshift(selector);
      el = el.parentElement;
    }
    return path.join(' > ');
  };

  const xpath = (el) => {
    if (!(el instanceof Element)) return '';
    if (el.id) return `//*[@id="${el.id.replace(/"/g, '&quot;')}"]`;
    const parts = [];
    while (el && el.nodeType === 1) {
      let index = 1, sibling = el.previousSibling;
      while (sibling) {
        if (sibling.nodeType === 1 && sibling.nodeName === el.nodeName) index++;
        sibling = sibling.previousSibling;
      }
      parts.unshift(`${el.nodeName.toLowerCase()}[${index}]`);
      el = el.parentElement;
    }
    return '/' + parts.join('/');
  };

  const descriptor = (el) => `${el.type || ''} ${el.name || ''} ${el.id || ''} ${el.autocomplete || ''} ${el.placeholder || ''}`;
  const isSensitiveElement = (el) => String(el.type || '').toLowerCase() === 'password' || looksSensitive(descriptor(el));
  const isFormControl = (el) => el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement;
  const valueOf = (el) => {
    if (!('value' in el)) return null;
    const value = String(el.value ?? '').slice(0, 5000);
    return SAFE && (isSensitiveElement(el) || isFormControl(el)) ? redact(value) : value;
  };

  const describe = (el) => {
    if (!(el instanceof Element)) return null;
    const rect = el.getBoundingClientRect();
    const attrs = {};
    for (const attr of Array.from(el.attributes).slice(0, 100)) {
      const name = String(attr.name || '').toLowerCase();
      const value = String(attr.value).slice(0, 1000);
      attrs[attr.name] = SAFE && (name === 'value' || name === 'srcdoc' || looksSensitive(name)) ? redact(value) : value;
    }
    const sensitiveElement = isSensitiveElement(el);
    let outerHTML = '';
    if (SAFE) {
      outerHTML = `<${el.tagName.toLowerCase()} data-capture-redacted="true">`;
    } else {
      try { outerHTML = String(el.outerHTML || '').slice(0, 8000); } catch (_) {}
    }
    return {
      tag: el.tagName.toLowerCase(), id: el.id || null,
      classes: typeof el.className === 'string' ? el.className : null,
      name: el.getAttribute('name'), type: el.getAttribute('type'), role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'), placeholder: el.getAttribute('placeholder'),
      autocomplete: el.getAttribute('autocomplete'), value: valueOf(el),
      checked: ('checked' in el) ? Boolean(el.checked) : null,
      text: SAFE && (sensitiveElement || isFormControl(el)) ? '' : String(el.innerText || el.textContent || '').trim().slice(0, 500),
      href: el.getAttribute('href'), attrs,
      rect: {x: rect.x, y: rect.y, width: rect.width, height: rect.height},
      cssPath: cssPath(el), xpath: xpath(el), outerHTML
    };
  };

  const emit = (payload) => { try { send(JSON.stringify(payload)); } catch (_) {} };
  const base = (event, target) => ({event, ts: Date.now(), url: location.href, target: describe(target)});
  document.addEventListener('click', (e) => emit({...base('click', e.target), button: e.button, x: e.clientX, y: e.clientY}), listenerOptions);
  document.addEventListener('change', (e) => emit(base('change', e.target)), listenerOptions);
  const timers = new WeakMap();
  document.addEventListener('input', (e) => {
    if (!(e.target instanceof Element)) return;
    clearTimeout(timers.get(e.target));
    timers.set(e.target, setTimeout(() => emit(base('input', e.target)), 300));
  }, listenerOptions);
  document.addEventListener('keydown', (e) => {
    const key = e.key || '';
    if (key.length <= 1 && !e.ctrlKey && !e.metaKey && !e.altKey) return;
    emit({...base('keydown', e.target), key, code: e.code, ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey});
  }, listenerOptions);
  document.addEventListener('focusin', (e) => emit(base('focus', e.target)), listenerOptions);
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const data = {};
    try {
      new FormData(form).forEach((value, key) => {
        const normalized = value instanceof File
          ? {name: SAFE ? redact(value.name) : value.name, size: value.size, type: value.type}
          : String(value).slice(0, 10000);
        const clean = SAFE && !(value instanceof File) ? redact(normalized) : normalized;
        if (Object.prototype.hasOwnProperty.call(data, key)) {
          data[key] = Array.isArray(data[key]) ? [...data[key], clean] : [data[key], clean];
        } else {
          data[key] = clean;
        }
      });
    } catch (error) { data.__error = String(error); }
    emit({...base('form_submit', form), action: form.action, method: form.method, data});
  }, listenerOptions);
  if (CAPTURE_CLIPBOARD) {
    document.addEventListener('paste', (e) => {
      let text = '';
      try { text = (e.clipboardData || window.clipboardData).getData('text') || ''; } catch (_) {}
      emit({...base('paste', e.target), data: SAFE ? redact(text) : text.slice(0, 10000)});
    }, listenerOptions);
  }
  const dumpStorage = (factory) => {
    try {
      const storage = factory();
      const values = {};
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        values[key] = storage.getItem(key);
      }
      return {ok: true, values};
    } catch (error) {
      return {ok: false, error: String(error)};
    }
  };
  const cookieState = () => {
    let raw = '';
    try { raw = String(document.cookie || ''); } catch (_) { return null; }
    if (!SAFE) return raw;
    const names = raw.split(';').map((part) => part.split('=')[0].trim()).filter(Boolean);
    return {names, count: names.length, length: raw.length};
  };
  // Last chance to read a page that is being closed, hidden, or frozen: the
  // renderer dies with the window, so the dump travels with this message
  // instead of needing a round trip.
  let lastFlush = 0;
  const flushState = (trigger) => {
    const now = Date.now();
    if (trigger === 'hidden' && now - lastFlush < 500) return;
    lastFlush = now;
    emit({
      event: 'storage_state', ts: now, trigger, url: location.href, origin: location.origin,
      localStorage: dumpStorage(() => window.localStorage),
      sessionStorage: dumpStorage(() => window.sessionStorage),
      cookie: cookieState()
    });
  };
  window.addEventListener('pagehide', () => flushState('pagehide'), listenerOptions);
  window.addEventListener('freeze', () => flushState('freeze'), listenerOptions);
  window.addEventListener('unload', () => flushState('unload'), listenerOptions);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flushState('hidden');
  }, listenerOptions);
  window.addEventListener('popstate', () => emit({event: 'popstate', ts: Date.now(), url: location.href}), listenerOptions);
  window.addEventListener('hashchange', (e) => emit({event: 'hashchange', ts: Date.now(), url: location.href, oldURL: e.oldURL, newURL: e.newURL}), listenerOptions);
  window.addEventListener('beforeunload', () => {
    emit({event: 'beforeunload', ts: Date.now(), url: location.href});
    flushState('beforeunload');
  }, listenerOptions);
})();
"""
        return (
            template.replace("__BINDING__", json.dumps(self.binding_name))
            .replace("__MARKER__", json.dumps(self.install_marker))
            .replace("__SAFE__", "true" if self.config.sensitive_mode == "safe" else "false")
            .replace("__CLIPBOARD__", "true" if self.config.capture_clipboard else "false")
        )
