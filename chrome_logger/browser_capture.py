from __future__ import annotations

import copy
import json
import time
from typing import Any

from .client_storage import storage_origin
from .constants import PAGE_TYPES
from .labels import TIMELINE_CONSOLE_LEVELS, console_text, interaction_label, short_text
from .models import PendingCommand


class BrowserCaptureMixin:
    def _user_event(self, session_id: str | None, params: dict[str, Any]) -> None:
        payload_text = str(params.get("payload") or "")
        payload_size = len(payload_text.encode("utf-8", errors="replace"))
        if payload_size > self.config.max_interaction_payload_bytes:
            self.stats["droppedUserEvents"] += 1
            # One stable message: the count lives in stats.droppedUserEvents.
            self.store.add_warning(
                "Dropped oversized interaction payloads "
                f"(limit {self.config.max_interaction_payload_bytes} bytes; see stats.droppedUserEvents)"
            )
            return
        context_id = params.get("executionContextId")
        frame_id = None
        if context_id is not None:
            with self.state_lock:
                allowed = int(context_id) in self.interaction_contexts.get(session_id or "", set())
                context = self.interaction_context_origins.get(session_id or "", {}).get(int(context_id)) or {}
                frame_id = context.get("frameId")
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
        # Joins the event to requests.jsonl, whose records carry frameId too.
        payload["frameId"] = frame_id
        payload["executionContextId"] = context_id
        payload["targetContext"] = self._target(session_id)
        timestamp = self.timestamps.from_epoch_ms(payload.get("ts"))
        payload["time"] = timestamp
        clean = self.store.redactor.interaction(payload)
        event_name = str(clean.get("event") or "unknown")
        relative = "interactions/forms.jsonl" if event_name == "form_submit" else "interactions/events.jsonl"
        self.stats["userEvents"] += 1
        self.store.write_jsonl(relative, clean, redact=False)
        self.store.timeline(
            "user_event",
            timestamp,
            sessionId=session_id,
            event=event_name,
            label=interaction_label(clean),
            target=clean.get("target"),
        )

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
        if event["level"] in TIMELINE_CONSOLE_LEVELS:
            # Errors and warnings belong next to the requests and clicks that
            # caused them; debug chatter stays in console.jsonl only.
            self.store.timeline(
                "console",
                event["time"],
                sessionId=session_id,
                level=event["level"],
                # Redact the whole text first: shortening joins lines and cuts
                # tokens, which hides them from line- and token-based patterns.
                text=short_text(self.store.redactor.text(" ".join(console_text(value) for value in values))),
            )

    def _exception_event(self, session_id: str | None, params: dict[str, Any]) -> None:
        details = copy.deepcopy(params.get("exceptionDetails") or {})
        event = {
            "sessionId": session_id,
            "target": self._target(session_id),
            "time": self.timestamps.from_epoch_ms(params.get("timestamp")),
            "details": details,
        }
        self.store.write_jsonl("browser/exceptions.jsonl", event, redact=True)
        exception = details.get("exception") or {}
        self.store.timeline(
            "exception",
            event["time"],
            sessionId=session_id,
            text=short_text(
                self.store.redactor.text(
                    str(exception.get("description") or details.get("text") or "Uncaught exception")
                )
            ),
            url=details.get("url"),
            lineNumber=details.get("lineNumber"),
        )

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
        if sessions is None:
            with self.state_lock:
                sessions = [sid for sid, info in self.targets.items() if info.get("type") in PAGE_TYPES]
        for session_id in sessions:
            with self.state_lock:
                info = copy.deepcopy(self.targets.get(session_id) or {})
            origin = storage_origin(info.get("url"))
            if not origin:
                # about:blank, chrome:// and similar pages have no Web Storage.
                continue
            with self.state_lock:
                self._storage_snapshot_group_id += 1
                group_id = self._storage_snapshot_group_id
                self._storage_snapshot_groups[group_id] = {
                    "label": label,
                    "sessionId": session_id,
                    "target": self._target(session_id),
                    "url": info.get("url"),
                    "origin": origin,
                    "remaining": 2,
                    "sections": {},
                }
            for part in ("localStorage", "sessionStorage"):
                self._send_storage_read(group_id, session_id, origin, part, use_storage_key=False)

    def _send_storage_read(
        self,
        group_id: int,
        session_id: str,
        origin: str,
        part: str,
        *,
        use_storage_key: bool,
    ) -> None:
        """Read one Web Storage area through CDP, without running page JavaScript."""
        is_local = part == "localStorage"
        storage_id: dict[str, Any] = (
            {"storageKey": origin + "/", "isLocalStorage": is_local}
            if use_storage_key
            else {"securityOrigin": origin, "isLocalStorage": is_local}
        )
        with self.state_lock:
            self._snapshot_pending += 1
        self.send(
            "DOMStorage.getDOMStorageItems",
            {"storageId": storage_id},
            session_id,
            PendingCommand(
                "snapshot_storage",
                {
                    "group": group_id,
                    "part": part,
                    "origin": origin,
                    "sessionId": session_id,
                    "storageKey": use_storage_key,
                },
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
            if kind == "snapshot_cookies":
                label = str(data.get("label") or "snapshot")
                payload: dict[str, Any] = {"time": self.timestamps.normalize(), "label": label}
                if error:
                    payload["error"] = error
                else:
                    payload["cookies"] = result.get("cookies") or []
                    # Keep the event-sourced jar aligned with explicit snapshots.
                    self._handle_cookie_sync({"reasons": [f"snapshot:{label}"]}, None, result)
                self.store.write_json(f"snapshots/cookies_{label}.json", payload, redact=True)
                return
            self._storage_read_response(data, error, result)
        finally:
            with self._snapshot_condition:
                self._snapshot_pending = max(0, self._snapshot_pending - 1)
                self._snapshot_condition.notify_all()

    def _storage_read_response(self, data: dict[str, Any], error: Any, result: dict[str, Any]) -> None:
        group_id = data.get("group")
        part = str(data.get("part") or "")
        if error and not data.get("storageKey") and self.is_live():
            # securityOrigin is deprecated; retry once with the storageKey form.
            with self.state_lock:
                still_open = group_id in self._storage_snapshot_groups
            if still_open:
                self._send_storage_read(
                    int(group_id),
                    str(data.get("sessionId") or ""),
                    str(data.get("origin") or ""),
                    part,
                    use_storage_key=True,
                )
                return
        if error:
            section: dict[str, Any] = {"ok": False, "error": error}
        else:
            values: dict[str, Any] = {}
            for item in result.get("entries") or []:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    values[str(item[0])] = item[1]
            section = {"ok": True, "values": values}
        with self.state_lock:
            group = self._storage_snapshot_groups.get(group_id)
            if group is None:
                return
            group["sections"][part] = section
            group["remaining"] -= 1
            if group["remaining"] > 0:
                return
            self._storage_snapshot_groups.pop(group_id, None)
        storage = {
            "url": group.get("url"),
            "origin": group.get("origin"),
            "localStorage": group["sections"].get("localStorage"),
            "sessionStorage": group["sections"].get("sessionStorage"),
        }
        label = str(group.get("label") or "snapshot")
        payload = {
            "time": self.timestamps.normalize(),
            "label": label,
            "sessionId": group.get("sessionId"),
            "target": group.get("target"),
            "source": "DOMStorage.getDOMStorageItems",
            "storage": storage,
        }
        errors = [section.get("error") for section in group["sections"].values() if not section.get("ok")]
        if errors:
            payload["error"] = errors[0] if len(errors) == 1 else errors
        self.seed_dom_storage(str(group.get("origin") or ""), storage, f"dump:{label}", group.get("sessionId"))
        self.store.write_jsonl(f"snapshots/storage_{label}.jsonl", payload, redact=True)

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

  // Bounded reads: an event on <body> or a large container must not
  // serialize the whole page (innerText forces layout, outerHTML copies it).
  const SKIP_TEXT = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE']);
  const textOf = (el) => {
    let out = '';
    try {
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, {
        acceptNode: (node) => (node.parentElement && SKIP_TEXT.has(node.parentElement.tagName)
          ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT)
      });
      let node;
      while ((node = walker.nextNode()) && out.length < 600) out += node.nodeValue + ' ';
    } catch (_) {}
    return out.replace(/\s+/g, ' ').trim().slice(0, 500);
  };
  const isLarge = (el) => el === document.body || el === document.documentElement
    || el.getElementsByTagName('*').length > 200;
  const testIdOf = (el) => {
    for (const name of ['data-testid', 'data-test-id', 'data-test', 'data-cy', 'data-qa']) {
      const value = el.getAttribute(name);
      if (value) return value.slice(0, 200);
    }
    return null;
  };
  const labelOf = (el) => {
    try {
      const labels = el.labels ? Array.from(el.labels) : [];
      const ids = String(el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
      const parts = [...labels.map(textOf), ...ids.map((id) => {
        const node = document.getElementById(id);
        return node ? textOf(node) : '';
      })].filter(Boolean);
      return parts.length ? parts.join(' ').slice(0, 200) : null;
    } catch (_) { return null; }
  };

  const escapeAttr = (value) => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  const openingTag = (el, attrs) => {
    const tag = el.tagName.toLowerCase();
    const parts = Object.entries(attrs).map(([name, value]) => `${name}="${escapeAttr(value)}"`);
    return `<${[tag, ...parts].join(' ')}>`;
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
    const large = isLarge(el);
    let outerHTML = '';
    if (SAFE) {
      outerHTML = `<${el.tagName.toLowerCase()} data-capture-redacted="true">`;
    } else {
      try {
        // A large element keeps only its own tag: its subtree would be huge.
        outerHTML = large ? openingTag(el, attrs) + '<!-- children omitted -->'
          : String(el.outerHTML || '').slice(0, 8000);
      } catch (_) {}
    }
    const typedText = isFormControl(el) || el.isContentEditable;
    return {
      tag: el.tagName.toLowerCase(), id: el.id || null,
      classes: typeof el.className === 'string' ? el.className : null,
      name: el.getAttribute('name'), type: el.getAttribute('type'), role: el.getAttribute('role'),
      ariaLabel: el.getAttribute('aria-label'), placeholder: el.getAttribute('placeholder'),
      autocomplete: el.getAttribute('autocomplete'), value: valueOf(el),
      checked: ('checked' in el) ? Boolean(el.checked) : null,
      // Typed text (form controls, contenteditable editors) is a value.
      text: SAFE && (sensitiveElement || typedText) ? '' : textOf(el),
      testId: testIdOf(el), label: labelOf(el),
      href: el.getAttribute('href'), attrs,
      rect: {x: rect.x, y: rect.y, width: rect.width, height: rect.height},
      cssPath: cssPath(el), xpath: xpath(el), outerHTML
    };
  };

  const emit = (payload) => { try { send(JSON.stringify(payload)); } catch (_) {} };
  // isTrusted is false for events a script dispatched (element.click()).
  const base = (event, target, e) => ({
    event, ts: Date.now(), url: location.href, trusted: e ? e.isTrusted : null, target: describe(target)
  });
  document.addEventListener('click', (e) => emit({...base('click', e.target, e), button: e.button, x: e.clientX, y: e.clientY}), listenerOptions);
  document.addEventListener('change', (e) => emit(base('change', e.target, e)), listenerOptions);
  const timers = new WeakMap();
  document.addEventListener('input', (e) => {
    if (!(e.target instanceof Element)) return;
    clearTimeout(timers.get(e.target));
    timers.set(e.target, setTimeout(() => emit(base('input', e.target, e)), 300));
  }, listenerOptions);
  document.addEventListener('keydown', (e) => {
    const key = e.key || '';
    if (e.repeat || e.isComposing || key === 'Process' || key === 'Dead') return;
    // AltGr reports Ctrl+Alt on Windows: AltGr+2 is "@" typed, not a shortcut.
    const altGraph = typeof e.getModifierState === 'function' && e.getModifierState('AltGraph');
    if (key.length <= 1 && (altGraph || (!e.ctrlKey && !e.metaKey))) return;
    emit({...base('keydown', e.target, e), key, code: e.code, ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey});
  }, listenerOptions);
  document.addEventListener('focusin', (e) => emit(base('focus', e.target, e)), listenerOptions);
  // The entries FormData would hold, without constructing one: the
  // constructor fires a `formdata` event the page's listeners would see.
  const formGetter = (name) => {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, name);
    return (form) => { try { return descriptor.get.call(form); } catch (_) { return null; } };
  };
  const formControls = formGetter('elements');
  const formAction = formGetter('action');
  const formMethod = formGetter('method');
  const NATIVE_CONTROLS = [HTMLInputElement, HTMLSelectElement, HTMLTextAreaElement, HTMLButtonElement,
    HTMLFieldSetElement, HTMLOutputElement, HTMLObjectElement];
  const formEntries = (form, submitter) => {
    const entries = [];
    for (const el of Array.from(formControls(form) || [])) {
      const name = el.getAttribute('name');
      if (!name || el.matches(':disabled')) continue;
      if (!NATIVE_CONTROLS.some((type) => el instanceof type)) {
        // A form-associated custom element keeps its value in page-defined
        // properties this isolated world cannot read: say so explicitly.
        entries.push([name, '<value not readable: custom form element>']);
        continue;
      }
      const type = String(el.type || '').toLowerCase();
      if (el instanceof HTMLButtonElement || ['submit', 'button', 'reset', 'image'].includes(type)) {
        if (el === submitter && type !== 'image') entries.push([name, el.value]);
        continue;
      }
      if (el instanceof HTMLFieldSetElement || el instanceof HTMLOutputElement || el instanceof HTMLObjectElement) continue;
      if (type === 'checkbox' || type === 'radio') {
        if (el.checked) entries.push([name, el.value || 'on']);
        continue;
      }
      if (type === 'file') {
        for (const file of Array.from(el.files || [])) entries.push([name, file]);
        continue;
      }
      if (el instanceof HTMLSelectElement) {
        for (const option of Array.from(el.selectedOptions)) entries.push([name, option.value]);
        continue;
      }
      entries.push([name, String(el.value ?? '')]);
    }
    return entries;
  };
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const data = {};
    try {
      formEntries(form, e.submitter).forEach(([key, value]) => {
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
    emit({
      ...base('form_submit', form, e), action: formAction(form), method: formMethod(form), data,
      submitter: e.submitter ? describe(e.submitter) : null
    });
  }, listenerOptions);
  if (CAPTURE_CLIPBOARD) {
    document.addEventListener('paste', (e) => {
      let text = '';
      try { text = (e.clipboardData || window.clipboardData).getData('text') || ''; } catch (_) {}
      emit({...base('paste', e.target, e), data: SAFE ? redact(text) : text.slice(0, 10000)});
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
  // No `unload` listener: `pagehide` fires in every case `unload` would, and
  // an `unload` listener makes Chrome log a permissions-policy violation on
  // the page and can keep the page out of the back/forward cache.
  window.addEventListener('pagehide', () => flushState('pagehide'), listenerOptions);
  window.addEventListener('freeze', () => flushState('freeze'), listenerOptions);
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
