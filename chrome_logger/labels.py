"""Readable one-line descriptions of captured events, shared by the timeline and reports."""

from __future__ import annotations

import json
from typing import Any

TIMELINE_CONSOLE_LEVELS = frozenset({"error", "warning", "assert"})
_TIMELINE_TEXT_LIMIT = 300
_LABELLED_EVENTS = {"click", "change", "input", "keydown", "focus", "form_submit", "paste"}


def short_text(text: str, limit: int = _TIMELINE_TEXT_LIMIT) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def console_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def element_label(target: Any) -> str:
    """Describe an element the way a person would point at it: ``button#go "Log in"``."""
    if not isinstance(target, dict):
        return ""
    tag = str(target.get("tag") or "?")
    selector = tag
    if target.get("id"):
        selector += f"#{target['id']}"
    elif target.get("testId"):
        selector += f"[data-testid={target['testId']}]"
    elif target.get("name"):
        selector += f"[name={target['name']}]"
    if target.get("type") and tag in {"input", "button"}:
        selector += f"[type={target['type']}]"
    text = target.get("ariaLabel") or target.get("label") or target.get("text") or target.get("placeholder") or ""
    text = short_text(str(text), 60)
    return f'{selector} "{text}"' if text else selector


def interaction_label(event: dict[str, Any]) -> str:
    """One readable line per interaction, for the timeline and the overview report."""
    name = str(event.get("event") or "unknown")
    if name not in _LABELLED_EVENTS:
        return name
    label = f"{name} {element_label(event.get('target'))}".strip()
    if name == "keydown" and event.get("key"):
        modifiers = [mod for mod in ("ctrl", "alt", "shift", "meta") if event.get(mod)]
        label += f" key={'+'.join([*modifiers, str(event['key'])])}"
    attrs = (event.get("target") or {}).get("attrs") or {}
    if name == "form_submit" and event.get("action") and ("action" in attrs or "method" in attrs):
        # Without these attributes the browser default (GET to the page itself)
        # is not what happened: script handled the submit.
        label += f" → {str(event.get('method') or 'get').upper()} {event['action']}"
    return label
