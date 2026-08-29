from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# IDs emitted by CDP are correlation identifiers, not authentication secrets. They
# must stay stable in canonical records. API/body payloads are redacted with
# ``preserve_protocol_ids=False`` so an application field called ``sessionId`` is
# still treated as sensitive.
_PROTOCOL_ID_KEYS = {
    "sessionid",
    "requestid",
    "loaderid",
    "frameid",
    "targetid",
    "browsercontextid",
    "executioncontextid",
    "transportid",
    "connectionid",
    "interceptionid",
}

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.])(?:"
    r"authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|"
    r"pass(?:word|wd)?|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|bearer|jwt|"
    r"session(?:[_-]?(?:token|key|secret|cookie|auth))?|"
    r"csrf|xsrf|otp|pin|cvv|cvc|cc|card(?:[_-]?(?:number|no|num))?|"
    r"credit[_-]?card|credential|assertion|signature|sig|auth[_-]?code"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)

# OAuth-style URL parameters are sensitive even when their names are generic.
_URL_SECRET_KEYS = {
    "code",
    "state",
    "signature",
    "sig",
    "jwt",
    "assertion",
    "credential",
    "auth",
}

# Normalized aliases cover common camelCase/compact field names that the
# separator-aware regular expression cannot recognize by itself. URL-only
# names such as ``code`` and ``state`` deliberately stay out of this set so
# protocol diagnostics do not lose their numeric error code.
_SENSITIVE_NORMALIZED_KEYS = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "password",
    "passwd",
    "pwd",
    "secret",
    "clientsecret",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "token",
    "bearer",
    "jwt",
    "session",
    "sessiontoken",
    "sessionkey",
    "sessionsecret",
    "sessioncookie",
    "sessionauth",
    "csrf",
    "xsrf",
    "otp",
    "pin",
    "cvv",
    "cvc",
    "cc",
    "cardnumber",
    "cardno",
    "cardnum",
    "creditcard",
    "credential",
    "assertion",
    "signature",
    "sig",
    "authcode",
}

_SENSITIVE_NORMALIZED_FRAGMENTS = {
    "password",
    "passwd",
    "clientsecret",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "sessionsecret",
    "sessioncookie",
    "csrf",
    "xsrf",
    "credential",
    "assertion",
    "cardnumber",
    "creditcard",
    "authcode",
}

_COOKIE_CONTAINER_KEYS = {
    "cookie",
    "cookies",
    "associatedcookies",
    "blockedcookies",
    "exemptedcookies",
    "cookiepartitionkey",
}

# Raw CDP fields such as headersText/requestHeadersText may contain credentials.
_RAW_HEADER_LINE = re.compile(
    r"(?im)^(?P<name>\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token|x-csrf-token)\s*:\s*)(?P<value>[^\r\n]*)"
)
_AUTH_VALUE = re.compile(r"(?i)(\b(?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]+)")
_JWT_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})(?![A-Za-z0-9_-])"
)
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|csrf|xsrf|otp|pin|cvv|cvc|"
    r"card[_-]?(?:number|no|num)|credit[_-]?card|credential|assertion|jwt|auth[_-]?code)"
    r"\b\s*[=:]\s*)([^&\s,;]+)"
)
_ALREADY_REDACTED = re.compile(
    r"^<redacted len=\d+(?: hmac=[0-9a-f]{8,64}| source=browser)?>$",
    re.IGNORECASE,
)

_JSON_SECRET = re.compile(
    r'(?i)(["\'](?:password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|'
    r"refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|csrf|xsrf|otp|pin|cvv|cvc|"
    r"card[_-]?(?:number|no|num)|credit[_-]?card|credential|assertion|jwt|"
    r'auth[_-]?code|sessionid)["\']\s*:\s*["\'])(.*?)(["\'])'
)
_HTML_SENSITIVE_ATTRIBUTE = re.compile(
    r"(?i)(\b(?:value|srcdoc)\s*=\s*)(?P<quote>[\"']?)(?P<value>.*?)(?P=quote)(?=\s|/?>)",
    re.DOTALL,
)


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).casefold())


def _is_protocol_id(key: Any) -> bool:
    return _normalized_key(key) in _PROTOCOL_ID_KEYS


def _is_sensitive_key(key: Any, *, preserve_protocol_ids: bool = True) -> bool:
    normalized = _normalized_key(key)
    if _is_protocol_id(key):
        if preserve_protocol_ids:
            return False
        # Application session IDs are commonly authentication material. Other
        # business identifiers such as requestId are useful and not secrets by
        # default.
        if normalized == "sessionid":
            return True
    text = str(key)
    return (
        bool(_SENSITIVE_KEY.search(text))
        or normalized in _SENSITIVE_NORMALIZED_KEYS
        or any(fragment in normalized for fragment in _SENSITIVE_NORMALIZED_FRAGMENTS)
    )


def _is_sensitive_url_parameter(key: Any) -> bool:
    normalized = _normalized_key(key)
    return _is_sensitive_key(key, preserve_protocol_ids=False) or normalized in _URL_SECRET_KEYS


def _fingerprint(value: Any, key: bytes) -> str:
    raw = str(value).encode("utf-8", errors="replace")
    # This is a short, randomly keyed per-capture correlation tag, not a
    # password verifier or stored password hash. A fast HMAC is intentional.
    digest = hmac.new(key, raw, hashlib.sha256).hexdigest()[:12]  # lgtm[py/weak-sensitive-data-hashing]
    return f"<redacted len={len(raw)} hmac={digest}>"


def _looks_like_cookie(value: dict[str, Any]) -> bool:
    lowered = {str(key).casefold() for key in value}
    return (
        "name" in lowered
        and "value" in lowered
        and bool(lowered.intersection({"domain", "path", "expires", "sameparty", "samesite", "httponly", "secure"}))
    )


@dataclass(slots=True)
class Redactor:
    mode: str = "safe"
    _key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    @property
    def enabled(self) -> bool:
        return self.mode != "raw"

    def value(self, value: Any) -> Any:
        if not self.enabled:
            return value
        if isinstance(value, str) and _ALREADY_REDACTED.fullmatch(value):
            return value
        return _fingerprint(value, self._key)

    def headers(self, headers: Any) -> Any:
        if not self.enabled or not isinstance(headers, dict):
            return copy.deepcopy(headers)
        result: dict[str, Any] = {}
        for key, value in headers.items():
            result[str(key)] = (
                self.value(value) if _is_sensitive_key(key, preserve_protocol_ids=False) else self.object(value)
            )
        return result

    def _redact_parameters(self, value: str) -> str:
        try:
            items = parse_qsl(value, keep_blank_values=True)
            if not items:
                return value
            redacted = [
                (
                    key,
                    str(self.value(item)) if _is_sensitive_url_parameter(key) else item,
                )
                for key, item in items
            ]
            return urlencode(redacted, doseq=True)
        except Exception:
            return self.text(value)

    def url(self, url: str | None) -> str | None:
        if not self.enabled or not url:
            return url
        try:
            parts = urlsplit(url)
            if parts.scheme.casefold() in {"data", "javascript"}:
                return str(self.value(url))
            query = self._redact_parameters(parts.query)
            fragment = parts.fragment
            # OAuth implicit-flow and callback fragments often contain
            # access_token/code/state parameters.
            if "?" in fragment:
                fragment_path, _, fragment_query = fragment.partition("?")
                fragment = fragment_path + "?" + self._redact_parameters(fragment_query)
            elif "=" in fragment:
                fragment = self._redact_parameters(fragment)
            else:
                fragment = self.text(fragment)

            username = parts.username
            password = parts.password
            host = parts.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            userinfo = ""
            if username is not None:
                userinfo = str(self.value(username))
                if password is not None:
                    userinfo += ":" + str(self.value(password))
                userinfo += "@"
            port = f":{parts.port}" if parts.port else ""
            netloc = f"{userinfo}{host}{port}"
            return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))
        except Exception:
            return self.text(url)

    def object(
        self,
        value: Any,
        *,
        parent_key: str | None = None,
        preserve_protocol_ids: bool = True,
    ) -> Any:
        if not self.enabled:
            return copy.deepcopy(value)

        parent_normalized = _normalized_key(parent_key or "")
        cookie_context = parent_normalized in _COOKIE_CONTAINER_KEYS
        if (
            parent_key
            and _is_sensitive_key(parent_key, preserve_protocol_ids=preserve_protocol_ids)
            and not cookie_context
        ):
            return self.value(value)

        if isinstance(value, dict):
            cookie_object = cookie_context or _looks_like_cookie(value)
            out: dict[str, Any] = {}
            for key, item in value.items():
                key_s = str(key)
                normalized = _normalized_key(key_s)
                if normalized in {"headers", "requestheaders", "responseheaders"}:
                    out[key_s] = self.headers(item)
                elif normalized in {
                    "url",
                    "documenturl",
                    "origin",
                    "oldurl",
                    "newurl",
                    "href",
                    "action",
                    "src",
                    "formaction",
                    "poster",
                    "urlfragment",
                } and isinstance(item, str):
                    out[key_s] = self.url(item) if normalized != "urlfragment" else self._redact_parameters(item)
                elif cookie_object and normalized == "value":
                    out[key_s] = self.value(item)
                elif normalized in _COOKIE_CONTAINER_KEYS:
                    out[key_s] = self.object(
                        item,
                        parent_key=key_s,
                        preserve_protocol_ids=preserve_protocol_ids,
                    )
                elif _is_sensitive_key(key_s, preserve_protocol_ids=preserve_protocol_ids):
                    out[key_s] = self.value(item)
                else:
                    out[key_s] = self.object(
                        item,
                        parent_key=key_s,
                        preserve_protocol_ids=preserve_protocol_ids,
                    )
            return out
        if isinstance(value, list):
            return [
                self.object(item, parent_key=parent_key, preserve_protocol_ids=preserve_protocol_ids) for item in value
            ]
        if isinstance(value, tuple):
            return [
                self.object(item, parent_key=parent_key, preserve_protocol_ids=preserve_protocol_ids) for item in value
            ]
        if isinstance(value, str):
            return self.text(value)
        return copy.deepcopy(value)

    def text(self, text: str) -> str:
        if not self.enabled:
            return text
        result = _RAW_HEADER_LINE.sub(
            lambda match: match.group("name") + str(self.value(match.group("value"))),
            text,
        )
        result = _AUTH_VALUE.sub(lambda match: match.group(1) + str(self.value(match.group(2))), result)
        result = _JWT_VALUE.sub(lambda match: str(self.value(match.group(1))), result)
        result = _KEY_VALUE.sub(lambda match: match.group(1) + str(self.value(match.group(2))), result)
        result = _JSON_SECRET.sub(
            lambda match: match.group(1) + str(self.value(match.group(2))) + match.group(3),
            result,
        )
        result = _HTML_SENSITIVE_ATTRIBUTE.sub(
            lambda match: (
                match.group(1) + match.group("quote") + str(self.value(match.group("value"))) + match.group("quote")
            ),
            result,
        )
        return result

    def _redact_multipart(self, text: str, content_type: str) -> str | None:
        boundary_match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;\s]+))", content_type, re.IGNORECASE)
        if not boundary_match:
            return None
        boundary = boundary_match.group(1) or boundary_match.group(2)
        delimiter = "--" + boundary
        chunks = text.split(delimiter)
        if len(chunks) < 3:
            return None
        output = [chunks[0]]
        disposition = re.compile(r"(?im)^Content-Disposition:[^\r\n]*\bname=(?:\"([^\"]*)\"|([^;\r\n]+))")
        for chunk in chunks[1:]:
            if chunk.startswith("--"):
                output.append(delimiter + chunk)
                continue
            separator = "\r\n\r\n" if "\r\n\r\n" in chunk else "\n\n" if "\n\n" in chunk else None
            if separator is None:
                output.append(delimiter + chunk)
                continue
            headers, body = chunk.split(separator, 1)
            match = disposition.search(headers)
            if match and _is_sensitive_key(
                (match.group(1) or match.group(2) or "").strip(), preserve_protocol_ids=False
            ):
                trailing = ""
                while body.endswith(("\r", "\n")):
                    trailing = body[-1] + trailing
                    body = body[:-1]
                body = str(self.value(body)) + trailing
            output.append(delimiter + headers + separator + body)
        return "".join(output)

    def body_text(self, text: str, content_type: str | None = None) -> str:
        if not self.enabled:
            return text
        ctype = (content_type or "").lower()
        stripped = text.lstrip()
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                return json.dumps(
                    self.object(parsed, preserve_protocol_ids=False),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            except (json.JSONDecodeError, TypeError, ValueError):
                parsed = None
        if "application/x-www-form-urlencoded" in ctype:
            return self._redact_parameters(text)
        if "multipart/form-data" in ctype:
            multipart = self._redact_multipart(text, content_type or "")
            if multipart is not None:
                return multipart
        return self.text(text)

    def interaction(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return copy.deepcopy(payload)
        clean = self.object(payload)
        target = clean.get("target") if isinstance(clean, dict) else None
        if isinstance(target, dict):
            input_type = str(target.get("type") or "").lower()
            fields = [str(target.get(field) or "") for field in ("name", "id", "autocomplete", "placeholder")]
            if input_type == "password" or any(
                _is_sensitive_key(field, preserve_protocol_ids=False) for field in fields
            ):
                if "value" in target:
                    target["value"] = self.value(target["value"])
                attrs = target.get("attrs")
                if isinstance(attrs, dict) and "value" in attrs:
                    attrs["value"] = self.value(attrs["value"])
                if "outerHTML" in target:
                    target["outerHTML"] = f'<{target.get("tag", "element")} data-sensitive-redacted="true">'
        return clean
