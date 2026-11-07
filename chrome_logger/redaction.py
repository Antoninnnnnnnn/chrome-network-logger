from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, quote_plus, unquote_plus, urlsplit, urlunsplit

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
    r"credit[_-]?card|credential|assertion|signature|sig|auth[_-]?code|private[_-]?key"
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
    "privatekey",
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
    "privatekey",
}

# Application data: a field called sessionId in there is the application's own
# session, not a CDP correlation id.
_APP_DATA_KEYS = {"values", "entries", "localstorage", "sessionstorage", "data", "newvalue", "oldvalue"}

_URL_HEADERS = {"referer", "location", "content-location"}

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
_KEY_VALUE_NAMES = (
    r"(?i)(\b(?:password|passwd|pwd|secret|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|csrf|xsrf|otp|pin|cvv|cvc|"
    r"card[_-]?(?:number|no|num)|credit[_-]?card|credential|assertion|jwt|auth[_-]?code)"
    r"\b\s*[=:]\s*)"
)
# A value already turned into a marker is never matched again.
_KEY_VALUE = re.compile(_KEY_VALUE_NAMES + r"(?!<redacted)([^&\s,;]+)")
# Inside serialized JSON a value must stop at the closing quote or an escape.
_KEY_VALUE_IN_JSON = re.compile(_KEY_VALUE_NAMES + r'(?!<redacted)([^&\s,;"\\<]+)')
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


_CAMEL_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+")
# camelCase names whose last word, or last two words, name a secret:
# authToken, userSecret, csrfToken, privateKey. Only the end counts, so
# tokenType, sessionStorage or accessTokenExpiresAt stay readable.
_CAMEL_SECRET_LAST = {"token", "secret", "password", "passwd", "pwd", "credential", "credentials", "jwt", "cookie"}
_CAMEL_SECRET_PAIRS = {
    ("secret", "key"),
    ("private", "key"),
    ("api", "key"),
    ("access", "key"),
    ("signing", "key"),
    ("encryption", "key"),
}
# Field names that carry no data themselves (expiresAt, user_id, roles).
_ORDINARY_KEY = re.compile(r"^[a-z]+(?:[_-][a-z]+|[A-Z][a-z]+)*$")
# A JSON document behind a numeric prefix: Socket.IO/Engine.IO frames ("42[...]").
_PREFIXED_JSON = re.compile(r"^\s*(\d{1,4})\s*([\[{].*)$", re.DOTALL)
_MAX_EMBEDDED_JSON = 1024 * 1024


def _credential_like(token: str) -> bool:
    """Tell a credential after Basic/Bearer from an ordinary word ("Basic plan", "Basic Membership")."""
    if len(token) < 4:
        return False
    ordinary_word = token.isalpha() and len(token) <= 12 and (token.islower() or token.istitle())
    return not ordinary_word


def _camel_secret(key: str) -> bool:
    if not re.search(r"[a-z0-9][A-Z]", key):
        return False
    words = [word.casefold() for word in _CAMEL_WORDS.findall(key)]
    if len(words) < 2:
        return False
    return words[-1] in _CAMEL_SECRET_LAST or (words[-2], words[-1]) in _CAMEL_SECRET_PAIRS


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
        or _camel_secret(text)
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
    digest = hmac.new(key, raw, hashlib.sha256).hexdigest()[:12]
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
        if not self.enabled:
            return copy.deepcopy(headers)
        if isinstance(headers, list):
            # Cache Storage and Fetch use [{name, value}] instead of a mapping.
            out: list[Any] = []
            for item in headers:
                if isinstance(item, dict) and isinstance(item.get("name"), str) and "value" in item:
                    clean = dict(item)
                    clean["value"] = self.headers({item["name"]: item["value"]})[item["name"]]
                    out.append(clean)
                else:
                    out.append(self.object(item))
            return out
        if not isinstance(headers, dict):
            return copy.deepcopy(headers)
        result: dict[str, Any] = {}
        for key, value in headers.items():
            if _is_sensitive_key(key, preserve_protocol_ids=False):
                result[str(key)] = self.value(value)
            elif str(key).lower() in _URL_HEADERS and isinstance(value, str):
                # An OAuth callback's code travels on in Referer and Location.
                result[str(key)] = self.url(value)
            else:
                result[str(key)] = self.object(value)
        return result

    def keyed_value(self, key: Any, value: Any) -> Any:
        """Redact ``value`` as it would be under the field name ``key`` (storage keys, header names)."""
        if not self.enabled:
            return value
        return self.object({str(key): value}, preserve_protocol_ids=False)[str(key)]

    def _redact_parameters(self, value: str) -> str:
        """Redact ``a=b&c=d`` pairs; pieces that need no change keep their exact original text."""
        if not value:
            return value
        try:
            pieces = []
            for piece in value.split("&"):
                name, separator, raw = piece.partition("=")
                if not separator:
                    # A bare piece can be a whole token: "?<jwt>".
                    bare = unquote_plus(piece)
                    clean = self.text(bare)
                    pieces.append(piece if clean == bare else quote_plus(clean))
                    continue
                decoded = unquote_plus(raw)
                if _is_sensitive_url_parameter(unquote_plus(name)):
                    clean = str(self.value(decoded))
                else:
                    # Harmless names can still carry a JWT, a JSON document
                    # with a token, or a SAML response.
                    clean = self.text(decoded)
                    if clean == decoded:
                        pieces.append(piece)
                        continue
                pieces.append(name + "=" + quote_plus(clean))
            return "&".join(pieces)
        except Exception:
            return self.text(value)

    def _redact_fragment(self, fragment: str) -> str:
        """OAuth implicit-flow and hash-router fragments carry access_token/code/state parameters."""
        prefix = "#" if fragment.startswith("#") else ""
        body = fragment[len(prefix) :]
        fragment_path, question, fragment_query = body.partition("?")
        if question and "=" not in fragment_path:
            # A hash route with parameters: "#/cb?code=...".
            body = fragment_path + "?" + self._redact_parameters(fragment_query)
        elif "=" in body:
            # Parameters straight after "#", whose values may contain "?":
            # "#access_token=...&redirect=/x?y=1".
            body = self._redact_parameters(body)
        else:
            body = self.text(body)
        return prefix + body

    def url(self, url: str | None) -> str | None:
        if not self.enabled or not url:
            return url
        try:
            parts = urlsplit(url)
            if parts.scheme.casefold() in {"data", "javascript"}:
                return str(self.value(url))
            query = self._redact_parameters(parts.query)
            fragment = self._redact_fragment(parts.fragment)
            # Magic links and share URLs put JWTs in the path itself.
            path = _JWT_VALUE.sub(lambda match: quote(str(self.value(match.group(1))), safe=""), parts.path)

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
            return urlunsplit((parts.scheme, netloc, path, query, fragment))
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
            return self._redact_leaves(value)

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
                    "requesturl",
                } and isinstance(item, str):
                    out[key_s] = self.url(item) if normalized != "urlfragment" else self._redact_fragment(item)
                elif cookie_object and normalized == "value":
                    out[key_s] = self.value(item)
                elif normalized == "cookieline":
                    # A raw Set-Cookie line of a blocked or exempted cookie.
                    out[key_s] = self.value(item)
                elif normalized in _COOKIE_CONTAINER_KEYS:
                    out[key_s] = self.object(
                        item,
                        parent_key=key_s,
                        preserve_protocol_ids=preserve_protocol_ids,
                    )
                elif normalized in _APP_DATA_KEYS:
                    out[key_s] = self.object(item, parent_key=key_s, preserve_protocol_ids=False)
                elif _is_sensitive_key(key_s, preserve_protocol_ids=preserve_protocol_ids):
                    out[key_s] = self._redact_leaves(item)
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

    def _redact_leaves(self, value: Any) -> Any:
        """Everything under a sensitive name is secret, but its shape is useful: keep field names and nesting.

        A key that is not an ordinary field name ({"sk_live_...": true}) is itself a secret.
        """
        if isinstance(value, dict):
            return {
                (str(key) if _ORDINARY_KEY.match(str(key)) and len(str(key)) <= 40 else str(self.value(key))): (
                    self._redact_leaves(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._redact_leaves(item) for item in value]
        if value is None or isinstance(value, bool):
            return value
        return self.value(value)

    def _embedded_json(self, text: str) -> str | None:
        """Redact a string that is itself JSON, or JSON behind a numeric prefix (Socket.IO)."""
        stripped = text.strip()
        if not stripped or len(stripped) > _MAX_EMBEDDED_JSON:
            return None
        prefix = ""
        if stripped[0] not in "[{":
            match = _PREFIXED_JSON.match(stripped)
            if not match:
                return None
            prefix, stripped = match.group(1), match.group(2)
        if stripped[-1] not in "]}":
            return None
        try:
            parsed = json.loads(stripped)
            if not isinstance(parsed, (dict, list)):
                return None
            original = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            clean = self._scan(
                json.dumps(self.object(parsed, preserve_protocol_ids=False), ensure_ascii=False, separators=(",", ":")),
                structured=True,
            )
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            # RecursionError: deeply nested JSON is left to the text patterns.
            return None
        return prefix + clean if clean != original else text

    def text(self, text: str) -> str:
        if not self.enabled:
            return text
        embedded = self._embedded_json(text)
        if embedded is not None:
            return embedded
        return self._scan(text, structured=False)

    def _scan(self, text: str, *, structured: bool) -> str:
        """Pattern passes over free text. ``structured`` text is serialized JSON whose values are already
        redacted: the passes then only catch secrets inside keys, with patterns that stop at quotes so the
        JSON stays valid."""
        if structured:
            result = text
        else:
            result = _RAW_HEADER_LINE.sub(
                lambda match: match.group("name") + str(self.value(match.group("value"))),
                text,
            )
        result = _AUTH_VALUE.sub(
            lambda match: (
                match.group(1) + str(self.value(match.group(2))) if _credential_like(match.group(2)) else match.group(0)
            ),
            result,
        )
        result = _JWT_VALUE.sub(lambda match: str(self.value(match.group(1))), result)
        key_value = _KEY_VALUE_IN_JSON if structured else _KEY_VALUE
        result = key_value.sub(lambda match: match.group(1) + str(self.value(match.group(2))), result)
        if structured:
            return result
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
            trailing = ""
            while body.endswith(("\r", "\n")):
                trailing = body[-1] + trailing
                body = body[:-1]
            if match and _is_sensitive_key(
                (match.group(1) or match.group(2) or "").strip(), preserve_protocol_ids=False
            ):
                body = str(self.value(body))
            elif not re.search(r"(?im)^Content-Disposition:[^\r\n]*\bfilename\*?=", headers):
                # A text field with a harmless name (a GraphQL "operations"
                # part) can still hold credentials. File parts stay as sent.
                part_type = re.search(r"(?im)^Content-Type:\s*([^\r\n;]+)", headers)
                body = self.body_text(body, part_type.group(1) if part_type else "text/plain")
            output.append(delimiter + headers + separator + body + trailing)
        return "".join(output)

    def body_text(self, text: str, content_type: str | None = None) -> str:
        if not self.enabled:
            return text
        ctype = (content_type or "").lower()
        stripped = text.lstrip()
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                return self._scan(
                    json.dumps(
                        self.object(parsed, preserve_protocol_ids=False),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    structured=True,
                )
            except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
                # RecursionError: absurdly nested JSON falls back to text redaction.
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
