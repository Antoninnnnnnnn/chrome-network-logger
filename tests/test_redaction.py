from __future__ import annotations

import json

from chrome_logger.redaction import Redactor


def test_sensitive_headers_and_nested_keys_are_redacted() -> None:
    redactor = Redactor("safe")
    output = redactor.object(
        {
            "headers": {"Authorization": "Bearer abc", "Accept": "application/json", "Cookie": "sid=123"},
            "password": "hello",
            "nested": {"access_token": "secret", "normal": "value"},
        }
    )
    assert output["headers"]["Accept"] == "application/json"
    assert output["headers"]["Authorization"] != "Bearer abc"
    assert output["headers"]["Authorization"].startswith("<redacted")
    assert output["headers"]["Cookie"] != "sid=123"
    assert output["headers"]["Cookie"].startswith("<redacted")
    assert output["password"].startswith("<redacted")
    assert output["nested"]["access_token"].startswith("<redacted")
    assert output["nested"]["normal"] == "value"


def test_url_query_and_fragment_secrets_are_redacted() -> None:
    value = Redactor("safe").url(
        "https://example.com/callback?token=abc&q=ok#access_token=fragment-secret&state=oauth-state"
    )
    assert value is not None
    assert "token=abc" not in value
    assert "fragment-secret" not in value
    assert "oauth-state" not in value
    assert "q=ok" in value


def test_json_body_redaction() -> None:
    redactor = Redactor("safe")
    value = redactor.body_text('{"email":"a@example.com","password":"pw"}', "application/json")
    parsed = json.loads(value)
    assert parsed["email"] == "a@example.com"
    assert "pw" not in parsed["password"]


def test_cookie_objects_keep_metadata_but_hide_values() -> None:
    redactor = Redactor("safe")
    output = redactor.object(
        {
            "cookies": [
                {"name": "sid", "value": "cookie-secret", "domain": "example.com", "path": "/"}
            ],
            "associatedCookies": [
                {"cookie": {"name": "auth", "value": "nested-secret", "domain": "example.com"}}
            ],
        }
    )
    cookie = output["cookies"][0]
    nested = output["associatedCookies"][0]["cookie"]
    assert cookie["name"] == "sid"
    assert cookie["domain"] == "example.com"
    assert "cookie-secret" not in cookie["value"]
    assert nested["name"] == "auth"
    assert "nested-secret" not in nested["value"]


def test_protocol_ids_are_preserved_but_application_session_ids_are_not() -> None:
    redactor = Redactor("safe")
    canonical = redactor.object({"sessionId": "cdp-session", "requestId": "123"})
    body = json.loads(redactor.body_text('{"sessionId":"app-secret","requestId":"business-id"}', "application/json"))
    assert canonical == {"sessionId": "cdp-session", "requestId": "123"}
    assert "app-secret" not in body["sessionId"]
    assert body["requestId"] == "business-id"


def test_raw_header_text_is_redacted() -> None:
    text = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=secret\r\nAuthorization: Bearer abc\r\nX-Test: ok\r\n"
    clean = Redactor("safe").text(text)
    assert "sid=secret" not in clean
    assert "Bearer abc" not in clean
    assert "X-Test: ok" in clean


def test_raw_mode_preserves_values() -> None:
    value = {"password": "pw", "headers": {"Authorization": "Bearer abc"}}
    assert Redactor("raw").object(value) == value


def test_redaction_fingerprints_are_stable_only_within_one_session() -> None:
    first = Redactor("safe")
    second = Redactor("safe")
    assert first.value("1234") == first.value("1234")
    assert first.value("1234") != second.value("1234")


def test_hash_router_fragment_parameters_are_redacted() -> None:
    clean = Redactor("safe").url("https://example.test/#/callback?access_token=secret&q=ok")
    assert clean is not None
    assert "secret" not in clean
    assert "q=ok" in clean


def test_camel_case_and_prefixed_sensitive_fields_are_redacted() -> None:
    output = Redactor("safe").object(
        {
            "clientSecret": "client-secret",
            "accessToken": "access-secret",
            "confirmPassword": "password-secret",
            "normalCode": "public-code",
        },
        preserve_protocol_ids=False,
    )
    assert "client-secret" not in output["clientSecret"]
    assert "access-secret" not in output["accessToken"]
    assert "password-secret" not in output["confirmPassword"]
    assert output["normalCode"] == "public-code"


def test_protocol_error_code_is_not_treated_as_oauth_code() -> None:
    output = Redactor("safe").object({"error": {"code": -32601, "message": "Method not found"}})
    assert output["error"]["code"] == -32601


def test_oauth_code_and_state_are_redacted_only_in_urls() -> None:
    redactor = Redactor("safe")
    output = redactor.object({"code": 200, "state": "ready"})
    url = redactor.url("https://example.test/callback?code=secret-code&state=secret-state")
    assert output == {"code": 200, "state": "ready"}
    assert url is not None
    assert "secret-code" not in url
    assert "secret-state" not in url


def test_sensitive_multipart_field_is_redacted_without_destroying_other_parts() -> None:
    boundary = "test-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="email"\r\n\r\n'
        "a@example.com\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="confirmPassword"\r\n\r\n'
        "super-secret\r\n"
        f"--{boundary}--\r\n"
    )
    clean = Redactor("safe").body_text(body, f'multipart/form-data; boundary="{boundary}"')
    assert "a@example.com" in clean
    assert "super-secret" not in clean
    assert "confirmPassword" in clean
    assert "<redacted" in clean


def test_browser_side_redaction_marker_is_not_fingerprinted_again() -> None:
    redactor = Redactor("safe")
    marker = "<redacted len=12 source=browser>"
    assert redactor.value(marker) == marker
    clean = redactor.interaction({"target": {"type": "password", "value": marker}})
    assert clean["target"]["value"] == marker


def test_jwt_basic_auth_and_url_userinfo_are_redacted() -> None:
    redactor = Redactor("safe")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart"
    clean_text = redactor.text(f"Basic dXNlcjpwYXNz {jwt}")
    clean_url = redactor.url("https://user:password@example.test/path")
    assert "dXNlcjpwYXNz" not in clean_text
    assert jwt not in clean_text
    assert clean_url is not None
    assert "user" not in clean_url
    assert "password" not in clean_url
