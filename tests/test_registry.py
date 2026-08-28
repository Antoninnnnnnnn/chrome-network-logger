from __future__ import annotations

from chrome_logger.cdp import RequestRegistry


def test_request_ids_are_namespaced_by_session_and_redirect_hop() -> None:
    registry = RequestRegistry()
    a0 = registry.create("session-a", "42", {"sessionId": "session-a", "requestId": "42"})
    b0 = registry.create("session-b", "42", {"sessionId": "session-b", "requestId": "42"})
    a1 = registry.create("session-a", "42", {"sessionId": "session-a", "requestId": "42"})
    assert a0 != b0
    assert a0.endswith("hop0")
    assert a1.endswith("hop1")


def test_extra_info_is_assigned_in_hop_order_after_expectations_are_known() -> None:
    registry = RequestRegistry()
    first = registry.create("s", "1", {"sessionId": "s", "requestId": "1"})
    second = registry.create("s", "1", {"sessionId": "s", "requestId": "1"})
    registry.set_response_extra_expected(first, True)
    registry.set_response_extra_expected(second, True)

    assert registry.assign_extra("s", "1", "response", {"statusCode": 302}) == first
    assert registry.assign_extra("s", "1", "response", {"statusCode": 200}) == second
    assert registry.entries[first]["extraInfo"]["response"]["statusCode"] == 302
    assert registry.entries[second]["extraInfo"]["response"]["statusCode"] == 200


def test_response_extra_waits_when_the_target_hop_is_not_known() -> None:
    registry = RequestRegistry()
    first = registry.create("s", "1", {"sessionId": "s", "requestId": "1"})
    second = registry.create("s", "1", {"sessionId": "s", "requestId": "1"})

    assert registry.assign_extra("s", "1", "response", {"statusCode": 200}) is None
    registry.set_response_extra_expected(first, False)
    assigned = registry.set_response_extra_expected(second, True)

    assert assigned == [second]
    assert "response" not in registry.entries[first].get("extraInfo", {})
    assert registry.entries[second]["extraInfo"]["response"]["statusCode"] == 200


def test_request_extra_can_arrive_before_request_will_be_sent() -> None:
    registry = RequestRegistry()
    assert registry.assign_extra("s", "9", "request", {"headers": {"x": "y"}}) is None
    key = registry.create("s", "9", {"sessionId": "s", "requestId": "9"})
    assert registry.entries[key]["extraInfo"]["request"]["headers"] == {"x": "y"}
