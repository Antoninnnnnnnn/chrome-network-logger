from __future__ import annotations

from chrome_logger.cdp import TimestampMapper


def test_monotonic_timestamp_maps_to_wall_clock() -> None:
    mapper = TimestampMapper()
    first = mapper.normalize(10.0, 1_700_000_000.0)
    second = mapper.normalize(11.5)
    assert first["epochMs"] == 1_700_000_000_000
    assert second["epochMs"] == 1_700_000_001_500


def test_runtime_epoch_milliseconds_are_not_treated_as_monotonic_seconds() -> None:
    mapper = TimestampMapper()
    value = mapper.from_epoch_ms(1_700_000_000_123)
    assert value["epochMs"] == 1_700_000_000_123
