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


def test_offset_is_reanchored_after_the_system_sleeps() -> None:
    mapper = TimestampMapper()
    mapper.normalize(10.0, 1_700_000_000.0)
    # 600 s of suspend: the wall clock moved on, the monotonic clock did not.
    mapper.normalize(20.0, 1_700_000_610.0)
    mapper.normalize(21.0, 1_700_000_611.0)
    assert mapper.normalize(22.0)["epochMs"] == 1_700_000_612_000


def test_a_single_outlier_does_not_move_the_offset() -> None:
    mapper = TimestampMapper()
    mapper.normalize(10.0, 1_700_000_000.0)
    mapper.normalize(11.0, 1_700_009_999.0)
    mapper.normalize(12.0, 1_700_000_002.0)
    assert mapper.normalize(13.0)["epochMs"] == 1_700_000_003_000


def test_timestamps_the_platform_cannot_convert_do_not_raise() -> None:
    mapper = TimestampMapper()
    assert mapper.from_epoch_ms(1.0)["epochMs"] == 1
    assert mapper.from_epoch_ms(1e300)["iso"] == ""
