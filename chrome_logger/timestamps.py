from __future__ import annotations

import math
import threading
import time
from datetime import datetime
from typing import Any


class TimestampMapper:
    def __init__(self) -> None:
        self._offset: float | None = None
        self._lock = threading.Lock()

    def normalize(self, monotonic_seconds: float | None = None, wall_seconds: float | None = None) -> dict[str, Any]:
        monotonic_seconds = self._finite(monotonic_seconds)
        wall_seconds = self._finite(wall_seconds)
        with self._lock:
            if monotonic_seconds is not None and wall_seconds is not None:
                candidate = float(wall_seconds) - float(monotonic_seconds)
                if self._offset is None or abs(candidate - self._offset) < 5:
                    self._offset = candidate
            if wall_seconds is not None:
                epoch = float(wall_seconds)
            elif monotonic_seconds is not None and self._offset is not None:
                epoch = float(monotonic_seconds) + self._offset
            else:
                epoch = time.time()
        result: dict[str, Any] = {
            "epochMs": round(epoch * 1000),
            "iso": datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="milliseconds"),
        }
        if monotonic_seconds is not None:
            result["cdpMonotonicSeconds"] = monotonic_seconds
        return result

    def from_epoch_ms(self, epoch_ms: int | float | None) -> dict[str, Any]:
        finite_ms = self._finite(epoch_ms)
        epoch = finite_ms / 1000 if finite_ms is not None else time.time()
        return {
            "epochMs": round(epoch * 1000),
            "iso": datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="milliseconds"),
        }

    @staticmethod
    def _finite(value: int | float | None) -> float | None:
        if value is None:
            return None
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed if math.isfinite(parsed) else None
