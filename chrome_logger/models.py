from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PendingCommand:
    kind: str
    data: dict[str, Any]
    sent_at: float
