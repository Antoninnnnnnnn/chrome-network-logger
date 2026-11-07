from __future__ import annotations

import os
import time
from pathlib import Path


def replace_with_retry(source: Path, target: Path, *, attempts: int = 20) -> None:
    """Atomically move `source` onto `target`, retrying Windows sharing violations.

    On Windows an antivirus scan, a search indexer or an editor holding the
    target open makes os.replace fail with PermissionError for a moment. One
    such hiccup must not fail a whole capture.
    """
    for attempt in range(1, attempts + 1):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == attempts:
                raise
            time.sleep(min(0.05 * attempt, 0.25))
