from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

BodyMode = Literal["none", "api", "all"]
SensitiveMode = Literal["safe", "raw"]

DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_BUFFER = 256 * 1024 * 1024
DEFAULT_MAX_RESOURCE_BUFFER = 64 * 1024 * 1024
DEFAULT_MAX_POST_DATA = 16 * 1024 * 1024


@dataclass(slots=True)
class CaptureConfig:
    output_parent: Path
    profile_dir: Path
    body_mode: BodyMode = "api"
    sensitive_mode: SensitiveMode = "safe"
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_total_buffer: int = DEFAULT_MAX_TOTAL_BUFFER
    max_resource_buffer: int = DEFAULT_MAX_RESOURCE_BUFFER
    max_post_data: int = DEFAULT_MAX_POST_DATA
    capture_interactions: bool = True
    capture_clipboard: bool = False
    capture_console: bool = True
    capture_storage: bool = True
    compress_text_bodies: bool = True
    body_inline_limit: int = 4 * 1024
    websocket_inline_limit: int = 64 * 1024
    finalize_grace_seconds: float = 0.25
    shutdown_wait_seconds: float = 2.0
    writer_queue_size: int = 20_000
    log_level: str = "INFO"

    def validate(self) -> None:
        if self.body_mode not in {"none", "api", "all"}:
            raise ValueError(f"Invalid body mode: {self.body_mode}")
        if self.sensitive_mode not in {"safe", "raw"}:
            raise ValueError(f"Invalid sensitive mode: {self.sensitive_mode}")
        if self.max_body_bytes < 0:
            raise ValueError("max_body_bytes must be >= 0")
        if self.max_total_buffer <= 0 or self.max_resource_buffer <= 0:
            raise ValueError("CDP buffers must be positive")
        if self.max_resource_buffer > self.max_total_buffer:
            raise ValueError("max_resource_buffer cannot exceed max_total_buffer")
        if self.writer_queue_size < 100:
            raise ValueError("writer_queue_size is too small")
