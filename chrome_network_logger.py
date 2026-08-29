"""Backward-compatible entry point for Chrome Network Logger v3."""

from chrome_logger.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
