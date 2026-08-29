# Contributing

Thank you for improving Chrome Network Logger. Changes must preserve the project's authorization boundary, safe-by-default handling, and explicit capture limitations.

## Development setup

Use Python 3.10 or newer and a current Chrome or Chromium installation.

```bash
python -m venv .venv
python -m pip install -e .[dev]
```

Before submitting a change, run the same core checks as CI:

```bash
python -m ruff check .
python -m ruff format --check .
python -m bandit -q -r chrome_logger chrome_network_logger.py -s B404,B603
python -m compileall -q chrome_logger tests
python -m pytest --cov=chrome_logger
python -m build
python -m twine check dist/*
```

## Change requirements

- Add or update tests for behavioral changes and regressions.
- Keep `README.md` and `README.fr.md` synchronized when user-facing behavior changes.
- Update `CHANGELOG.md` for release-visible changes.
- Do not weaken safe-mode redaction, loopback CDP validation, bounded queues/buffers, or non-zero fatal exit behavior.
- Never commit real captures, browser profiles, proxy credentials, tokens, or third-party data. Use synthetic fixtures only.
- Keep output compatible with `schemaVersion: 3`, or document and test an intentional schema migration.
- Distinguish optional CDP capabilities from commands required for a valid capture.

## Pull requests

Describe the observed problem, the change, its security/privacy impact, and how it was verified. A focused reproduction using synthetic data is preferable to a private capture. Security vulnerabilities must follow [`SECURITY.md`](SECURITY.md), not a public issue.
