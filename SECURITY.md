# Security policy

## Captured data

Chrome Network Logger can observe application-layer data exposed by Chrome, including authentication headers, cookies, request/response bodies, Web Storage, forms, and user interactions. Treat every `session_*` directory as confidential, including captures created in `safe` mode.

`safe` mode performs context-aware best-effort redaction and uses a random per-session HMAC for comparison fingerprints. It cannot guarantee recognition of every proprietary, binary, encrypted-at-the-application-layer, or unusually named secret. `raw` mode intentionally preserves sensitive values and should only be used on systems and accounts you are authorized to inspect.

Never commit captures, `capture_profile`, or proxy credentials. The repository `.gitignore` excludes their default locations, but custom paths still require care.

## Reporting a vulnerability

Please open a private GitHub security advisory for vulnerabilities in the logger itself. Do not include real credentials, session cookies, private captures, or third-party data in a public issue.

A useful report contains:

- affected version and operating system;
- Chrome/Chromium version;
- minimal reproduction using synthetic data;
- expected and actual behavior;
- impact and any proposed fix.

## Supported version

Security fixes target the latest v3 release. The historical v2 monolithic implementation is superseded and should not be used for new sensitive captures.
