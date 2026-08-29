# Threat model

Chrome Network Logger is an authorized debugging and observability tool. Its main security objective is to reduce accidental secret exposure while accurately reporting when capture integrity is degraded.

## Protected assets

- credentials, cookies, tokens, form values, Web Storage, URLs, and captured bodies;
- integrity and completeness signals in the manifest;
- the dedicated Chrome profile and optional proxy credentials;
- host availability while processing attacker-controlled traffic.

## Trust boundaries

Web pages, response bodies, CDP events, proxy servers, and captured text are untrusted inputs. The local user, local filesystem permissions, Chrome installation, Python runtime, and repository dependencies are trusted. CDP is accepted only from the loopback host and the exact debugging port selected by Chrome.

## Mitigations

- `safe` is the default; `raw` requires an explicit option and prints a warning.
- Interaction capture runs in an isolated world and redacts every form-control/form value plus element markup before crossing the binding.
- Context-aware redaction covers headers, cookies, URLs, structured bodies, storage, HTML attributes, console data, and reports.
- A per-session HMAC supports equality checks without storing its key.
- Writer tasks, interaction payloads, pending protocol metadata, proxy connections, individual bodies, and total session body storage are bounded.
- Reports escape HTML, neutralize CSV formulas, and never execute captured markup.
- Required CDP command, writer, or shutdown failures cause an error/partial manifest and, for fatal failures, a non-zero exit code.
- Chrome uses a dedicated profile; stale locks are removed only after confirming no Chrome process still references it.

## Residual risks

- Best-effort redaction cannot recognize every proprietary, binary, compressed-inside-an-opaque-format, encrypted-at-the-application-layer, or unusually named secret.
- Private URLs, timing, sizes, origin names, and other metadata can remain sensitive even after value redaction.
- Raw mode intentionally records secrets. Safe-mode captures are still confidential.
- Files are not encrypted at rest; filesystem access controls and secure deletion are the operator's responsibility.
- Chrome/CDP may omit multipart file bytes, redirect bodies, WebTransport payloads, WebRTC traffic, or large/streaming bodies.
- A hostile local administrator or compromised Chrome/Python/runtime is outside this project's protection boundary.
- `--proxy-insecure-tls` intentionally disables upstream proxy certificate verification.

Use only isolated test accounts and synthetic data when possible. Never publish a capture without an independent review.
