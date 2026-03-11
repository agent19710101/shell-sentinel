# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## Delivered foundation (v0.8.0 → v0.10.3)

Shipped:
- Rule-coverage expansion for shell execution forms and encoded payload chains.
- Deterministic baseline workflows with governance metadata and expiry handling.
- Stable machine-readable outputs (`--json`, `--sarif`, `--rdjsonl`) with contract tests.
- File-aware scanning and improved GitHub Action ergonomics for input/file/files modes.
- CI/release hardening and action validation coverage.

## v0.11.0 — Decoder-chain depth

Scope:
- Add high-severity detection for gzip/xz decode-and-exec chains (for example: `... | gzip -d | sh`, `... | xz -d | bash`).
- Keep severity/rule IDs stable and documented in output contracts.
- Add focused regression tests for safe vs risky decode cases.

Exit criteria:
- New decoder rules covered by unit tests and file-mode line mapping tests.
- README examples include at least one gzip/xz detection case.

## v0.12.0 — Script-aware precision

Scope:
- Add optional script parsing mode for `--file` scans to improve multiline/control-flow precision.
- Reduce false positives from regex-only matching on benign heredoc/variable patterns.
- Preserve existing default behavior unless parser mode is explicitly enabled.

Exit criteria:
- Parser mode is opt-in and documented.
- Contract tests demonstrate unchanged default output shape.

## v0.13.0 — Team policy profiles

Scope:
- Add policy profile presets (`strict`, `balanced`, `legacy`) for faster organizational rollout.
- Allow profile + local policy override merging with deterministic precedence.
- Document migration guidance for existing `.shell-sentinel.yaml` users.

Exit criteria:
- Profile selection/merge behavior covered by tests.
- README + migration notes include profile adoption guidance.
