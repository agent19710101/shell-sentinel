# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## Delivered foundation (v0.8.0 → v0.11.0)

Shipped:
- Rule-coverage expansion for shell execution forms and encoded/compressed payload chains.
- Deterministic baseline workflows with governance metadata and expiry handling.
- Stable machine-readable outputs (`--json`, `--sarif`, `--rdjsonl`) with contract tests.
- File-aware scanning plus opt-in parser-backed file scanning (`--parser shell`) for higher precision.
- Team policy profiles (`strict`, `balanced`, `legacy`) for rollout ergonomics.
- CI/release hardening and action validation coverage.

## v0.12.0 — Parser control-flow precision

Scope:
- Extend `--parser shell` analysis to better track control-flow constructs (functions, loops, conditionals) with stable line mapping.
- Reduce false positives from text-window fallback in complex multiline scripts.
- Preserve default (`--parser none`) behavior and output compatibility.

Exit criteria:
- Parser mode enhancements covered by file-mode regression tests.
- Default mode contract remains unchanged.

## v0.13.0 — Policy profile migration polish

Scope:
- Add profile migration helpers/docs for existing `.shell-sentinel.yaml` users.
- Clarify precedence of `--policy-profile` + local policy file overrides.
- Add examples for team-wide onboarding patterns.

Exit criteria:
- Migration paths documented and tested.
- README + migration notes include profile adoption playbook.

## v0.14.0 — Ecosystem output compatibility

Scope:
- Add shellcheck-compatible output formatter for existing lint pipelines.
- Keep parity of severity mapping and line-level diagnostics.

Exit criteria:
- Formatter output covered by golden tests.
- README contains CI usage examples.
