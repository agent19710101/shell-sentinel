# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## Delivered foundation (v0.8.0 → v0.15.0)

Shipped:
- Rule-coverage expansion for shell execution forms and encoded/compressed payload chains.
- Deterministic baseline workflows with governance metadata and expiry handling.
- Stable machine-readable outputs (`--json`, `--sarif`, `--rdjsonl`) with contract tests.
- File-aware scanning plus opt-in parser-backed file scanning (`--parser shell`) for higher precision.
- Team policy profiles (`strict`, `balanced`, `legacy`) for rollout ergonomics.
- Built-in policy migration templates (`--print-policy-template`) for fast `.shell-sentinel.yaml` bootstrap.
- CI/release hardening and action validation coverage.

## v0.13.0 — Ecosystem output compatibility (shipped)

Delivered:
- Added shellcheck-compatible formatter output via `--shellcheck`.
- Broadened ANSI detection beyond CSI-only escapes (OSC/other control sequences).
- Expanded multiline file-window matching to reduce split-chain false negatives.
- Pinned GitHub Action install default to a release tag for reproducibility.
- Centralized finding-kind registry in `pkg/sentinel` to prevent drift across validation/output paths.

## v0.14.0 — Parser diagnostics explainability (shipped)

Delivered:
- Added `--parser-debug` for `--file --parser shell` runs to print matched statement context to stderr.
- Kept default output contracts stable; debug output is opt-in only.
- Added validation/tests for debug-mode constraints and parser debug event coverage.
- Added README troubleshooting example for CI/debug workflows.

## v0.15.0 — Finding confidence metadata

Delivered:
- Added confidence bands per finding (`low|medium|high`) for gradual rollout workflows.
- Exposed confidence additively in JSON/SARIF/rdjsonl/shellcheck outputs without breaking existing contracts.

Exit criteria:
- Confidence mapping documented with tests.
- README/examples updated for confidence-aware automation.
