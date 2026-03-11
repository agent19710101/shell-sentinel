# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## v0.8.0 — Rule tuning + baseline + CI formatter (shipped)

Delivered:
- Expanded fetch-execution detection to cover additional shell forms (`exec`, `env VAR=...`, `-lc`) with constrained matching.
- Added baseline file support for accepted findings (`--baseline`, `--update-baseline`) with deterministic signatures.
- Added reviewdog formatter output (`--rdjsonl`) and action output wiring.

## v0.9.0 — Baseline governance + policy diagnostics

Scope:
- Add baseline entry annotations (owner, justification, expiry).
- Add policy schema validation with clearer error diagnostics.
- Add machine-readable summary stats in output for dashboards.

Exit criteria:
- Baseline workflow supports audit metadata and expiry checks.
- Policy validation errors are deterministic and tested.
- Action examples updated for baseline governance.

## v0.10.0 — File-aware scanning and integration polish

Scope:
- Add optional file-aware scanning mode for direct line mapping.
- Improve GitHub Action inputs for repo-wide scanning scenarios.
- Publish migration notes and harden release checklist.

Exit criteria:
- CI integration guide covers at least 2 common workflows.
- Action behavior verified end-to-end in CI.
- Release checklist is documented and repeatable.
