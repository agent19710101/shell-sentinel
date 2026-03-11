# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## v0.8.0 — Rule tuning + safer defaults

Scope:
- Expand fetch-execution detection to cover additional shell forms with low false positives.
- Add optional strict mode profile for CI/security pipelines.
- Improve finding metadata (rule IDs and remediation hints).

Exit criteria:
- New rule coverage has regression tests for true/false positives.
- README includes strict profile examples.
- No JSON/SARIF contract regressions.

## v0.9.0 — Policy ergonomics + baseline workflows

Scope:
- Add baseline file support (suppress accepted findings with explicit review trail).
- Add policy schema validation with clearer error diagnostics.
- Add machine-readable summary stats in output for dashboards.

Exit criteria:
- Baseline flow documented for local + CI usage.
- Policy validation errors are deterministic and tested.
- Action examples updated for baseline-aware checks.

## v0.10.0 — Integration polish

Scope:
- Add reviewdog/problem-matcher friendly formatter.
- Improve GitHub Action inputs for repo-wide scanning scenarios.
- Publish migration notes and harden release checklist.

Exit criteria:
- CI integration guide covers at least 2 common workflows.
- Action behavior verified end-to-end in CI.
- Release checklist is documented and repeatable.
