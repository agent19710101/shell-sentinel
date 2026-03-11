# RELEASE_PLAN.md

## Goal
Ship a reliable `v0.x` line that is easy to adopt in local shells and CI, with clear output contracts for automation.

## v0.8.0 — Rule tuning + baseline + CI formatter (shipped)

Delivered:
- Expanded fetch-execution detection to cover additional shell forms (`exec`, `env VAR=...`, `-lc`) with constrained matching.
- Added baseline file support for accepted findings (`--baseline`, `--update-baseline`) with deterministic signatures.
- Added reviewdog formatter output (`--rdjsonl`) and action output wiring.

## v0.9.0 — Baseline governance + policy diagnostics (shipped in v0.9.1)

Delivered:
- Added baseline entry annotations (owner, justification, expiry) for `--update-baseline`.
- Added expiry-aware baseline filtering (expired entries no longer suppress findings).
- Added machine-readable summary stats in JSON output (`stats.total/high/warn/info`).
- Added policy schema validation with clearer error diagnostics (unknown fields + invalid `ignore_kinds`).
- Updated Action examples/docs for baseline governance defaults.

## v0.10.0 — File-aware scanning and integration polish (shipped)

Delivered:
- ✅ Added optional file-aware scanning mode (`--file`) for direct line mapping (`--rdjsonl`).
- ✅ Improved GitHub Action inputs for repo-wide scanning scenarios with explicit modes (`input`, `file`, `files`).
- ✅ Published migration notes (`MIGRATION.md`) and hardened release checklist (`RELEASE_CHECKLIST.md`).

Exit criteria:
- ✅ CI integration guide covers at least 2 common workflows.
- ✅ Action behavior verified end-to-end in CI via `scripts/validate-action.sh` and action docs/examples.
- ✅ Release checklist is documented and repeatable.

## v0.10.x follow-up hardening (in progress)

Delivered:
- ✅ Added multiline file-mode detection for split fetch execution patterns and improved action diagnostics (`v0.10.1`).
- ✅ Added heredoc shell-execution detection for remote fetch payloads with file-mode line mapping (`v0.10.2`).

Next:
- Expand obfuscated fetch-pipeline coverage (encoded/indirect chain variants).
