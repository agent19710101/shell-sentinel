# Migration Notes

## v0.10.0

### GitHub Action input mode is now explicit

The Action supports exactly one scan mode per run:

- `input`: scan a single inline shell payload
- `file`: scan one file path with `--file`
- `files`: scan multiple repo files via newline-separated git pathspecs

If zero or multiple modes are set, the Action exits with code `2`.

### Repo-wide scanning

Use `files` for common CI scenarios:

```yaml
- uses: agent19710101/shell-sentinel@v0.10.0
  with:
    files: |
      scripts/*.sh
      .github/workflows/*.yml
    fail-on: warn
```

Behavior:

- Resolves files with `git ls-files` for deterministic tracked-file scans.
- Aggregates all findings into one JSON report and one rdjsonl output.
- Returns non-zero if any scanned file reaches configured `fail-on` threshold.

### No breaking CLI changes

CLI flags and output contracts from `v0.9.x` remain compatible.

## v0.12.1

### Policy profile migration helper templates

Use built-in templates to bootstrap or refresh `.shell-sentinel.yaml` quickly:

```bash
# print all built-in templates
shell-sentinel --print-policy-template all

# print a specific template
shell-sentinel --print-policy-template strict > .shell-sentinel.yaml
```

Guidance:
- `strict`: no ignored finding kinds; highest-signal rollout.
- `balanced`: practical default with `mixed-script` ignored.
- `legacy`: preserves older behavior by ignoring decode-and-exec findings.

No breaking behavior changes for existing policy files.
