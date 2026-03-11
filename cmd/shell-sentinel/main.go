package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
	"gopkg.in/yaml.v3"
)

type report struct {
	Input    string             `json:"input"`
	Severity sentinel.Severity  `json:"severity"`
	Findings []sentinel.Finding `json:"findings"`
}

func main() {
	jsonOut := flag.Bool("json", false, "print JSON report")
	fromStdin := flag.Bool("stdin", false, "read payload from stdin")
	policyPath := flag.String("policy", ".shell-sentinel.yaml", "path to policy file")
	noPolicy := flag.Bool("no-policy", false, "disable policy file loading")
	hookShell := flag.String("hook", "", "print shell hook snippet (supported: bash, zsh, fish)")
	flag.Parse()

	if *hookShell != "" {
		h, err := renderHook(*hookShell)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(h)
		return
	}

	input, err := readInput(*fromStdin, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	policy, err := loadPolicy(*policyPath, *noPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	findings := sentinel.AnalyzeWithPolicy(input, policy)
	sev := sentinel.HighestSeverity(findings)
	r := report{Input: input, Severity: sev, Findings: findings}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printHuman(r)
	}

	if sev == sentinel.SeverityHigh {
		os.Exit(1)
	}
}

func readInput(fromStdin bool, args []string) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		if strings.TrimSpace(string(b)) == "" {
			return "", fmt.Errorf("stdin input is empty")
		}
		return string(b), nil
	}
	if len(args) == 0 {
		return "", fmt.Errorf("no input provided; pass text arg or --stdin")
	}
	return strings.Join(args, " "), nil
}

func loadPolicy(path string, disabled bool) (*sentinel.Policy, error) {
	if disabled {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read policy file %q: %w", path, err)
	}
	var policy sentinel.Policy
	if err := yaml.Unmarshal(b, &policy); err != nil {
		return nil, fmt.Errorf("parse policy file %q: %w", path, err)
	}
	return &policy, nil
}

func printHuman(r report) {
	fmt.Printf("severity: %s\n", r.Severity)
	if len(r.Findings) == 0 {
		fmt.Println("status: no risky patterns detected")
		return
	}
	for i, f := range r.Findings {
		fmt.Printf("%d. [%s] %s\n", i+1, f.Severity, f.Message)
		if f.Evidence != "" {
			fmt.Printf("   evidence: %s\n", f.Evidence)
		}
		if f.Suggestion != "" {
			fmt.Printf("   suggestion: %s\n", f.Suggestion)
		}
	}
}

func renderHook(shell string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "bash":
		return `# shell-sentinel bash preexec warning hook
# Usage:
#   eval "$(shell-sentinel --hook bash)"
# Optional:
#   export SHELL_SENTINEL_ARGS="--policy ~/.shell-sentinel.yaml"
__shell_sentinel_preexec() {
  local cmd="$BASH_COMMAND"
  [[ -z "$cmd" ]] && return 0
  if ! shell-sentinel ${SHELL_SENTINEL_ARGS:-} "$cmd" >/dev/null 2>&1; then
    echo "[shell-sentinel] high-risk command detected: $cmd" >&2
  fi
}
trap '__shell_sentinel_preexec' DEBUG`, nil
	case "zsh":
		return `# shell-sentinel zsh preexec warning hook
# Usage:
#   eval "$(shell-sentinel --hook zsh)"
# Optional:
#   export SHELL_SENTINEL_ARGS="--policy ~/.shell-sentinel.yaml"
__shell_sentinel_preexec() {
  local cmd="$1"
  [[ -z "$cmd" ]] && return 0
  if ! shell-sentinel ${SHELL_SENTINEL_ARGS:-} "$cmd" >/dev/null 2>&1; then
    print -u2 -- "[shell-sentinel] high-risk command detected: $cmd"
  fi
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec __shell_sentinel_preexec`, nil
	case "fish":
		return `# shell-sentinel fish preexec warning hook
# Usage:
#   shell-sentinel --hook fish | source
# Optional:
#   set -gx SHELL_SENTINEL_ARGS "--policy ~/.shell-sentinel.yaml"
function __shell_sentinel_preexec --on-event fish_preexec
  set -l cmd $argv[1]
  if test -z "$cmd"
    return 0
  end
  if not shell-sentinel $SHELL_SENTINEL_ARGS "$cmd" >/dev/null 2>&1
    echo "[shell-sentinel] high-risk command detected: $cmd" >&2
  end
end`, nil
	default:
		return "", fmt.Errorf("unsupported shell hook %q (supported: bash, zsh, fish)", shell)
	}
}
