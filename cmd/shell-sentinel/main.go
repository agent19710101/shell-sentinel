package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
	"gopkg.in/yaml.v3"
)

type report struct {
	Input    string             `json:"input"`
	Severity sentinel.Severity  `json:"severity"`
	Stats    reportStats        `json:"stats"`
	Findings []sentinel.Finding `json:"findings"`
}

type reportStats struct {
	Total int `json:"total"`
	High  int `json:"high"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
}

type baselineFile struct {
	Version     int             `json:"version"`
	GeneratedAt string          `json:"generated_at"`
	Entries     []baselineEntry `json:"entries"`
}

type baselineEntry struct {
	Signature     string            `json:"signature"`
	Kind          string            `json:"kind"`
	Severity      sentinel.Severity `json:"severity"`
	Message       string            `json:"message"`
	Evidence      string            `json:"evidence,omitempty"`
	Owner         string            `json:"owner,omitempty"`
	Justification string            `json:"justification,omitempty"`
	ExpiresAt     string            `json:"expires_at,omitempty"`
}

type rdjsonlDiagnostic struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Code     struct {
		Value string `json:"value"`
	} `json:"code"`
	Location struct {
		Path  string `json:"path"`
		Range struct {
			Start struct {
				Line   int `json:"line"`
				Column int `json:"column"`
			} `json:"start"`
			End struct {
				Line   int `json:"line"`
				Column int `json:"column"`
			} `json:"end"`
		} `json:"range"`
	} `json:"location"`
}

func main() {
	jsonOut := flag.Bool("json", false, "print JSON report")
	sarifOut := flag.Bool("sarif", false, "print SARIF v2.1.0 report")
	rdjsonlOut := flag.Bool("rdjsonl", false, "print reviewdog rdjsonl diagnostics")
	fromStdin := flag.Bool("stdin", false, "read payload from stdin")
	inputFile := flag.String("file", "", "read payload from file (line-aware scanning)")
	policyPath := flag.String("policy", ".shell-sentinel.yaml", "path to policy file")
	noPolicy := flag.Bool("no-policy", false, "disable policy file loading")
	baselinePath := flag.String("baseline", "", "optional baseline file for accepted findings")
	updateBaseline := flag.Bool("update-baseline", false, "write/merge current findings into baseline file")
	baselineOwner := flag.String("baseline-owner", "", "owner annotation for newly added baseline entries")
	baselineJustification := flag.String("baseline-justification", "", "justification annotation for newly added baseline entries")
	baselineExpiry := flag.String("baseline-expiry", "", "expiry annotation (RFC3339) for newly added baseline entries")
	sourcePath := flag.String("source", "shell-input", "logical source path for rdjsonl diagnostics")
	sourceLine := flag.Int("line", 1, "line number for rdjsonl diagnostics")
	failOn := flag.String("fail-on", "high", "exit non-zero for findings at or above this severity: warn|high")
	hookShell := flag.String("hook", "", "print shell hook snippet (supported: bash, zsh, fish)")
	flag.Parse()

	if outputModeCount(*jsonOut, *sarifOut, *rdjsonlOut) > 1 {
		fmt.Fprintln(os.Stderr, "error: only one of --json, --sarif, --rdjsonl can be set")
		os.Exit(2)
	}

	if *hookShell != "" {
		h, err := renderHook(*hookShell)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(h)
		return
	}

	input, err := readInput(*fromStdin, *inputFile, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	policy, err := loadPolicy(*policyPath, *noPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	findings, findingLines := analyzeInput(input, policy, *inputFile)
	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if err := validateBaselineFlags(*updateBaseline, *baselineOwner, *baselineJustification, *baselineExpiry); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if *updateBaseline {
		baseline = mergeBaseline(baseline, findings, *baselineOwner, *baselineJustification, *baselineExpiry)
		if err := saveBaseline(*baselinePath, baseline); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	}

	findings = applyBaseline(findings, baseline)
	sev := sentinel.HighestSeverity(findings)
	r := report{Input: input, Severity: sev, Stats: summarizeFindings(findings), Findings: findings}

	switch {
	case *sarifOut:
		if err := encodeSARIF(os.Stdout, input, findings); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	case *rdjsonlOut:
		source := strings.TrimSpace(*sourcePath)
		line := *sourceLine
		if strings.TrimSpace(*inputFile) != "" {
			source = *inputFile
			line = 0
		}
		if err := encodeRDJSONL(os.Stdout, findings, findingLines, source, line); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	case *jsonOut:
		if err := encodeReportJSON(os.Stdout, r); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	default:
		printHuman(r)
	}

	fail, err := shouldFail(sev, *failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if fail {
		os.Exit(1)
	}
}

func outputModeCount(jsonOut, sarifOut, rdjsonlOut bool) int {
	count := 0
	if jsonOut {
		count++
	}
	if sarifOut {
		count++
	}
	if rdjsonlOut {
		count++
	}
	return count
}

func encodeReportJSON(w io.Writer, r report) error {
	if r.Findings == nil {
		r.Findings = []sentinel.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func encodeSARIF(w io.Writer, input string, findings []sentinel.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sentinel.SARIFReport(input, findings))
}

func encodeRDJSONL(w io.Writer, findings []sentinel.Finding, findingLines []int, source string, line int) error {
	if source == "" {
		source = "shell-input"
	}
	if line < 1 {
		line = 1
	}
	enc := json.NewEncoder(w)
	for i, f := range findings {
		findingLine := line
		if i < len(findingLines) && findingLines[i] > 0 {
			findingLine = findingLines[i]
		}
		d := rdjsonlDiagnostic{
			Message:  f.Message,
			Severity: rdSeverity(f.Severity),
		}
		d.Code.Value = f.Kind
		d.Location.Path = source
		d.Location.Range.Start.Line = findingLine
		d.Location.Range.Start.Column = 1
		d.Location.Range.End.Line = findingLine
		d.Location.Range.End.Column = 1
		if err := enc.Encode(d); err != nil {
			return err
		}
	}
	return nil
}

func analyzeInput(input string, policy *sentinel.Policy, filePath string) ([]sentinel.Finding, []int) {
	if strings.TrimSpace(filePath) == "" {
		findings := sentinel.AnalyzeWithPolicy(input, policy)
		lines := make([]int, len(findings))
		for i := range lines {
			lines[i] = 1
		}
		return findings, lines
	}

	var (
		findings []sentinel.Finding
		lines    []int
	)
	for i, line := range strings.Split(input, "\n") {
		lineFindings := sentinel.AnalyzeWithPolicy(line, policy)
		for _, f := range lineFindings {
			findings = append(findings, f)
			lines = append(lines, i+1)
		}
	}
	return findings, lines
}

func rdSeverity(sev sentinel.Severity) string {
	switch sev {
	case sentinel.SeverityHigh:
		return "ERROR"
	case sentinel.SeverityWarn:
		return "WARNING"
	default:
		return "INFO"
	}
}

func shouldFail(sev sentinel.Severity, failOn string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "high", "":
		return sev == sentinel.SeverityHigh, nil
	case "warn":
		return sev == sentinel.SeverityHigh || sev == sentinel.SeverityWarn, nil
	default:
		return false, fmt.Errorf("invalid --fail-on value %q (supported: warn, high)", failOn)
	}
}

func summarizeFindings(findings []sentinel.Finding) reportStats {
	stats := reportStats{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case sentinel.SeverityHigh:
			stats.High++
		case sentinel.SeverityWarn:
			stats.Warn++
		default:
			stats.Info++
		}
	}
	return stats
}

func validateBaselineFlags(update bool, owner, justification, expiry string) error {
	if !update {
		if strings.TrimSpace(owner) != "" || strings.TrimSpace(justification) != "" || strings.TrimSpace(expiry) != "" {
			return fmt.Errorf("baseline annotation flags require --update-baseline")
		}
		return nil
	}
	if strings.TrimSpace(expiry) != "" {
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(expiry)); err != nil {
			return fmt.Errorf("invalid --baseline-expiry value %q (expected RFC3339)", expiry)
		}
	}
	return nil
}

func baselineEntryExpired(entry baselineEntry, now time.Time) bool {
	exp := strings.TrimSpace(entry.ExpiresAt)
	if exp == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return false
	}
	return !t.After(now)
}

func readInput(fromStdin bool, filePath string, args []string) (string, error) {
	if strings.TrimSpace(filePath) != "" {
		if fromStdin {
			return "", fmt.Errorf("--file cannot be used with --stdin")
		}
		if len(args) > 0 {
			return "", fmt.Errorf("--file cannot be used with positional input")
		}
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read file %q: %w", filePath, err)
		}
		if strings.TrimSpace(string(b)) == "" {
			return "", fmt.Errorf("file input is empty")
		}
		return string(b), nil
	}
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
		return "", fmt.Errorf("no input provided; pass text arg, --stdin, or --file")
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
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse policy file %q: %w", path, err)
	}
	if err := validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("validate policy file %q: %w", path, err)
	}
	return &policy, nil
}

func validatePolicy(policy sentinel.Policy) error {
	allowedKinds := map[string]struct{}{
		"ansi-escape":                   {},
		"non-ascii-domain":              {},
		"pipe-to-shell":                 {},
		"fetch-in-command-substitution": {},
		"mixed-script":                  {},
	}
	invalidKinds := make([]string, 0)
	for _, k := range policy.IgnoreKinds {
		kind := strings.TrimSpace(k)
		if kind == "" {
			continue
		}
		if _, ok := allowedKinds[kind]; !ok {
			invalidKinds = append(invalidKinds, kind)
		}
	}
	if len(invalidKinds) > 0 {
		sort.Strings(invalidKinds)
		return fmt.Errorf("invalid ignore_kinds values: %s (supported: ansi-escape, non-ascii-domain, pipe-to-shell, fetch-in-command-substitution, mixed-script)", strings.Join(invalidKinds, ", "))
	}
	return nil
}

func loadBaseline(path string) (*baselineFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &baselineFile{Version: 1}, nil
		}
		return nil, fmt.Errorf("read baseline file %q: %w", path, err)
	}
	var baseline baselineFile
	if err := json.Unmarshal(b, &baseline); err != nil {
		return nil, fmt.Errorf("parse baseline file %q: %w", path, err)
	}
	if baseline.Version == 0 {
		baseline.Version = 1
	}
	return &baseline, nil
}

func mergeBaseline(b *baselineFile, findings []sentinel.Finding, owner, justification, expiry string) *baselineFile {
	if b == nil {
		b = &baselineFile{Version: 1}
	}
	seen := make(map[string]baselineEntry, len(b.Entries))
	for _, e := range b.Entries {
		seen[e.Signature] = e
	}
	for _, f := range findings {
		sig := findingSignature(f)
		if _, ok := seen[sig]; ok {
			continue
		}
		seen[sig] = baselineEntry{
			Signature:     sig,
			Kind:          f.Kind,
			Severity:      f.Severity,
			Message:       f.Message,
			Evidence:      f.Evidence,
			Owner:         strings.TrimSpace(owner),
			Justification: strings.TrimSpace(justification),
			ExpiresAt:     strings.TrimSpace(expiry),
		}
	}
	entries := make([]baselineEntry, 0, len(seen))
	for _, e := range seen {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Signature < entries[j].Signature })
	b.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	b.Entries = entries
	return b
}

func saveBaseline(path string, baseline *baselineFile) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("--update-baseline requires --baseline <path>")
	}
	if baseline == nil {
		baseline = &baselineFile{Version: 1}
	}
	out, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("write baseline file %q: %w", path, err)
	}
	return nil
}

func applyBaseline(findings []sentinel.Finding, baseline *baselineFile) []sentinel.Finding {
	if baseline == nil || len(baseline.Entries) == 0 {
		return findings
	}
	accepted := make(map[string]struct{}, len(baseline.Entries))
	for _, e := range baseline.Entries {
		if baselineEntryExpired(e, time.Now().UTC()) {
			continue
		}
		accepted[e.Signature] = struct{}{}
	}
	out := findings[:0]
	for _, f := range findings {
		if _, ok := accepted[findingSignature(f)]; ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

func findingSignature(f sentinel.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.Kind, string(f.Severity), f.Message, f.Evidence}, "\x1f")))
	return hex.EncodeToString(sum[:])
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
