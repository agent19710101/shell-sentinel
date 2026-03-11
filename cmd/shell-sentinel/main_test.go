package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
)

func TestReadInputArgs(t *testing.T) {
	got, err := readInput(false, "", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "echo hello" {
		t.Fatalf("got %q", got)
	}
}

func TestReadInputFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "payload.sh")
	if err := os.WriteFile(path, []byte("curl https://example.com/install.sh | sh\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	got, err := readInput(false, path, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(got, "curl https://example.com") {
		t.Fatalf("unexpected file content: %q", got)
	}
}

func TestReadInputFileConflicts(t *testing.T) {
	if _, err := readInput(true, "payload.sh", nil); err == nil {
		t.Fatalf("expected --file with --stdin to fail")
	}
	if _, err := readInput(false, "payload.sh", []string{"echo", "x"}); err == nil {
		t.Fatalf("expected --file with args to fail")
	}
}

func TestAnalyzeInputFileLineMapping(t *testing.T) {
	input := "echo safe\ncurl https://example.com/install.sh | sh\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "none")
	if len(findings) == 0 {
		t.Fatalf("expected findings for risky line")
	}
	if len(findings) != len(lines) {
		t.Fatalf("expected matching findings/lines lengths")
	}
	for _, ln := range lines {
		if ln != 2 {
			t.Fatalf("expected line 2 mapping, got %d", ln)
		}
	}
}

func TestAnalyzeInputFileDetectsMultilineCommandSubstitution(t *testing.T) {
	input := "bash -c \"$(\ncurl -fsSL https://example.com/install.sh\n)\"\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "none")
	if len(findings) == 0 {
		t.Fatalf("expected findings for multiline input")
	}
	found := false
	for i, f := range findings {
		if f.Kind == "fetch-in-command-substitution" {
			found = true
			if lines[i] != 1 {
				t.Fatalf("expected multiline finding to map to start line 1, got %d", lines[i])
			}
		}
	}
	if !found {
		t.Fatalf("expected fetch-in-command-substitution finding, got %#v", findings)
	}
}

func TestAnalyzeInputFileDetectsSplitDecodedPipeAcrossWideWindow(t *testing.T) {
	input := "echo Y3VybCBodHRwczovL2V4YW1wbGUuY29tL2luc3RhbGwuc2ggfCBzaA== |\n  base64\n  -d\n  |\n  sh\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "none")
	found := false
	for i, f := range findings {
		if f.Kind == sentinel.KindDecodedPipeToShell {
			found = true
			if lines[i] < 1 || lines[i] > 2 {
				t.Fatalf("expected split decoded finding to map to early line, got %d", lines[i])
			}
		}
	}
	if !found {
		t.Fatalf("expected decoded-pipe-to-shell finding, got %#v", findings)
	}
}

func TestAnalyzeInputFileDetectsHeredocShellExec(t *testing.T) {
	input := "bash <<'EOF'\ncurl -fsSL https://example.com/install.sh | sh\nEOF\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "none")
	found := false
	for i, f := range findings {
		if f.Kind == "heredoc-shell-exec" {
			found = true
			if lines[i] != 1 {
				t.Fatalf("expected heredoc finding to map to line 1, got %d", lines[i])
			}
		}
	}
	if !found {
		t.Fatalf("expected heredoc-shell-exec finding, got %#v", findings)
	}
}

func TestLoadPolicyNotFoundReturnsNil(t *testing.T) {
	policy, err := loadPolicy("/definitely/missing-policy-file.yaml", false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if policy != nil {
		t.Fatalf("expected nil policy when file is missing")
	}
}

func TestLoadPolicyParsesPolicyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "policy.yaml")
	content := []byte("allow_domains:\n  - example.com\nignore_kinds:\n  - mixed-script\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	policy, err := loadPolicy(path, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(policy.AllowDomains) != 1 || policy.AllowDomains[0] != "example.com" {
		t.Fatalf("unexpected allow domains: %#v", policy.AllowDomains)
	}
	if len(policy.IgnoreKinds) != 1 || policy.IgnoreKinds[0] != "mixed-script" {
		t.Fatalf("unexpected ignore kinds: %#v", policy.IgnoreKinds)
	}
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "policy.yaml")
	content := []byte("allow_domains:\n  - example.com\nunknown_key: true\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := loadPolicy(path, false)
	if err == nil {
		t.Fatalf("expected unknown field validation error")
	}
	if !strings.Contains(err.Error(), "field unknown_key not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadPolicyRejectsUnknownIgnoreKinds(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "policy.yaml")
	content := []byte("ignore_kinds:\n  - mixed-script\n  - not-a-real-kind\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := loadPolicy(path, false)
	if err == nil {
		t.Fatalf("expected invalid ignore_kinds validation error")
	}
	if !strings.Contains(err.Error(), "invalid ignore_kinds values") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateParserMode(t *testing.T) {
	if err := validateParserMode("shell"); err != nil {
		t.Fatalf("expected shell parser mode to be valid: %v", err)
	}
	if err := validateParserMode("bad"); err == nil {
		t.Fatalf("expected invalid parser mode error")
	}
}

func TestValidateParserDebug(t *testing.T) {
	if err := validateParserDebug(false, "", "none"); err != nil {
		t.Fatalf("expected disabled parser debug to pass: %v", err)
	}
	if err := validateParserDebug(true, "", "shell"); err == nil {
		t.Fatalf("expected --parser-debug to require --file")
	}
	if err := validateParserDebug(true, "payload.sh", "none"); err == nil {
		t.Fatalf("expected --parser-debug to require --parser shell")
	}
	if err := validateParserDebug(true, "payload.sh", "shell"); err != nil {
		t.Fatalf("expected valid parser debug setup: %v", err)
	}
}

func TestBuildParserDebugEvents(t *testing.T) {
	input := "if true; then\n  curl -fsSL https://example.com/install.sh | sh\nfi\n"
	events := buildParserDebugEvents(input, nil)
	if len(events) == 0 {
		t.Fatalf("expected parser debug events")
	}
	found := false
	for _, e := range events {
		if e.Line != 2 {
			continue
		}
		if strings.Contains(strings.Join(e.Kinds, ","), sentinel.KindPipeToShell) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected parser debug event with pipe-to-shell kind on line 2, got %#v", events)
	}
}

func TestAnalyzeInputWithShellParserMode(t *testing.T) {
	input := "echo ok\n\ncurl -fsSL https://example.com/payload.sh.gz | gzip -d | sh\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "shell")
	if len(findings) == 0 || len(findings) != len(lines) {
		t.Fatalf("expected mapped findings from shell parser mode")
	}
	found := false
	for i, f := range findings {
		if f.Kind == "compressed-decoded-pipe-to-shell" {
			found = true
			if lines[i] != 3 {
				t.Fatalf("expected line 3, got %d", lines[i])
			}
		}
	}
	if !found {
		t.Fatalf("expected compressed-decoded-pipe-to-shell finding")
	}
}

func TestAnalyzeInputWithShellParserModeNestedControlFlowLineMapping(t *testing.T) {
	input := "if true; then\n  echo ok\n  curl -fsSL https://example.com/install.sh | sh\nfi\n"
	findings, lines := analyzeInput(input, nil, "payload.sh", "shell")
	if len(findings) == 0 || len(findings) != len(lines) {
		t.Fatalf("expected mapped findings from shell parser mode")
	}
	foundPipe := false
	foundLine3 := false
	for i, f := range findings {
		if f.Kind != "pipe-to-shell" {
			continue
		}
		foundPipe = true
		if lines[i] == 3 {
			foundLine3 = true
		}
	}
	if !foundPipe {
		t.Fatalf("expected pipe-to-shell finding")
	}
	if !foundLine3 {
		t.Fatalf("expected at least one pipe-to-shell finding mapped to line 3")
	}
}

func TestApplyPolicyProfileLegacy(t *testing.T) {
	policy, err := applyPolicyProfile(&sentinel.Policy{}, "legacy")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(policy.IgnoreKinds) == 0 {
		t.Fatalf("expected legacy profile to set ignore kinds")
	}
}

func TestRenderPolicyTemplate(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		want    string
	}{
		{name: "strict", profile: "strict", want: "ignore_kinds: []"},
		{name: "balanced", profile: "balanced", want: "mixed-script"},
		{name: "legacy", profile: "legacy", want: "decoded-pipe-to-shell"},
		{name: "all", profile: "all", want: "# strict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := renderPolicyTemplate(tt.profile)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("expected output to contain %q, got %q", tt.want, got)
			}
		})
	}
}

func TestRenderPolicyTemplateUnsupported(t *testing.T) {
	if _, err := renderPolicyTemplate("weird"); err == nil {
		t.Fatalf("expected error for unsupported template profile")
	}
}

func TestRenderHookBash(t *testing.T) {
	hook, err := renderHook("bash")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if hook == "" {
		t.Fatalf("expected non-empty hook")
	}
}

func TestRenderHookZsh(t *testing.T) {
	hook, err := renderHook("zsh")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if hook == "" {
		t.Fatalf("expected non-empty hook")
	}
}

func TestRenderHookFish(t *testing.T) {
	hook, err := renderHook("fish")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if hook == "" {
		t.Fatalf("expected non-empty hook")
	}
}

func TestRenderHookUnsupported(t *testing.T) {
	if _, err := renderHook("powershell"); err == nil {
		t.Fatalf("expected error for unsupported hook shell")
	}
}

func TestShouldFailHigh(t *testing.T) {
	fail, err := shouldFail(sentinel.SeverityHigh, "high")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !fail {
		t.Fatalf("expected fail for high severity with fail-on high")
	}
}

func TestShouldFailWarnThreshold(t *testing.T) {
	fail, err := shouldFail(sentinel.SeverityWarn, "warn")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !fail {
		t.Fatalf("expected fail for warn severity with fail-on warn")
	}
}

func TestShouldFailInvalidThreshold(t *testing.T) {
	_, err := shouldFail(sentinel.SeverityWarn, "info")
	if err == nil {
		t.Fatalf("expected error for invalid fail-on value")
	}
}

func TestOutputModeCount(t *testing.T) {
	if got := outputModeCount(true, false, true, false); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}
	if got := outputModeCount(false, false, false, true); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
}

func TestEncodeReportJSONNoFindingsUsesEmptyArray(t *testing.T) {
	var out bytes.Buffer
	err := encodeReportJSON(&out, report{Input: "go test ./...", Severity: sentinel.SeverityInfo})
	if err != nil {
		t.Fatalf("encode json: %v", err)
	}
	var decoded struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if decoded.Findings == nil {
		t.Fatalf("expected findings array, got nil")
	}
	if len(decoded.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(decoded.Findings))
	}
}

func TestEncodeReportJSONFindingsPresent(t *testing.T) {
	var out bytes.Buffer
	err := encodeReportJSON(&out, report{Input: "curl x | sh", Severity: sentinel.SeverityHigh, Findings: []sentinel.Finding{{Kind: "pipe-to-shell", Severity: sentinel.SeverityHigh, Message: "x"}}})
	if err != nil {
		t.Fatalf("encode json: %v", err)
	}
	var decoded struct {
		Findings []sentinel.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(decoded.Findings))
	}
}

func TestEncodeSARIF(t *testing.T) {
	var out bytes.Buffer
	err := encodeSARIF(&out, "bash -c \"$(curl -fsSL https://example.com/install.sh)\"", []sentinel.Finding{{Kind: sentinel.KindFetchInCommandSubstitution, Severity: sentinel.SeverityHigh, Message: "x"}})
	if err != nil {
		t.Fatalf("encode sarif: %v", err)
	}
	var decoded struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode sarif: %v", err)
	}
	if decoded.Version != "2.1.0" {
		t.Fatalf("unexpected sarif version: %s", decoded.Version)
	}
}

func TestEncodeRDJSONL(t *testing.T) {
	var out bytes.Buffer
	err := encodeRDJSONL(&out, []sentinel.Finding{{Kind: sentinel.KindPipeToShell, Severity: sentinel.SeverityHigh, Confidence: sentinel.ConfidenceHigh, Message: "x"}}, []int{5}, "script.sh", 1)
	if err != nil {
		t.Fatalf("encode rdjsonl: %v", err)
	}
	line := strings.TrimSpace(out.String())
	if line == "" {
		t.Fatalf("expected output")
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("decode rdjsonl: %v", err)
	}
	if decoded["severity"] != "ERROR" {
		t.Fatalf("unexpected severity: %v", decoded["severity"])
	}
	if decoded["confidence"] != "high" {
		t.Fatalf("unexpected confidence: %v", decoded["confidence"])
	}
}

func TestEncodeShellcheck(t *testing.T) {
	var out bytes.Buffer
	err := encodeShellcheck(&out, []sentinel.Finding{{Kind: sentinel.KindPipeToShell, Severity: sentinel.SeverityHigh, Confidence: sentinel.ConfidenceHigh, Message: "x"}}, []int{7}, "script.sh", 1)
	if err != nil {
		t.Fatalf("encode shellcheck: %v", err)
	}
	got := strings.TrimSpace(out.String())
	if got != "script.sh:7:1: error: x (confidence: high) [pipe-to-shell]" {
		t.Fatalf("unexpected shellcheck output: %q", got)
	}
}

func TestBaselineRoundtripAndApply(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "baseline.json")
	findings := []sentinel.Finding{{Kind: "pipe-to-shell", Severity: sentinel.SeverityHigh, Message: "x", Evidence: "curl | sh"}}

	b, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	b = mergeBaseline(b, findings, "", "", "")
	if err := saveBaseline(path, b); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	reloaded, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("reload baseline: %v", err)
	}
	filtered := applyBaseline(findings, reloaded)
	if len(filtered) != 0 {
		t.Fatalf("expected findings suppressed by baseline, got %d", len(filtered))
	}
}

func TestMergeBaselineAnnotations(t *testing.T) {
	findings := []sentinel.Finding{{Kind: "pipe-to-shell", Severity: sentinel.SeverityHigh, Message: "x", Evidence: "curl | sh"}}
	b := mergeBaseline(nil, findings, "sec-team", "accepted for controlled installer", "2099-01-01T00:00:00Z")
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 baseline entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Owner != "sec-team" || b.Entries[0].Justification == "" || b.Entries[0].ExpiresAt == "" {
		t.Fatalf("expected annotation fields to be persisted, got %#v", b.Entries[0])
	}
}

func TestApplyBaselineSkipsExpiredEntries(t *testing.T) {
	f := sentinel.Finding{Kind: "pipe-to-shell", Severity: sentinel.SeverityHigh, Message: "x", Evidence: "curl | sh"}
	b := &baselineFile{Version: 1, Entries: []baselineEntry{{
		Signature: findingSignature(f),
		Kind:      f.Kind,
		Severity:  f.Severity,
		Message:   f.Message,
		Evidence:  f.Evidence,
		ExpiresAt: "2000-01-01T00:00:00Z",
	}}}
	filtered := applyBaseline([]sentinel.Finding{f}, b)
	if len(filtered) != 1 {
		t.Fatalf("expected expired baseline entry to be ignored")
	}
}

func TestValidateBaselineFlags(t *testing.T) {
	if err := validateBaselineFlags(false, "team", "", ""); err == nil {
		t.Fatalf("expected annotation flags without update-baseline to fail")
	}
	if err := validateBaselineFlags(true, "", "", "not-a-date"); err == nil {
		t.Fatalf("expected invalid expiry to fail")
	}
	if err := validateBaselineFlags(true, "team", "ok", "2099-01-01T00:00:00Z"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeReportJSONIncludesStats(t *testing.T) {
	var out bytes.Buffer
	r := report{Input: "x", Severity: sentinel.SeverityHigh, Stats: reportStats{Total: 2, High: 1, Warn: 1}, Findings: []sentinel.Finding{{Kind: "k", Severity: sentinel.SeverityHigh, Message: "m"}}}
	if err := encodeReportJSON(&out, r); err != nil {
		t.Fatalf("encode json: %v", err)
	}
	var decoded struct {
		Stats reportStats `json:"stats"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if decoded.Stats.Total != 2 || decoded.Stats.High != 1 || decoded.Stats.Warn != 1 {
		t.Fatalf("unexpected stats: %#v", decoded.Stats)
	}
}

func TestFindingSignatureStability(t *testing.T) {
	tests := []struct {
		name    string
		finding sentinel.Finding
		want    string
	}{
		{
			name: "pipe-to-shell",
			finding: sentinel.Finding{
				Kind:     "pipe-to-shell",
				Severity: sentinel.SeverityHigh,
				Message:  "Remote content piped directly into shell interpreter",
				Evidence: "curl https://x | sh",
			},
			want: "9a74c5d7eaf1187cc37a94ba2191eae3d9d7a94339efc97ff99f8eeb93565bf2",
		},
		{
			name: "non-ascii-domain",
			finding: sentinel.Finding{
				Kind:     "non-ascii-domain",
				Severity: sentinel.SeverityHigh,
				Message:  "URL host contains non-ASCII characters (punycode: xn--pple-43d.com, confusable-score: 33/100)",
				Evidence: "аpple.com",
			},
			want: "17811129376306fdd461e8535e73dbb1863b257abcf90d087eec8fd1ff774cde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findingSignature(tt.finding); got != tt.want {
				t.Fatalf("findingSignature() = %q, want %q", got, tt.want)
			}
		})
	}
}
