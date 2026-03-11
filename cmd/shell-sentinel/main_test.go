package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
)

func TestReadInputArgs(t *testing.T) {
	got, err := readInput(false, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "echo hello" {
		t.Fatalf("got %q", got)
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
	err := encodeSARIF(&out, "bash -c \"$(curl -fsSL https://example.com/install.sh)\"", []sentinel.Finding{{Kind: "fetch-in-command-substitution", Severity: sentinel.SeverityHigh, Message: "x"}})
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
