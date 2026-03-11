package main

import (
	"os"
	"path/filepath"
	"testing"
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

func TestRenderHookUnsupported(t *testing.T) {
	if _, err := renderHook("zsh"); err == nil {
		t.Fatalf("expected error for unsupported hook shell")
	}
}
