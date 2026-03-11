package sentinel

import "fmt"

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool               `json:"tool"`
	Artifacts          []sarifArtifact         `json:"artifacts,omitempty"`
	Results            []sarifResult           `json:"results,omitempty"`
	Invocations        []sarifInvocation       `json:"invocations,omitempty"`
	ColumnKind         string                  `json:"columnKind,omitempty"`
	OriginalURIBaseIDs map[string]sarifURIBase `json:"originalUriBaseIds,omitempty"`
}

type sarifURIBase struct {
	URI string `json:"uri"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription sarifMessageText `json:"shortDescription,omitempty"`
}

type sarifMessageText struct {
	Text string `json:"text"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessageText `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifRegion struct {
	StartLine int              `json:"startLine"`
	Snippet   sarifMessageText `json:"snippet,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

func SARIFReport(input string, findings []Finding) any {
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(findings))
	snippet := compact(input)

	for _, f := range findings {
		if _, ok := rulesByID[f.Kind]; !ok {
			rulesByID[f.Kind] = sarifRule{
				ID:               f.Kind,
				Name:             f.Kind,
				ShortDescription: sarifMessageText{Text: f.Message},
			}
		}
		msg := f.Message
		if f.Evidence != "" {
			msg = fmt.Sprintf("%s (evidence: %s)", f.Message, f.Evidence)
		}
		results = append(results, sarifResult{
			RuleID:  f.Kind,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessageText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: "shell-input"},
					Region: sarifRegion{
						StartLine: 1,
						Snippet:   sarifMessageText{Text: snippet},
					},
				},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}

	return sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "shell-sentinel",
				InformationURI: "https://github.com/agent19710101/shell-sentinel",
				Rules:          rules,
			}},
			Artifacts:   []sarifArtifact{{Location: sarifArtifactLocation{URI: "shell-input"}}},
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
		}},
	}
}

func sarifLevel(sev Severity) string {
	switch sev {
	case SeverityHigh:
		return "error"
	case SeverityWarn:
		return "warning"
	default:
		return "note"
	}
}
