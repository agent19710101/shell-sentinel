package sentinel

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Severity string

const (
	SeverityInfo Severity = "info"
	SeverityWarn Severity = "warn"
	SeverityHigh Severity = "high"
)

type Finding struct {
	Kind       string   `json:"kind"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Evidence   string   `json:"evidence,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
}

func Analyze(input string) []Finding {
	var findings []Finding
	if hasANSIEscape(input) {
		findings = append(findings, Finding{
			Kind:       "ansi-escape",
			Severity:   SeverityWarn,
			Message:    "ANSI escape sequence detected; output may hide or rewrite visible text",
			Suggestion: "Strip control characters before execution",
		})
	}

	for _, tok := range strings.Fields(input) {
		if f, ok := inspectURL(tok); ok {
			findings = append(findings, f)
		}
	}

	if looksLikePipeToShell(input) {
		findings = append(findings, Finding{
			Kind:       "pipe-to-shell",
			Severity:   SeverityHigh,
			Message:    "Remote content piped directly into shell interpreter",
			Evidence:   compact(input),
			Suggestion: "Download and inspect script before running",
		})
	}

	if looksLikeFetchInCommandSubstitution(input) {
		findings = append(findings, Finding{
			Kind:       "fetch-in-command-substitution",
			Severity:   SeverityHigh,
			Message:    "Remote content executed via command substitution",
			Evidence:   compact(input),
			Suggestion: "Avoid $(...) or backticks for remote content; save and inspect first",
		})
	}

	if hasSuspiciousUnicode(input) {
		findings = append(findings, Finding{
			Kind:       "mixed-script",
			Severity:   SeverityWarn,
			Message:    "Mixed-script text detected (possible homograph trick)",
			Suggestion: "Verify domains/identifiers are ASCII or expected script",
		})
	}

	return findings
}

func HighestSeverity(findings []Finding) Severity {
	level := SeverityInfo
	for _, f := range findings {
		switch f.Severity {
		case SeverityHigh:
			return SeverityHigh
		case SeverityWarn:
			if level == SeverityInfo {
				level = SeverityWarn
			}
		}
	}
	return level
}

func hasANSIEscape(s string) bool { return strings.Contains(s, "\x1b[") }

func inspectURL(token string) (Finding, bool) {
	u, err := url.Parse(token)
	if err != nil || u.Host == "" {
		return Finding{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Finding{}, false
	}
	for _, r := range host {
		if r > unicode.MaxASCII {
			return Finding{
				Kind:       "non-ascii-domain",
				Severity:   SeverityHigh,
				Message:    "URL host contains non-ASCII characters",
				Evidence:   host,
				Suggestion: "Use punycode/ASCII host when validating download sources",
			}, true
		}
	}
	return Finding{}, false
}

func looksLikePipeToShell(s string) bool {
	l := strings.ToLower(s)
	if !strings.Contains(l, "|") {
		return false
	}
	return (strings.Contains(l, "curl") || strings.Contains(l, "wget")) &&
		(strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "| zsh"))
}

func looksLikeFetchInCommandSubstitution(s string) bool {
	l := strings.ToLower(s)
	if !(strings.Contains(l, "$(") || strings.Contains(l, "`")) {
		return false
	}
	if !(strings.Contains(l, "curl") || strings.Contains(l, "wget")) {
		return false
	}
	return strings.Contains(l, "sh") || strings.Contains(l, "bash") || strings.Contains(l, "zsh")
}

func hasSuspiciousUnicode(s string) bool {
	var latin, nonLatin bool
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.In(r, unicode.Latin) {
			latin = true
		} else {
			nonLatin = true
		}
		if latin && nonLatin {
			return true
		}
	}
	return false
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
