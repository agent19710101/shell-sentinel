package sentinel

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

type Severity string

const (
	SeverityInfo Severity = "info"
	SeverityWarn Severity = "warn"
	SeverityHigh Severity = "high"
)

const (
	KindANSIEscape                   = "ansi-escape"
	KindNonASCIIDomain               = "non-ascii-domain"
	KindPipeToShell                  = "pipe-to-shell"
	KindDecodedPipeToShell           = "decoded-pipe-to-shell"
	KindCompressedDecodedPipeToShell = "compressed-decoded-pipe-to-shell"
	KindFetchInCommandSubstitution   = "fetch-in-command-substitution"
	KindHeredocShellExec             = "heredoc-shell-exec"
	KindMixedScript                  = "mixed-script"
)

var knownKinds = []string{
	KindANSIEscape,
	KindNonASCIIDomain,
	KindPipeToShell,
	KindDecodedPipeToShell,
	KindCompressedDecodedPipeToShell,
	KindFetchInCommandSubstitution,
	KindHeredocShellExec,
	KindMixedScript,
}

type Finding struct {
	Kind       string   `json:"kind"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Evidence   string   `json:"evidence,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
}

type Policy struct {
	AllowDomains []string `yaml:"allow_domains"`
	IgnoreKinds  []string `yaml:"ignore_kinds"`
}

var shellExecFetchPattern = regexp.MustCompile(`(?i)\b(?:(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*|exec\s+)*(?:sh|bash|zsh|dash|ksh)\b\s+-[lc]+\s+["']?[^"']*(?:\$\([^)]*\b(?:curl|wget)\b[^)]*\)|` + "`[^`]*\\b(?:curl|wget)\\b[^`]*`" + `)[^"']*["']?`)
var heredocShellExecPattern = regexp.MustCompile(`(?is)\b(?:sh|bash|zsh|dash|ksh)\b[^\n]*<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*['"]?`)
var ansiEscapePattern = regexp.MustCompile("\\x1b(?:\\[[0-?]*[ -/]*[@-~]|\\][^\\x1b\\x07]*(?:\\x07|\\x1b\\\\)|[@-Z\\\\-_])")

func Analyze(input string) []Finding {
	return AnalyzeWithPolicy(input, nil)
}

func AnalyzeWithPolicy(input string, policy *Policy) []Finding {
	var findings []Finding
	if hasANSIEscape(input) {
		findings = append(findings, Finding{
			Kind:       KindANSIEscape,
			Severity:   SeverityWarn,
			Message:    "ANSI escape sequence detected; output may hide or rewrite visible text",
			Suggestion: "Strip control characters before execution",
		})
	}

	for _, tok := range strings.Fields(input) {
		if f, ok := inspectURL(tok, policy); ok {
			findings = append(findings, f)
		}
	}

	if looksLikePipeToShell(input) {
		findings = append(findings, Finding{
			Kind:       KindPipeToShell,
			Severity:   SeverityHigh,
			Message:    "Remote content piped directly into shell interpreter",
			Evidence:   compact(input),
			Suggestion: "Download and inspect script before running",
		})
	}

	if looksLikeDecodedPipeToShell(input) {
		findings = append(findings, Finding{
			Kind:       KindDecodedPipeToShell,
			Severity:   SeverityHigh,
			Message:    "Decoded payload piped into shell interpreter",
			Evidence:   compact(input),
			Suggestion: "Decode to a file and review content before execution",
		})
	}

	if looksLikeCompressedDecodePipeToShell(input) {
		findings = append(findings, Finding{
			Kind:       KindCompressedDecodedPipeToShell,
			Severity:   SeverityHigh,
			Message:    "Compressed payload decoded and piped into shell interpreter",
			Evidence:   compact(input),
			Suggestion: "Decompress to a file and review content before execution",
		})
	}

	if looksLikeFetchInCommandSubstitution(input) {
		findings = append(findings, Finding{
			Kind:       KindFetchInCommandSubstitution,
			Severity:   SeverityHigh,
			Message:    "Remote content executed via command substitution",
			Evidence:   compact(input),
			Suggestion: "Avoid $(...) or backticks for remote content; save and inspect first",
		})
	}

	if hasSuspiciousUnicode(input) {
		findings = append(findings, Finding{
			Kind:       KindMixedScript,
			Severity:   SeverityWarn,
			Message:    "Mixed-script text detected (possible homograph trick)",
			Suggestion: "Verify domains/identifiers are ASCII or expected script",
		})
	}

	if looksLikeHeredocShellExec(input) {
		findings = append(findings, Finding{
			Kind:       KindHeredocShellExec,
			Severity:   SeverityHigh,
			Message:    "Heredoc content appears to execute remote-fetched script",
			Evidence:   compact(input),
			Suggestion: "Avoid executing heredoc content that fetches remote scripts; save and review first",
		})
	}

	return filterIgnoredFindings(findings, policy)
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

func hasANSIEscape(s string) bool { return ansiEscapePattern.MatchString(s) }

func inspectURL(token string, policy *Policy) (Finding, bool) {
	u, err := url.Parse(token)
	if err != nil || u.Host == "" {
		return Finding{}, false
	}
	host := u.Hostname()
	if host == "" || isAllowedDomain(host, policy) {
		return Finding{}, false
	}

	for _, r := range host {
		if r > unicode.MaxASCII {
			asciiHost, convErr := idna.Lookup.ToASCII(host)
			if convErr != nil {
				asciiHost = "<conversion-failed>"
			}
			score := confusableScore(host)
			return Finding{
				Kind:       KindNonASCIIDomain,
				Severity:   SeverityHigh,
				Message:    fmt.Sprintf("URL host contains non-ASCII characters (punycode: %s, confusable-score: %d/100)", asciiHost, score),
				Evidence:   host,
				Suggestion: "Use punycode/ASCII host when validating download sources",
			}, true
		}
	}
	return Finding{}, false
}

func looksLikePipeToShell(s string) bool {
	l := normalizedShellText(s)
	if !strings.Contains(l, "|") {
		return false
	}
	return (strings.Contains(l, "curl") || strings.Contains(l, "wget")) &&
		(strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "| zsh"))
}

func looksLikeFetchInCommandSubstitution(s string) bool {
	return shellExecFetchPattern.MatchString(s)
}

func looksLikeDecodedPipeToShell(s string) bool {
	l := normalizedShellText(s)
	if !(strings.Contains(l, "base64 -d") || strings.Contains(l, "base64 --decode") || strings.Contains(l, "openssl base64 -d")) {
		return false
	}
	return strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "| zsh")
}

func looksLikeCompressedDecodePipeToShell(s string) bool {
	l := normalizedShellText(s)
	hasCompressedDecode := strings.Contains(l, "gzip -d") || strings.Contains(l, "gunzip") ||
		strings.Contains(l, "xz -d") || strings.Contains(l, "unxz")
	if !hasCompressedDecode {
		return false
	}
	return strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "| zsh")
}

func looksLikeHeredocShellExec(s string) bool {
	if !heredocShellExecPattern.MatchString(s) {
		return false
	}
	l := normalizedShellText(s)
	if !(strings.Contains(l, "curl") || strings.Contains(l, "wget")) {
		return false
	}
	return strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "| zsh") ||
		strings.Contains(l, "$(curl") || strings.Contains(l, "$(wget") ||
		strings.Contains(l, "`curl") || strings.Contains(l, "`wget")
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

func normalizedShellText(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func confusableScore(host string) int {
	score := 0
	var latin, nonLatin bool
	for _, r := range host {
		if r > unicode.MaxASCII {
			score += 20
		}
		if unicode.IsLetter(r) {
			if unicode.In(r, unicode.Latin) {
				latin = true
			} else {
				nonLatin = true
			}
		}
		if strings.ContainsRune("аеорсхуіј", unicode.ToLower(r)) { // common Cyrillic lookalikes
			score += 8
		}
	}
	if latin && nonLatin {
		score += 25
	}
	if score > 100 {
		return 100
	}
	return score
}

func isAllowedDomain(host string, policy *Policy) bool {
	if policy == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, d := range policy.AllowDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func KnownKinds() []string {
	out := make([]string, len(knownKinds))
	copy(out, knownKinds)
	return out
}

func IsKnownKind(kind string) bool {
	for _, k := range knownKinds {
		if kind == k {
			return true
		}
	}
	return false
}

func filterIgnoredFindings(findings []Finding, policy *Policy) []Finding {
	if policy == nil || len(policy.IgnoreKinds) == 0 {
		return findings
	}
	ignored := make(map[string]struct{}, len(policy.IgnoreKinds))
	for _, k := range policy.IgnoreKinds {
		k = strings.TrimSpace(k)
		if k != "" {
			ignored[k] = struct{}{}
		}
	}
	filtered := findings[:0]
	for _, f := range findings {
		if _, ok := ignored[f.Kind]; ok {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}
