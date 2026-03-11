package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
	"gopkg.in/yaml.v3"
)

type report struct {
	Input    string             `json:"input"`
	Severity sentinel.Severity  `json:"severity"`
	Findings []sentinel.Finding `json:"findings"`
}

func main() {
	jsonOut := flag.Bool("json", false, "print JSON report")
	fromStdin := flag.Bool("stdin", false, "read payload from stdin")
	policyPath := flag.String("policy", ".shell-sentinel.yaml", "path to policy file")
	noPolicy := flag.Bool("no-policy", false, "disable policy file loading")
	flag.Parse()

	input, err := readInput(*fromStdin, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	policy, err := loadPolicy(*policyPath, *noPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	findings := sentinel.AnalyzeWithPolicy(input, policy)
	sev := sentinel.HighestSeverity(findings)
	r := report{Input: input, Severity: sev, Findings: findings}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printHuman(r)
	}

	if sev == sentinel.SeverityHigh {
		os.Exit(1)
	}
}

func readInput(fromStdin bool, args []string) (string, error) {
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
		return "", fmt.Errorf("no input provided; pass text arg or --stdin")
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
	if err := yaml.Unmarshal(b, &policy); err != nil {
		return nil, fmt.Errorf("parse policy file %q: %w", path, err)
	}
	return &policy, nil
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
