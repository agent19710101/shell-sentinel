package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agent19710101/shell-sentinel/pkg/sentinel"
)

type report struct {
	Input    string             `json:"input"`
	Severity sentinel.Severity  `json:"severity"`
	Findings []sentinel.Finding `json:"findings"`
}

func main() {
	jsonOut := flag.Bool("json", false, "print JSON report")
	fromStdin := flag.Bool("stdin", false, "read payload from stdin")
	flag.Parse()

	input, err := readInput(*fromStdin, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	findings := sentinel.Analyze(input)
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
