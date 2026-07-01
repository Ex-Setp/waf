package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aegis-waf/internal/securityeval"
)

func main() {
	rulesDir := flag.String("rules-dir", "", "directory containing Coraza SecRule .conf files")
	corpusDir := flag.String("corpus-dir", "", "security corpus directory")
	out := flag.String("out", "docs/security-coverage-report.md", "markdown report output path")
	baselinePath := flag.String("baseline", "", "optional baseline JSON path for regression comparison")
	writeBaselinePath := flag.String("write-baseline", "", "write current result as JSON baseline")
	maxBlockRateDrop := flag.Float64("max-block-rate-drop", securityeval.DefaultMaxBlockRateDrop, "maximum allowed attack block rate regression as decimal fraction")
	maxFPIncrease := flag.Int("max-fp-increase", securityeval.DefaultMaxFalsePositiveIncrease, "maximum allowed benign false positive increase")
	format := flag.String("format", "markdown", "output format: markdown or json")
	flag.Parse()

	result, err := securityeval.Evaluate(context.Background(), securityeval.Options{
		RulesDir:                 *rulesDir,
		CorpusDir:                *corpusDir,
		MaxBlockRateDrop:         *maxBlockRateDrop,
		MaxFalsePositiveIncrease: *maxFPIncrease,
	})
	if err != nil {
		fatal(err)
	}
	var baseline *securityeval.Result
	if *baselinePath != "" {
		loaded, err := securityeval.ReadBaseline(*baselinePath)
		if err != nil {
			fatal(err)
		}
		baseline = &loaded
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatal(err)
	}
	var content []byte
	switch *format {
	case "markdown", "md":
		content = []byte(result.MarkdownWithBaseline(baseline))
	case "json":
		payload := struct {
			Result     securityeval.Result     `json:"result"`
			Comparison securityeval.Comparison `json:"comparison"`
		}{
			Result:     result,
			Comparison: securityeval.CompareResults(result, baseline),
		}
		content, err = json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("unsupported format %q", *format))
	}
	if err := os.WriteFile(*out, content, 0o644); err != nil {
		fatal(err)
	}
	if *writeBaselinePath != "" {
		baselineJSON, err := result.JSON()
		if err != nil {
			fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(*writeBaselinePath), 0o755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*writeBaselinePath, baselineJSON, 0o644); err != nil {
			fatal(err)
		}
	}
	if err := result.ValidateWithBaseline(baseline); err != nil {
		fatal(err)
	}
	fmt.Printf("security coverage report written to %s\n", *out)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
