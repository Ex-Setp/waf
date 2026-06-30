package main

import (
	"context"
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
	flag.Parse()

	result, err := securityeval.Evaluate(context.Background(), securityeval.Options{RulesDir: *rulesDir, CorpusDir: *corpusDir})
	if err != nil {
		fatal(err)
	}
	if err := result.Validate(); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, []byte(result.Markdown()), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("security coverage report written to %s\n", *out)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
