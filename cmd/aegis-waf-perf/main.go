package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"aegis-waf/internal/perfbench"
)

func main() {
	requests := flag.Int("requests", 100, "requests per scenario")
	concurrency := flag.Int("concurrency", 8, "base concurrency")
	timeout := flag.Duration("timeout", 10*time.Second, "benchmark timeout per scenario")
	out := flag.String("out", "", "optional markdown report output path")
	flag.Parse()

	report, err := perfbench.RunLocalReport(context.Background(), perfbench.Options{
		RequestsPerScenario: *requests,
		Concurrency:         *concurrency,
		Timeout:             *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "run T128 benchmark: %v\n", err)
		os.Exit(1)
	}
	markdown := report.Markdown()
	if *out != "" {
		if err := os.WriteFile(*out, []byte(markdown), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Print(markdown)
}
