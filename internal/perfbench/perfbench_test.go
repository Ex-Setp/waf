package perfbench

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestT128ReportCoversRequiredRealLinkScenariosAndMetrics(t *testing.T) {
	report, err := RunLocalReport(context.Background(), Options{RequestsPerScenario: 8, Concurrency: 2, Timeout: time.Second})
	if err != nil {
		t.Fatalf("RunLocalReport returned error: %v", err)
	}

	wantScenarios := []string{"pure-reverse-proxy", "rule-detection", "cc-protection", "semantic-analysis", "large-body", "high-concurrency", "slow-upstream"}
	for _, name := range wantScenarios {
		result, ok := report.Scenario(name)
		if !ok {
			t.Fatalf("missing scenario %q in %#v", name, report.Scenarios)
		}
		if result.Requests == 0 || result.QPS <= 0 {
			t.Fatalf("scenario %s missing throughput metrics: %#v", name, result)
		}
		if result.Latency.P50 <= 0 || result.Latency.P95 <= 0 || result.Latency.P99 <= 0 {
			t.Fatalf("scenario %s missing latency percentiles: %#v", name, result.Latency)
		}
		if result.CPU.Percent < 0 || result.Memory.AllocBytes == 0 || result.GC.NumGC < 0 {
			t.Fatalf("scenario %s missing runtime metrics: %#v", name, result)
		}
		if result.LogQueue.Depth < 0 || result.Upstream.ErrorRate < 0 || result.Upstream.ErrorRate > 1 {
			t.Fatalf("scenario %s missing queue/upstream metrics: %#v", name, result)
		}
	}

	markdown := report.Markdown()
	for _, token := range []string{"QPS", "P50", "P95", "P99", "CPU", "内存", "GC", "日志队列", "upstream错误率"} {
		if !strings.Contains(markdown, token) {
			t.Fatalf("markdown report missing %q:\n%s", token, markdown)
		}
	}
}
