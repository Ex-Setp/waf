package featureloop

import (
	"context"
	"testing"
	"time"
)

func TestT129SemanticLoopClustersObservedAttacksAndPromotesStableRules(t *testing.T) {
	loop := NewSemanticLoop(SemanticLoopOptions{MinClusterSize: 2, StableHits: 3, ObservationWindow: time.Hour})
	ctx := context.Background()

	first, err := loop.Observe(ctx, SemanticObservation{Language: "sql", Payload: "select * from users where id=1 union select password from users", At: time.Now()})
	if err != nil {
		t.Fatalf("first Observe returned error: %v", err)
	}
	if len(first.Clusters) != 0 || len(first.GeneratedRules) != 0 {
		t.Fatalf("single observation should not generate cluster/rule: %#v", first)
	}

	second, err := loop.Observe(ctx, SemanticObservation{Language: "sql", Payload: "select name from members where id=2 union select token from sessions", At: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatalf("second Observe returned error: %v", err)
	}
	if len(second.Clusters) != 1 || len(second.GeneratedRules) != 1 {
		t.Fatalf("expected one clustered observation rule, got %#v", second)
	}
	if second.GeneratedRules[0].Action != RuleActionLog {
		t.Fatalf("new cluster rule action=%s, want log", second.GeneratedRules[0].Action)
	}

	for i := 0; i < 2; i++ {
		if _, err := loop.Observe(ctx, SemanticObservation{Language: "sql", Payload: "select email from accounts where id=3 union select secret from vault", At: time.Now().Add(time.Duration(i+2) * time.Minute)}); err != nil {
			t.Fatalf("stable Observe %d returned error: %v", i, err)
		}
	}
	stable, err := loop.Observe(ctx, SemanticObservation{Language: "sql", Payload: "select email from accounts where id=4 union select secret from vault", At: time.Now().Add(5 * time.Minute)})
	if err != nil {
		t.Fatalf("stable Observe returned error: %v", err)
	}
	if len(stable.PromotedRules) != 1 {
		t.Fatalf("expected one promoted rule after stable hits, got %#v", stable)
	}
	if stable.PromotedRules[0].Action != RuleActionDeny {
		t.Fatalf("promoted action=%s, want deny", stable.PromotedRules[0].Action)
	}
	if stable.PromotedRules[0].Hash == "" || stable.PromotedRules[0].RuleText == "" {
		t.Fatalf("promoted rule incomplete: %#v", stable.PromotedRules[0])
	}
}

func TestT129SemanticLoopSupportsJSSkeletonObservation(t *testing.T) {
	loop := NewSemanticLoop(SemanticLoopOptions{MinClusterSize: 2, StableHits: 2})
	ctx := context.Background()
	payloads := []string{
		"document.write(location.hash)",
		"document.write(location.search)",
	}
	var result SemanticLoopResult
	for _, payload := range payloads {
		var err error
		result, err = loop.Observe(ctx, SemanticObservation{Language: "js", Payload: payload})
		if err != nil {
			t.Fatalf("Observe(%q) error: %v", payload, err)
		}
	}
	if len(result.GeneratedRules) == 0 {
		t.Fatalf("expected JS observation rule, got %#v", result)
	}
	if result.GeneratedRules[0].Language != "js" {
		t.Fatalf("generated language=%s, want js", result.GeneratedRules[0].Language)
	}
}
