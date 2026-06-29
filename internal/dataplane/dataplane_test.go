package dataplane

import (
	"context"
	"strings"
	"testing"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

func TestNewMockEngine(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "mock"}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected engine")
	}
}

func TestNewDefaultsToMockEngine(t *testing.T) {
	engine, err := New(config.DataplaneConfig{}, nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, ok := engine.(*mockEngine); !ok {
		t.Fatalf("expected *mockEngine, got %T", engine)
	}
}

func TestNewNormalizesMode(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: " XDP ", FailOpen: true}, nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, ok := engine.(*xdpEngine); !ok {
		t.Fatalf("expected *xdpEngine, got %T", engine)
	}
}

func TestNewRejectsUnsupportedMode(t *testing.T) {
	_, err := New(config.DataplaneConfig{Mode: "other"}, zap.NewNop())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `unsupported dataplane mode "other"`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "expected mock or xdp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMockEngineStartStopIdempotent(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "mock"}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := engine.Start(ctx); err != nil {
			t.Fatalf("Start #%d returned error: %v", i+1, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := engine.Stop(ctx); err != nil {
			t.Fatalf("Stop #%d returned error: %v", i+1, err)
		}
	}
}

func TestMockEngineEvaluateAllows(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "mock"}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	result, err := engine.Evaluate(context.Background(), RequestMeta{
		Method: "GET",
		Path:   "/",
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("expected decision allow, got %q", result.Decision)
	}
	if result.Reason != mockPassReason {
		t.Fatalf("expected reason %q, got %q", mockPassReason, result.Reason)
	}
}
