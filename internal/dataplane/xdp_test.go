package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

func TestXDPEngineStartFailOpen(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: true}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = engine.Start(context.Background())
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	xdp := engine.(*xdpEngine)
	if !xdp.started {
		t.Fatal("expected engine to be marked started in fail-open mode")
	}
	if xdp.program.Status().Reason == "" {
		t.Fatal("expected xdp status reason to be set")
	}
}

func TestXDPEngineStartFailClosed(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: false}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = engine.Start(context.Background())
	requireExpectedXDPStartError(t, err)
	if !strings.Contains(err.Error(), "xdp load unavailable") && !strings.Contains(err.Error(), "xdp attach unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestXDPEngineEvaluateFailOpenAllows(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: true}, zap.NewNop())
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
	if result.Reason != xdpFailOpenReason {
		t.Fatalf("expected reason %q, got %q", xdpFailOpenReason, result.Reason)
	}
}

func TestXDPEngineEvaluateFailClosedBlocksWithError(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: false}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	result, err := engine.Evaluate(context.Background(), RequestMeta{
		Method: "GET",
		Path:   "/",
	})
	if !errors.Is(err, errXDPNotImplemented) {
		t.Fatalf("expected errXDPNotImplemented, got %v", err)
	}
	if result.Decision != DecisionBlock {
		t.Fatalf("expected decision block, got %q", result.Decision)
	}
	if result.Reason != xdpFailClosedReason {
		t.Fatalf("expected reason %q, got %q", xdpFailClosedReason, result.Reason)
	}
}

func TestXDPEngineStopIdempotent(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: true}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := engine.Stop(ctx); err != nil {
			t.Fatalf("Stop #%d returned error: %v", i+1, err)
		}
	}
}

func TestXDPProgramStatus(t *testing.T) {
	program := newXDPProgram(config.DataplaneConfig{InterfaceName: "eth0"})
	status := program.Status()

	if status.InterfaceName != "eth0" {
		t.Fatalf("expected interface eth0, got %q", status.InterfaceName)
	}
	if status.Platform == "" {
		t.Fatal("expected platform to be set")
	}
	if status.Loaded || status.Attached {
		t.Fatal("expected skeleton status to stay unloaded and unattached")
	}
	if status.Reason == "" {
		t.Fatal("expected status reason")
	}
}

func TestLinuxDataplanePackageCrossCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compile in short mode")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "dataplane-linux.test")
	cmd := exec.Command("go", "test", "-c", "-o", outputPath, "./internal/dataplane")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
		"GOCACHE="+filepath.Join(repoRoot, ".gocache"),
		"GOMODCACHE="+filepath.Join(repoRoot, ".gomodcache"),
		"GOPATH="+filepath.Join(repoRoot, ".gopath"),
		"GOPROXY=https://goproxy.cn,direct",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("linux dataplane package cross-compile failed: %v\n%s", err, output)
	}
}
