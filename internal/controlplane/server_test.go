package controlplane

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "aegis-waf/api/control/v1"
	"aegis-waf/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestHealthReturnsStatusAndVersion(t *testing.T) {
	server := New(config.ControlConfig{
		Network: "unix",
		Address: filepath.Join(t.TempDir(), "aegis-waf.sock"),
	}, "test-version")

	resp, err := server.Health(context.Background(), &controlv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if resp.GetStatus() != "SERVING" {
		t.Fatalf("expected SERVING status, got %q", resp.GetStatus())
	}
	if resp.GetVersion() != "test-version" {
		t.Fatalf("expected version test-version, got %q", resp.GetVersion())
	}
}

func TestStartStopUnixHealthRPC(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nested", "aegis-waf.sock")
	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err == nil {
		t.Fatal("expected stale socket write to fail before parent directory exists")
	}

	server := New(config.ControlConfig{
		Network: "unix",
		Address: socketPath,
	}, "rpc-version")

	if err := server.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	defer server.Stop()

	if _, err := os.Stat(filepath.Dir(socketPath)); err != nil {
		t.Fatalf("expected socket parent directory: %v", err)
	}

	conn := dialUnixControl(t, socketPath)
	defer conn.Close()

	client := controlv1.NewControlServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Health(ctx, &controlv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC returned error: %v", err)
	}
	if resp.GetStatus() != "SERVING" {
		t.Fatalf("expected SERVING status, got %q", resp.GetStatus())
	}
	if resp.GetVersion() != "rpc-version" {
		t.Fatalf("expected version rpc-version, got %q", resp.GetVersion())
	}
}

func TestStartUnixRemovesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "aegis-waf.sock")
	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale socket placeholder: %v", err)
	}

	server := New(config.ControlConfig{
		Network: "unix",
		Address: socketPath,
	}, "test")

	if err := server.Start(); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	server.Stop()
}

func TestStartRejectsUnsupportedNetwork(t *testing.T) {
	server := New(config.ControlConfig{
		Network: "udp",
		Address: "127.0.0.1:0",
	}, "test")

	err := server.Start()
	if err == nil {
		t.Fatal("expected unsupported network error")
	}
	if !strings.Contains(err.Error(), "unsupported control plane network") {
		t.Fatalf("expected unsupported network error, got %v", err)
	}
}

func TestStartRejectsMissingAddress(t *testing.T) {
	server := New(config.ControlConfig{
		Network: "unix",
	}, "test")

	err := server.Start()
	if err == nil {
		t.Fatal("expected missing address error")
	}
	if !strings.Contains(err.Error(), "address is required") {
		t.Fatalf("expected missing address error, got %v", err)
	}
}

func dialUnixControl(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		"aegis-control",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial control socket: %v", err)
	}

	return conn
}
