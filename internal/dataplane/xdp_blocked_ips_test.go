package dataplane

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

func TestBlockedIPMapManagerUpsertDeleteSnapshot(t *testing.T) {
	manager := newBlockedIPMapManager()
	expiresAt := time.Unix(1700000000, 0).UTC()
	ip := net.ParseIP("203.0.113.10")

	if err := manager.Upsert(context.Background(), BlockedIP{IP: ip, Reason: "cc rate limit exceeded", ExpiresAt: expiresAt}); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	blocked, ok := manager.Match(ip, time.Unix(1699999999, 0).UTC())
	if !ok || blocked.Reason != "cc rate limit exceeded" || !blocked.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected blocked ip: %+v ok=%v", blocked, ok)
	}
	if _, ok := manager.Match(ip, time.Unix(1700000001, 0).UTC()); ok {
		t.Fatal("expired blocked ip still matched")
	}
	if got := len(manager.Snapshot()); got != 0 {
		t.Fatalf("expected expired entry to be deleted, got %d", got)
	}
}

func TestBlockedIPMapManagerRejectsEmptyIP(t *testing.T) {
	manager := newBlockedIPMapManager()
	if err := manager.Upsert(context.Background(), BlockedIP{}); !errors.Is(err, errBlockedIPEmpty) {
		t.Fatalf("expected errBlockedIPEmpty, got %v", err)
	}
	if err := manager.Delete(context.Background(), nil); !errors.Is(err, errBlockedIPEmpty) {
		t.Fatalf("expected errBlockedIPEmpty, got %v", err)
	}
}

func TestBlockedIPMapManagerWritesBoundMap(t *testing.T) {
	manager := newBlockedIPMapManager()
	writer := &recordingMapWriter{}
	manager.Bind(writer)
	ip := net.ParseIP("198.51.100.20")
	if err := manager.Upsert(context.Background(), BlockedIP{IP: ip, Reason: "confirmed malicious"}); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	if writer.updates != 1 {
		t.Fatalf("expected one map update, got %d", writer.updates)
	}
	if _, ok := writer.lastKey.(blockedIPKey); !ok {
		t.Fatalf("expected blockedIPKey, got %T", writer.lastKey)
	}
	if _, ok := writer.lastVal.(blockedIPValue); !ok {
		t.Fatalf("expected blockedIPValue, got %T", writer.lastVal)
	}
	if err := manager.Delete(context.Background(), ip); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if writer.deletes != 1 {
		t.Fatalf("expected one map delete, got %d", writer.deletes)
	}
}

func TestMockEngineFastBlocksDownstreamRequests(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "mock"}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	blocker := engine.(FastBlocker)
	ip := net.ParseIP("203.0.113.44")
	if err := blocker.UpsertBlockedIP(context.Background(), BlockedIP{IP: ip, Reason: "confirmed malicious"}); err != nil {
		t.Fatalf("UpsertBlockedIP returned error: %v", err)
	}
	result, err := engine.Evaluate(context.Background(), RequestMeta{RemoteIP: ip, Path: "/"})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.Decision != DecisionBlock || result.Reason != "confirmed malicious" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if err := blocker.DeleteBlockedIP(context.Background(), ip); err != nil {
		t.Fatalf("DeleteBlockedIP returned error: %v", err)
	}
	result, err = engine.Evaluate(context.Background(), RequestMeta{RemoteIP: ip, Path: "/"})
	if err != nil {
		t.Fatalf("Evaluate after delete returned error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("expected allow after delete, got %+v", result)
	}
}

func TestXDPEngineBlockedIPChannel(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: true}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	xdp := engine.(*xdpEngine)
	ip := net.ParseIP("192.0.2.99")
	if err := xdp.UpsertBlockedIP(context.Background(), BlockedIP{IP: ip, Reason: "xdp fast block"}); err != nil {
		t.Fatalf("UpsertBlockedIP returned error: %v", err)
	}
	program := xdp.program.(xdpBlockedIPProgram)
	if got := len(program.BlockedIPs().Snapshot()); got != 1 {
		t.Fatalf("expected one blocked ip, got %d", got)
	}
	result, err := xdp.Evaluate(context.Background(), RequestMeta{RemoteIP: ip, Path: "/"})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.Decision != DecisionBlock || result.Reason != "xdp fast block" {
		t.Fatalf("unexpected xdp result: %+v", result)
	}
	if err := xdp.DeleteBlockedIP(context.Background(), ip); err != nil {
		t.Fatalf("DeleteBlockedIP returned error: %v", err)
	}
	if got := len(program.BlockedIPs().Snapshot()); got != 0 {
		t.Fatalf("expected empty blocked ip map, got %d", got)
	}
}
