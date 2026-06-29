package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

type recordingMapWriter struct {
	updates int
	deletes int
	lastKey any
	lastVal any
}

func (w *recordingMapWriter) Update(key any, value any, flags uint64) error {
	w.updates++
	w.lastKey = key
	w.lastVal = value
	return nil
}

func (w *recordingMapWriter) Delete(key any) error {
	w.deletes++
	w.lastKey = key
	return nil
}

func TestSemanticFingerprintMapManagerUpsertDeleteSnapshot(t *testing.T) {
	manager := newSemanticFingerprintMapManager()
	expiresAt := time.Unix(1700000000, 0).UTC()

	if err := manager.Upsert(context.Background(), SemanticFingerprint{
		Hash:      "sqli-union-select",
		Action:    1,
		Severity:  90,
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}

	snapshot := manager.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("expected one fingerprint, got %d", len(snapshot))
	}
	for _, fp := range snapshot {
		if fp.Action != 1 || fp.Severity != 90 || !fp.ExpiresAt.Equal(expiresAt) {
			t.Fatalf("unexpected fingerprint snapshot: %+v", fp)
		}
	}

	if err := manager.Delete(context.Background(), "sqli-union-select"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if got := len(manager.Snapshot()); got != 0 {
		t.Fatalf("expected empty snapshot after delete, got %d", got)
	}
}

func TestSemanticFingerprintMapManagerRejectsEmptyHash(t *testing.T) {
	manager := newSemanticFingerprintMapManager()

	if err := manager.Upsert(context.Background(), SemanticFingerprint{}); !errors.Is(err, errSemanticFingerprintEmpty) {
		t.Fatalf("expected errSemanticFingerprintEmpty, got %v", err)
	}
	if err := manager.Delete(context.Background(), " "); !errors.Is(err, errSemanticFingerprintEmpty) {
		t.Fatalf("expected errSemanticFingerprintEmpty, got %v", err)
	}
}

func TestSemanticFingerprintMapManagerWritesBoundMap(t *testing.T) {
	manager := newSemanticFingerprintMapManager()
	writer := &recordingMapWriter{}
	manager.Bind(writer)

	if err := manager.Upsert(context.Background(), SemanticFingerprint{
		Hash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Action:   2,
		Severity: 10,
	}); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	if writer.updates != 1 {
		t.Fatalf("expected one map update, got %d", writer.updates)
	}
	if _, ok := writer.lastKey.(semanticFingerprintKey); !ok {
		t.Fatalf("expected semanticFingerprintKey, got %T", writer.lastKey)
	}
	if _, ok := writer.lastVal.(semanticFingerprintValue); !ok {
		t.Fatalf("expected semanticFingerprintValue, got %T", writer.lastVal)
	}

	if err := manager.Delete(context.Background(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if writer.deletes != 1 {
		t.Fatalf("expected one map delete, got %d", writer.deletes)
	}
}

func TestXDPEngineSemanticFingerprintChannel(t *testing.T) {
	engine, err := New(config.DataplaneConfig{Mode: "xdp", FailOpen: true}, zap.NewNop())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	xdp := engine.(*xdpEngine)
	if err := xdp.UpsertSemanticFingerprint(context.Background(), SemanticFingerprint{
		Hash:     "xss-script-alert",
		Action:   1,
		Severity: 80,
	}); err != nil {
		t.Fatalf("UpsertSemanticFingerprint returned error: %v", err)
	}

	program := xdp.program.(xdpSemanticFingerprintProgram)
	if got := len(program.SemanticFingerprints().Snapshot()); got != 1 {
		t.Fatalf("expected one semantic fingerprint, got %d", got)
	}

	if err := xdp.DeleteSemanticFingerprint(context.Background(), "xss-script-alert"); err != nil {
		t.Fatalf("DeleteSemanticFingerprint returned error: %v", err)
	}
	if got := len(program.SemanticFingerprints().Snapshot()); got != 0 {
		t.Fatalf("expected empty semantic fingerprint map, got %d", got)
	}
}
