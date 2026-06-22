package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	semanticFingerprintMapName = "semantic_fingerprints"
	semanticFingerprintKeySize = 32
)

var errSemanticFingerprintEmpty = errors.New("semantic fingerprint hash is empty")

type SemanticFingerprint struct {
	Hash      string
	Action    uint32
	Severity  uint32
	ExpiresAt time.Time
}

type semanticFingerprintKey [semanticFingerprintKeySize]byte

type semanticFingerprintValue struct {
	Action    uint32
	Severity  uint32
	ExpiresAt uint64
}

type xdpMapWriter interface {
	Update(any, any, uint64) error
	Delete(any) error
}

type semanticFingerprintMapManager struct {
	mu          sync.RWMutex
	writer      xdpMapWriter
	fingerprint map[semanticFingerprintKey]semanticFingerprintValue
}

func newSemanticFingerprintMapManager() *semanticFingerprintMapManager {
	return &semanticFingerprintMapManager{
		fingerprint: make(map[semanticFingerprintKey]semanticFingerprintValue),
	}
}

func (m *semanticFingerprintMapManager) Bind(writer xdpMapWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.writer = writer
}

func (m *semanticFingerprintMapManager) Upsert(ctx context.Context, fp SemanticFingerprint) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	key, err := semanticFingerprintHashKey(fp.Hash)
	if err != nil {
		return err
	}
	value := semanticFingerprintValue{
		Action:    fp.Action,
		Severity:  fp.Severity,
		ExpiresAt: uint64(fp.ExpiresAt.Unix()),
	}
	if fp.ExpiresAt.IsZero() {
		value.ExpiresAt = 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer != nil {
		if err := m.writer.Update(key, value, 0); err != nil {
			return fmt.Errorf("update semantic fingerprint xdp map: %w", err)
		}
	}
	m.fingerprint[key] = value
	return nil
}

func (m *semanticFingerprintMapManager) Delete(ctx context.Context, hash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	key, err := semanticFingerprintHashKey(hash)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writer != nil {
		if err := m.writer.Delete(key); err != nil {
			return fmt.Errorf("delete semantic fingerprint xdp map: %w", err)
		}
	}
	delete(m.fingerprint, key)
	return nil
}

func (m *semanticFingerprintMapManager) Snapshot() map[string]SemanticFingerprint {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := make(map[string]SemanticFingerprint, len(m.fingerprint))
	for key, value := range m.fingerprint {
		fp := SemanticFingerprint{
			Hash:     hex.EncodeToString(key[:]),
			Action:   value.Action,
			Severity: value.Severity,
		}
		if value.ExpiresAt > 0 {
			fp.ExpiresAt = time.Unix(int64(value.ExpiresAt), 0).UTC()
		}
		snapshot[fp.Hash] = fp
	}
	return snapshot
}

func semanticFingerprintHashKey(hash string) (semanticFingerprintKey, error) {
	var key semanticFingerprintKey
	cleaned := strings.TrimSpace(strings.ToLower(hash))
	if cleaned == "" {
		return key, errSemanticFingerprintEmpty
	}

	decoded, err := hex.DecodeString(cleaned)
	if err == nil && len(decoded) == semanticFingerprintKeySize {
		copy(key[:], decoded)
		return key, nil
	}

	sum := sha256.Sum256([]byte(hash))
	binary.BigEndian.PutUint64(key[:8], binary.BigEndian.Uint64(sum[:8]))
	copy(key[8:], sum[8:])
	return key, nil
}
