package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	blockedIPMapName = "blocked_ips"
	blockedIPKeySize = 16
)

var errBlockedIPEmpty = errors.New("blocked ip is empty")

type blockedIPKey [blockedIPKeySize]byte

type blockedIPValue struct {
	ExpiresAt uint64
}

type blockedIPMapManager struct {
	mu      sync.RWMutex
	writer  xdpMapWriter
	blocked map[blockedIPKey]blockedIPValue
	reasons map[blockedIPKey]string
}

func newBlockedIPMapManager() *blockedIPMapManager {
	return &blockedIPMapManager{blocked: make(map[blockedIPKey]blockedIPValue), reasons: make(map[blockedIPKey]string)}
}

func (m *blockedIPMapManager) Bind(writer xdpMapWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writer = writer
}

func (m *blockedIPMapManager) Upsert(ctx context.Context, blocked BlockedIP) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := blockedIPMapKey(blocked.IP)
	if err != nil {
		return err
	}
	value := blockedIPValue{}
	if !blocked.ExpiresAt.IsZero() {
		value.ExpiresAt = uint64(blocked.ExpiresAt.Unix())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writer != nil {
		if err := m.writer.Update(key, value, 0); err != nil {
			return fmt.Errorf("update blocked ip xdp map: %w", err)
		}
	}
	m.blocked[key] = value
	m.reasons[key] = blocked.Reason
	return nil
}

func (m *blockedIPMapManager) Delete(ctx context.Context, ip net.IP) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := blockedIPMapKey(ip)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writer != nil {
		if err := m.writer.Delete(key); err != nil {
			return fmt.Errorf("delete blocked ip xdp map: %w", err)
		}
	}
	delete(m.blocked, key)
	delete(m.reasons, key)
	return nil
}

func (m *blockedIPMapManager) Match(ip net.IP, now time.Time) (BlockedIP, bool) {
	key, err := blockedIPMapKey(ip)
	if err != nil {
		return BlockedIP{}, false
	}
	m.mu.RLock()
	value, ok := m.blocked[key]
	reason := m.reasons[key]
	m.mu.RUnlock()
	if !ok {
		return BlockedIP{}, false
	}
	blocked := BlockedIP{IP: append(net.IP(nil), ip...), Reason: reason}
	if value.ExpiresAt > 0 {
		blocked.ExpiresAt = time.Unix(int64(value.ExpiresAt), 0).UTC()
		if !now.IsZero() && now.After(blocked.ExpiresAt) {
			_ = m.Delete(context.Background(), ip)
			return BlockedIP{}, false
		}
	}
	return blocked, true
}

func (m *blockedIPMapManager) Snapshot() map[string]BlockedIP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := make(map[string]BlockedIP, len(m.blocked))
	for key, value := range m.blocked {
		ip := net.IP(key[:]).String()
		blocked := BlockedIP{IP: append(net.IP(nil), key[:]...), Reason: m.reasons[key]}
		if value.ExpiresAt > 0 {
			blocked.ExpiresAt = time.Unix(int64(value.ExpiresAt), 0).UTC()
		}
		snapshot[ip] = blocked
	}
	return snapshot
}

func blockedIPMapKey(ip net.IP) (blockedIPKey, error) {
	var key blockedIPKey
	if ip == nil {
		return key, errBlockedIPEmpty
	}
	normalized := ip.To16()
	if normalized == nil {
		return key, errBlockedIPEmpty
	}
	copy(key[:], normalized)
	return key, nil
}
