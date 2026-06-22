package dataplane

import (
	"context"
	"net"
	"sync"
	"time"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

const mockPassReason = "mock-pass"

type mockEngine struct {
	cfg    config.DataplaneConfig
	logger *zap.Logger
	blocks *blockedIPMapManager

	mu      sync.Mutex
	started bool
}

func newMockEngine(cfg config.DataplaneConfig, logger *zap.Logger) *mockEngine {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &mockEngine{
		cfg:    cfg,
		logger: logger,
		blocks: newBlockedIPMapManager(),
	}
}

func (e *mockEngine) Start(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.started = true
	return nil
}

func (e *mockEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.started = false
	return nil
}

func (e *mockEngine) Evaluate(_ context.Context, meta RequestMeta) (Result, error) {
	if e.blocks != nil {
		if blocked, ok := e.blocks.Match(meta.RemoteIP, time.Now()); ok {
			reason := blocked.Reason
			if reason == "" {
				reason = "dataplane blocked ip"
			}
			return Result{Decision: DecisionBlock, Reason: reason}, nil
		}
	}
	return Result{
		Decision: DecisionAllow,
		Reason:   mockPassReason,
	}, nil
}

func (e *mockEngine) UpsertBlockedIP(ctx context.Context, blocked BlockedIP) error {
	return e.blocks.Upsert(ctx, blocked)
}

func (e *mockEngine) DeleteBlockedIP(ctx context.Context, ip net.IP) error {
	return e.blocks.Delete(ctx, ip)
}
