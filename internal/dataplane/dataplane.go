package dataplane

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
)

type RequestMeta struct {
	ID        string
	Method    string
	Path      string
	Host      string
	RemoteIP  net.IP
	Headers   map[string][]string
	Timestamp time.Time
}

type Result struct {
	Decision Decision
	Reason   string
}

type BlockedIP struct {
	IP        net.IP
	Reason    string
	ExpiresAt time.Time
}

type FastBlocker interface {
	UpsertBlockedIP(context.Context, BlockedIP) error
	DeleteBlockedIP(context.Context, net.IP) error
}

type Engine interface {
	Start(context.Context) error
	Stop(context.Context) error
	Evaluate(context.Context, RequestMeta) (Result, error)
}

func New(cfg config.DataplaneConfig, logger *zap.Logger) (Engine, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "mock"
	}
	switch mode {
	case "mock":
		return newMockEngine(cfg, logger), nil
	case "xdp":
		return newXDPEngine(cfg, logger), nil
	default:
		return nil, fmt.Errorf("unsupported dataplane mode %q: expected mock or xdp", cfg.Mode)
	}
}
