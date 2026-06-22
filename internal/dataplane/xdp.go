package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
)

const (
	xdpFailOpenReason   = "xdp-unavailable-fail-open"
	xdpFailClosedReason = "xdp-unavailable-fail-closed"
)

var errXDPNotImplemented = errors.New("xdp/eBPF adapter is not implemented in this skeleton; set dataplane.failOpen=true to run without XDP enforcement")
var errXDPMissingObject = errors.New("xdp/eBPF object path is not configured")
var errXDPMissingProgram = errors.New("xdp/eBPF program name is not configured")
var errXDPMissingInterface = errors.New("xdp interface name is not configured")
var errXDPMapManagerUnavailable = errors.New("xdp semantic fingerprint map manager is unavailable")

type xdpProgram interface {
	Load(context.Context) error
	Attach(context.Context) error
	Detach(context.Context) error
	Status() xdpProgramStatus
}

type xdpProgramStatus struct {
	Platform      string
	InterfaceName string
	Supported     bool
	Loaded        bool
	Attached      bool
	Reason        string
	ObjectPath    string
	ProgramName   string
}

type xdpSemanticFingerprintProgram interface {
	SemanticFingerprints() *semanticFingerprintMapManager
}

type xdpBlockedIPProgram interface {
	BlockedIPs() *blockedIPMapManager
}

type xdpEngine struct {
	cfg     config.DataplaneConfig
	logger  *zap.Logger
	program xdpProgram

	mu      sync.Mutex
	started bool
}

func newXDPEngine(cfg config.DataplaneConfig, logger *zap.Logger) *xdpEngine {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &xdpEngine{
		cfg:     cfg,
		logger:  logger,
		program: newXDPProgram(cfg),
	}
}

func (e *xdpEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.program.Load(ctx); err != nil {
		e.started = e.cfg.FailOpen
		return e.startUnavailableError("load", err)
	}

	if err := e.program.Attach(ctx); err != nil {
		_ = e.program.Detach(ctx)
		e.started = e.cfg.FailOpen
		return e.startUnavailableError("attach", err)
	}

	e.started = true
	return nil
}

func (e *xdpEngine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.started = false
	return e.program.Detach(ctx)
}

func (e *xdpEngine) UpsertSemanticFingerprint(ctx context.Context, fp SemanticFingerprint) error {
	program, ok := e.program.(xdpSemanticFingerprintProgram)
	if !ok || program.SemanticFingerprints() == nil {
		return errXDPMapManagerUnavailable
	}

	return program.SemanticFingerprints().Upsert(ctx, fp)
}

func (e *xdpEngine) DeleteSemanticFingerprint(ctx context.Context, hash string) error {
	program, ok := e.program.(xdpSemanticFingerprintProgram)
	if !ok || program.SemanticFingerprints() == nil {
		return errXDPMapManagerUnavailable
	}

	return program.SemanticFingerprints().Delete(ctx, hash)
}

func (e *xdpEngine) UpsertBlockedIP(ctx context.Context, blocked BlockedIP) error {
	program, ok := e.program.(xdpBlockedIPProgram)
	if !ok || program.BlockedIPs() == nil {
		return errXDPMapManagerUnavailable
	}
	return program.BlockedIPs().Upsert(ctx, blocked)
}

func (e *xdpEngine) DeleteBlockedIP(ctx context.Context, ip net.IP) error {
	program, ok := e.program.(xdpBlockedIPProgram)
	if !ok || program.BlockedIPs() == nil {
		return errXDPMapManagerUnavailable
	}
	return program.BlockedIPs().Delete(ctx, ip)
}

func (e *xdpEngine) Evaluate(_ context.Context, meta RequestMeta) (Result, error) {
	if program, ok := e.program.(xdpBlockedIPProgram); ok && program.BlockedIPs() != nil {
		if blocked, ok := program.BlockedIPs().Match(meta.RemoteIP, time.Now()); ok {
			reason := blocked.Reason
			if reason == "" {
				reason = "xdp blocked ip"
			}
			return Result{Decision: DecisionBlock, Reason: reason}, nil
		}
	}
	if e.cfg.FailOpen {
		return Result{
			Decision: DecisionAllow,
			Reason:   xdpFailOpenReason,
		}, nil
	}

	return Result{
		Decision: DecisionBlock,
		Reason:   xdpFailClosedReason,
	}, errXDPNotImplemented
}

func (e *xdpEngine) startUnavailableError(stage string, err error) error {
	if e.cfg.FailOpen {
		e.logger.Warn("xdp unavailable; continuing because fail-open is enabled",
			zap.String("stage", stage),
			zap.Error(err),
		)
		return nil
	}

	return fmt.Errorf("xdp %s unavailable: %w", stage, err)
}
