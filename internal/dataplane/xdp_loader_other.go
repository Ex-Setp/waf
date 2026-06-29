//go:build !linux

package dataplane

import (
	"context"
	"errors"
	"runtime"

	"aegis-waf/internal/config"
)

var errXDPOnlySupportedOnLinux = errors.New("XDP only supported on Linux")

type xdpUnsupportedProgram struct {
	iface  string
	maps   *semanticFingerprintMapManager
	blocks *blockedIPMapManager
}

func newXDPProgram(cfg config.DataplaneConfig) xdpProgram {
	return &xdpUnsupportedProgram{
		iface:  cfg.InterfaceName,
		maps:   newSemanticFingerprintMapManager(),
		blocks: newBlockedIPMapManager(),
	}
}

func (p *xdpUnsupportedProgram) Load(context.Context) error {
	return errXDPOnlySupportedOnLinux
}

func (p *xdpUnsupportedProgram) Attach(context.Context) error {
	return errXDPOnlySupportedOnLinux
}

func (p *xdpUnsupportedProgram) Detach(context.Context) error {
	return nil
}

func (p *xdpUnsupportedProgram) SemanticFingerprints() *semanticFingerprintMapManager {
	if p.maps == nil {
		p.maps = newSemanticFingerprintMapManager()
	}
	return p.maps
}

func (p *xdpUnsupportedProgram) BlockedIPs() *blockedIPMapManager {
	if p.blocks == nil {
		p.blocks = newBlockedIPMapManager()
	}
	return p.blocks
}

func (p *xdpUnsupportedProgram) Status() xdpProgramStatus {
	return xdpProgramStatus{
		Platform:      runtime.GOOS,
		InterfaceName: p.iface,
		Supported:     false,
		Loaded:        false,
		Attached:      false,
		Reason:        errXDPOnlySupportedOnLinux.Error(),
		ObjectPath:    "",
		ProgramName:   "",
	}
}
