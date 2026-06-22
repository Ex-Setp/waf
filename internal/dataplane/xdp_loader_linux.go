//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"aegis-waf/internal/config"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const xdpPlatformName = "linux"

type xdpLinuxProgram struct {
	ifaceName   string
	objectPath  string
	programName string

	mu         sync.Mutex
	ifaceIndex int
	collection *ebpf.Collection
	program    *ebpf.Program
	xdpLink    link.Link
	maps       *semanticFingerprintMapManager
	blocks     *blockedIPMapManager
	reason     string
}

type ebpfMapWriter struct {
	inner *ebpf.Map
}

func (w ebpfMapWriter) Update(key any, value any, flags uint64) error {
	return w.inner.Update(key, value, ebpf.MapUpdateFlags(flags))
}

func (w ebpfMapWriter) Delete(key any) error {
	return w.inner.Delete(key)
}

func newXDPProgram(cfg config.DataplaneConfig) xdpProgram {
	return &xdpLinuxProgram{
		ifaceName:   cfg.InterfaceName,
		objectPath:  cfg.XDPObjectPath,
		programName: cfg.XDPProgramName,
		maps:        newSemanticFingerprintMapManager(),
		blocks:      newBlockedIPMapManager(),
		reason:      errXDPMissingObject.Error(),
	}
}

func (p *xdpLinuxProgram) Load(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := ctx.Err(); err != nil {
		p.reason = err.Error()
		return err
	}

	if p.objectPath == "" {
		p.reason = errXDPMissingObject.Error()
		return errXDPMissingObject
	}
	if p.programName == "" {
		p.reason = errXDPMissingProgram.Error()
		return errXDPMissingProgram
	}
	if _, err := os.Stat(p.objectPath); err != nil {
		p.reason = fmt.Sprintf("xdp object %q unavailable: %v", p.objectPath, err)
		return fmt.Errorf("xdp object %q unavailable: %w", p.objectPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(p.objectPath)
	if err != nil {
		p.reason = fmt.Sprintf("load collection spec: %v", err)
		return fmt.Errorf("load xdp collection spec: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		p.reason = fmt.Sprintf("load collection: %v", err)
		return fmt.Errorf("load xdp collection: %w", err)
	}

	program, ok := collection.Programs[p.programName]
	if !ok || program == nil {
		collection.Close()
		p.reason = fmt.Sprintf("xdp program %q not found in object", p.programName)
		return fmt.Errorf("xdp program %q not found in object", p.programName)
	}

	if p.collection != nil {
		p.collection.Close()
	}

	p.collection = collection
	p.program = program
	if p.maps == nil {
		p.maps = newSemanticFingerprintMapManager()
	}
	if fingerprintMap := collection.Maps[semanticFingerprintMapName]; fingerprintMap != nil {
		p.maps.Bind(ebpfMapWriter{inner: fingerprintMap})
	}
	if p.blocks == nil {
		p.blocks = newBlockedIPMapManager()
	}
	if blockedIPMap := collection.Maps[blockedIPMapName]; blockedIPMap != nil {
		p.blocks.Bind(ebpfMapWriter{inner: blockedIPMap})
	}
	p.reason = ""
	return nil
}

func (p *xdpLinuxProgram) Attach(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := ctx.Err(); err != nil {
		p.reason = err.Error()
		return err
	}

	if p.ifaceName == "" {
		p.reason = errXDPMissingInterface.Error()
		return errXDPMissingInterface
	}
	if p.program == nil {
		p.reason = errXDPMissingProgram.Error()
		return errXDPMissingProgram
	}

	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil {
		p.reason = fmt.Sprintf("lookup interface %q: %v", p.ifaceName, err)
		return fmt.Errorf("lookup xdp interface %q: %w", p.ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   p.program,
		Interface: iface.Index,
	})
	if err != nil {
		p.reason = fmt.Sprintf("attach xdp to interface %q: %v", p.ifaceName, err)
		return fmt.Errorf("attach xdp to interface %q: %w", p.ifaceName, err)
	}

	if p.xdpLink != nil {
		_ = p.xdpLink.Close()
	}

	p.ifaceIndex = iface.Index
	p.xdpLink = xdpLink
	p.reason = ""
	return nil
}

func (p *xdpLinuxProgram) Detach(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var detachErr error
	if p.xdpLink != nil {
		detachErr = p.xdpLink.Close()
		p.xdpLink = nil
	}
	if p.collection != nil {
		p.collection.Close()
		p.collection = nil
	}

	p.program = nil
	p.ifaceIndex = 0
	if detachErr != nil {
		p.reason = detachErr.Error()
		return detachErr
	}

	if p.reason == "" {
		p.reason = "xdp detached"
	}
	return nil
}

func (p *xdpLinuxProgram) SemanticFingerprints() *semanticFingerprintMapManager {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.maps == nil {
		p.maps = newSemanticFingerprintMapManager()
	}
	return p.maps
}

func (p *xdpLinuxProgram) BlockedIPs() *blockedIPMapManager {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.blocks == nil {
		p.blocks = newBlockedIPMapManager()
	}
	return p.blocks
}

func (p *xdpLinuxProgram) Status() xdpProgramStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	return xdpProgramStatus{
		Platform:      xdpPlatformName,
		InterfaceName: p.ifaceName,
		Supported:     true,
		Loaded:        p.program != nil,
		Attached:      p.xdpLink != nil,
		Reason:        p.reason,
		ObjectPath:    p.objectPath,
		ProgramName:   p.programName,
	}
}
