//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis-waf/internal/config"
)

func TestXDPLoaderLinuxStatusIncludesConfiguredObjectAndProgram(t *testing.T) {
	program := newXDPProgram(config.DataplaneConfig{
		InterfaceName:  "eth0",
		XDPObjectPath:  "objects/aegis_waf_xdp.o",
		XDPProgramName: "aegis_waf_xdp",
	})

	status := program.Status()
	if status.Platform != xdpPlatformName {
		t.Fatalf("expected platform %q, got %q", xdpPlatformName, status.Platform)
	}
	if status.InterfaceName != "eth0" {
		t.Fatalf("expected interface eth0, got %q", status.InterfaceName)
	}
	if status.ObjectPath != "objects/aegis_waf_xdp.o" {
		t.Fatalf("expected object path, got %q", status.ObjectPath)
	}
	if status.ProgramName != "aegis_waf_xdp" {
		t.Fatalf("expected program name, got %q", status.ProgramName)
	}
	if !status.Supported || status.Loaded || status.Attached {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestXDPLoaderLinuxLoadMissingObjectReturnsBeforeKernelWork(t *testing.T) {
	missingObject := filepath.Join(t.TempDir(), "missing.o")
	program := newXDPProgram(config.DataplaneConfig{
		InterfaceName:  "eth0",
		XDPObjectPath:  missingObject,
		XDPProgramName: "aegis_waf_xdp",
	})

	err := program.Load(context.Background())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing object error, got %v", err)
	}
	if !strings.Contains(err.Error(), "xdp object") {
		t.Fatalf("expected xdp object error, got %v", err)
	}

	status := program.Status()
	if status.Loaded || status.Attached {
		t.Fatalf("expected unloaded and unattached status, got %+v", status)
	}
	if status.Reason == "" {
		t.Fatal("expected status reason")
	}
}

func TestXDPLoaderLinuxAttachMissingInterfaceNameDoesNotNeedRealDevice(t *testing.T) {
	program := &xdpLinuxProgram{}

	err := program.Attach(context.Background())
	if !errors.Is(err, errXDPMissingInterface) {
		t.Fatalf("expected errXDPMissingInterface, got %v", err)
	}
}
