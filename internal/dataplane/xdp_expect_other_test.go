//go:build !linux

package dataplane

import (
	"errors"
	"testing"
)

func requireExpectedXDPStartError(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, errXDPOnlySupportedOnLinux) {
		t.Fatalf("expected errXDPOnlySupportedOnLinux, got %v", err)
	}
}
