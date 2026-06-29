//go:build linux

package dataplane

import (
	"errors"
	"testing"
)

func requireExpectedXDPStartError(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, errXDPMissingObject) {
		t.Fatalf("expected errXDPMissingObject, got %v", err)
	}
}
