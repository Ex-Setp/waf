package crs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagerReloadScansCRSFiles(t *testing.T) {
	dir := t.TempDir()
	content := `# OWASP CRS 4.0.0
SecRule ARGS "@contains attack" "id:1001,phase:2,deny,log,msg:'attack',severity:'CRITICAL'"
SecRule REQUEST_HEADERS "@contains bad" "id:1002,phase:1,log,msg:'bad',severity:'WARNING'"`
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-900.conf"), []byte(content), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	manager := NewManager(Config{Enabled: true, RulesDir: dir, ParanoiaLevel: 2, InboundThreshold: 7})
	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}
	status := manager.Status()
	if !status.Loaded || status.RuleCount != 2 || status.FileCount != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.Version != "4.0.0" || status.ParanoiaLevel != 2 || status.InboundThreshold != 7 {
		t.Fatalf("unexpected config status: %+v", status)
	}
}
