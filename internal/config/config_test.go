package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Fatalf("expected default server host 0.0.0.0, got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("expected default server port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.Mode != "release" {
		t.Fatalf("expected default server mode release, got %q", cfg.Server.Mode)
	}
	if !cfg.Control.Enabled {
		t.Fatal("expected control plane to be enabled by default")
	}
	if cfg.Control.Network != "unix" {
		t.Fatalf("expected default control network unix, got %q", cfg.Control.Network)
	}
	if cfg.Control.Address != "data/aegis-waf.sock" {
		t.Fatalf("expected default control address data/aegis-waf.sock, got %q", cfg.Control.Address)
	}
	if cfg.Security.MaxBodySize != 10*1024*1024 {
		t.Fatalf("expected default max body size 10485760, got %d", cfg.Security.MaxBodySize)
	}
	if !cfg.Security.EnableSemantic {
		t.Fatal("expected semantic analysis to be enabled by default")
	}
	if cfg.Security.EnableXDP {
		t.Fatal("expected XDP to be disabled by default")
	}
	if cfg.Database.Driver != "sqlite" {
		t.Fatalf("expected default database driver sqlite, got %q", cfg.Database.Driver)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected default logging level info, got %q", cfg.Logging.Level)
	}
	if cfg.Rules.Directory != "rules" {
		t.Fatalf("expected default rules directory rules, got %q", cfg.Rules.Directory)
	}
	if len(cfg.Rules.CustomFiles) != 0 {
		t.Fatalf("expected no default custom rule files, got %v", cfg.Rules.CustomFiles)
	}
	if len(cfg.Rules.DisabledRuleIDs) != 0 {
		t.Fatalf("expected no default disabled rule IDs, got %v", cfg.Rules.DisabledRuleIDs)
	}
	if !cfg.Rules.AutoReload {
		t.Fatal("expected rules auto reload to be enabled by default")
	}
	if cfg.Dataplane.Enabled {
		t.Fatal("expected dataplane to be disabled by default")
	}
	if cfg.Dataplane.Mode != "mock" {
		t.Fatalf("expected default dataplane mode mock, got %q", cfg.Dataplane.Mode)
	}
	if cfg.Dataplane.InterfaceName != "" {
		t.Fatalf("expected default dataplane interface to be empty, got %q", cfg.Dataplane.InterfaceName)
	}
	if cfg.Dataplane.XDPObjectPath != "" {
		t.Fatalf("expected default xdp object path to be empty, got %q", cfg.Dataplane.XDPObjectPath)
	}
	if cfg.Dataplane.XDPProgramName != "" {
		t.Fatalf("expected default xdp program name to be empty, got %q", cfg.Dataplane.XDPProgramName)
	}
	if !cfg.Dataplane.FailOpen {
		t.Fatal("expected dataplane fail open to be enabled by default")
	}
}

func TestLoadFromFile(t *testing.T) {
	clearConfigEnv(t)

	path := writeConfigFile(t, `
server:
  host: 127.0.0.1
  port: 9090
  mode: debug
security:
  maxBodySize: 2048
  enableSemantic: false
  enableXDP: true
control:
  enabled: false
  network: tcp
  address: 127.0.0.1:9900
database:
  driver: postgres
  dsn: postgres://user:pass@localhost:5432/aegis?sslmode=disable
logging:
  level: debug
  format: console
rules:
  directory: /etc/aegis/rules
  customFiles:
    - /etc/aegis/custom/custom.conf
  disabledRuleIDs:
    - 942100
  autoReload: false
dataplane:
  enabled: true
  mode: mock
  interfaceName: eth0
  xdpObjectPath: objects/aegis_waf_xdp.o
  xdpProgramName: aegis_waf_xdp
  failOpen: false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Fatalf("expected file server host 127.0.0.1, got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Fatalf("expected file server port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Server.Mode != "debug" {
		t.Fatalf("expected file server mode debug, got %q", cfg.Server.Mode)
	}
	if cfg.Security.MaxBodySize != 2048 {
		t.Fatalf("expected file max body size 2048, got %d", cfg.Security.MaxBodySize)
	}
	if cfg.Security.EnableSemantic {
		t.Fatal("expected semantic analysis to be disabled from file")
	}
	if !cfg.Security.EnableXDP {
		t.Fatal("expected XDP to be enabled from file")
	}
	if cfg.Control.Enabled {
		t.Fatal("expected control plane to be disabled from file")
	}
	if cfg.Control.Network != "tcp" {
		t.Fatalf("expected file control network tcp, got %q", cfg.Control.Network)
	}
	if cfg.Control.Address != "127.0.0.1:9900" {
		t.Fatalf("expected file control address 127.0.0.1:9900, got %q", cfg.Control.Address)
	}
	if cfg.Database.Driver != "postgres" {
		t.Fatalf("expected file database driver postgres, got %q", cfg.Database.Driver)
	}
	if cfg.Database.DSN != "postgres://user:pass@localhost:5432/aegis?sslmode=disable" {
		t.Fatalf("unexpected file database dsn %q", cfg.Database.DSN)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("expected file logging level debug, got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "console" {
		t.Fatalf("expected file logging format console, got %q", cfg.Logging.Format)
	}
	if cfg.Rules.Directory != "/etc/aegis/rules" {
		t.Fatalf("expected file rules directory /etc/aegis/rules, got %q", cfg.Rules.Directory)
	}
	if len(cfg.Rules.CustomFiles) != 1 || cfg.Rules.CustomFiles[0] != "/etc/aegis/custom/custom.conf" {
		t.Fatalf("unexpected file custom rule files: %v", cfg.Rules.CustomFiles)
	}
	if len(cfg.Rules.DisabledRuleIDs) != 1 || cfg.Rules.DisabledRuleIDs[0] != 942100 {
		t.Fatalf("unexpected file disabled rule IDs: %v", cfg.Rules.DisabledRuleIDs)
	}
	if cfg.Rules.AutoReload {
		t.Fatal("expected rules auto reload to be disabled from file")
	}
	if !cfg.Dataplane.Enabled {
		t.Fatal("expected dataplane to be enabled from file")
	}
	if cfg.Dataplane.Mode != "mock" {
		t.Fatalf("expected file dataplane mode mock, got %q", cfg.Dataplane.Mode)
	}
	if cfg.Dataplane.InterfaceName != "eth0" {
		t.Fatalf("expected file dataplane interface eth0, got %q", cfg.Dataplane.InterfaceName)
	}
	if cfg.Dataplane.XDPObjectPath != "objects/aegis_waf_xdp.o" {
		t.Fatalf("expected file xdp object path objects/aegis_waf_xdp.o, got %q", cfg.Dataplane.XDPObjectPath)
	}
	if cfg.Dataplane.XDPProgramName != "aegis_waf_xdp" {
		t.Fatalf("expected file xdp program name aegis_waf_xdp, got %q", cfg.Dataplane.XDPProgramName)
	}
	if cfg.Dataplane.FailOpen {
		t.Fatal("expected dataplane fail open to be disabled from file")
	}
}

func TestLoadEnvironmentOverrides(t *testing.T) {
	clearConfigEnv(t)

	path := writeConfigFile(t, `
server:
  host: 127.0.0.1
  port: 9090
  mode: release
security:
  maxBodySize: 2048
  enableSemantic: true
  enableXDP: false
control:
  enabled: true
  network: unix
  address: data/file.sock
database:
  driver: sqlite
  dsn: file.db
logging:
  level: info
  format: json
rules:
  directory: rules
  customFiles:
    - file.conf
  disabledRuleIDs:
    - 100
  autoReload: true
dataplane:
  enabled: false
  mode: mock
  interfaceName: eth0
  xdpObjectPath: file.o
  xdpProgramName: file_xdp
  failOpen: true
`)

	t.Setenv("AEGIS_WAF_SERVER_HOST", "192.168.1.10")
	t.Setenv("AEGIS_WAF_SERVER_PORT", "10080")
	t.Setenv("AEGIS_WAF_SERVER_MODE", "debug")
	t.Setenv("AEGIS_WAF_SECURITY_MAX_BODY_SIZE", "4096")
	t.Setenv("AEGIS_WAF_SECURITY_ENABLE_SEMANTIC", "false")
	t.Setenv("AEGIS_WAF_SECURITY_ENABLE_XDP", "true")
	t.Setenv("AEGIS_WAF_CONTROL_ENABLED", "false")
	t.Setenv("AEGIS_WAF_CONTROL_NETWORK", "tcp")
	t.Setenv("AEGIS_WAF_CONTROL_ADDRESS", "127.0.0.1:9901")
	t.Setenv("AEGIS_WAF_DATABASE_DRIVER", "postgres")
	t.Setenv("AEGIS_WAF_DATABASE_DSN", "env-dsn")
	t.Setenv("AEGIS_WAF_LOGGING_LEVEL", "warn")
	t.Setenv("AEGIS_WAF_LOGGING_FORMAT", "console")
	t.Setenv("AEGIS_WAF_RULES_DIRECTORY", "env-rules")
	t.Setenv("AEGIS_WAF_RULES_CUSTOM_FILES", "env-a.conf,env-b.conf")
	t.Setenv("AEGIS_WAF_RULES_DISABLED_RULE_IDS", "200,201")
	t.Setenv("AEGIS_WAF_RULES_AUTO_RELOAD", "false")
	t.Setenv("AEGIS_WAF_DATAPLANE_ENABLED", "true")
	t.Setenv("AEGIS_WAF_DATAPLANE_MODE", "mock")
	t.Setenv("AEGIS_WAF_DATAPLANE_INTERFACE", "env0")
	t.Setenv("AEGIS_WAF_DATAPLANE_XDP_OBJECT_PATH", "env.o")
	t.Setenv("AEGIS_WAF_DATAPLANE_XDP_PROGRAM_NAME", "env_xdp")
	t.Setenv("AEGIS_WAF_DATAPLANE_FAIL_OPEN", "false")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Host != "192.168.1.10" {
		t.Fatalf("expected env server host 192.168.1.10, got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 10080 {
		t.Fatalf("expected env server port 10080, got %d", cfg.Server.Port)
	}
	if cfg.Server.Mode != "debug" {
		t.Fatalf("expected env server mode debug, got %q", cfg.Server.Mode)
	}
	if cfg.Security.MaxBodySize != 4096 {
		t.Fatalf("expected env max body size 4096, got %d", cfg.Security.MaxBodySize)
	}
	if cfg.Security.EnableSemantic {
		t.Fatal("expected env semantic analysis override to false")
	}
	if !cfg.Security.EnableXDP {
		t.Fatal("expected env XDP override to true")
	}
	if cfg.Control.Enabled {
		t.Fatal("expected env control enabled override to false")
	}
	if cfg.Control.Network != "tcp" {
		t.Fatalf("expected env control network tcp, got %q", cfg.Control.Network)
	}
	if cfg.Control.Address != "127.0.0.1:9901" {
		t.Fatalf("expected env control address 127.0.0.1:9901, got %q", cfg.Control.Address)
	}
	if cfg.Database.Driver != "postgres" {
		t.Fatalf("expected env database driver postgres, got %q", cfg.Database.Driver)
	}
	if cfg.Database.DSN != "env-dsn" {
		t.Fatalf("expected env database dsn env-dsn, got %q", cfg.Database.DSN)
	}
	if cfg.Logging.Level != "warn" {
		t.Fatalf("expected env logging level warn, got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "console" {
		t.Fatalf("expected env logging format console, got %q", cfg.Logging.Format)
	}
	if cfg.Rules.Directory != "env-rules" {
		t.Fatalf("expected env rules directory env-rules, got %q", cfg.Rules.Directory)
	}
	if len(cfg.Rules.CustomFiles) != 2 || cfg.Rules.CustomFiles[0] != "env-a.conf" || cfg.Rules.CustomFiles[1] != "env-b.conf" {
		t.Fatalf("unexpected env custom rule files: %v", cfg.Rules.CustomFiles)
	}
	if len(cfg.Rules.DisabledRuleIDs) != 2 || cfg.Rules.DisabledRuleIDs[0] != 200 || cfg.Rules.DisabledRuleIDs[1] != 201 {
		t.Fatalf("unexpected env disabled rule IDs: %v", cfg.Rules.DisabledRuleIDs)
	}
	if cfg.Rules.AutoReload {
		t.Fatal("expected env rules auto reload override to false")
	}
	if !cfg.Dataplane.Enabled {
		t.Fatal("expected env dataplane enabled override to true")
	}
	if cfg.Dataplane.Mode != "mock" {
		t.Fatalf("expected env dataplane mode mock, got %q", cfg.Dataplane.Mode)
	}
	if cfg.Dataplane.InterfaceName != "env0" {
		t.Fatalf("expected env dataplane interface env0, got %q", cfg.Dataplane.InterfaceName)
	}
	if cfg.Dataplane.XDPObjectPath != "env.o" {
		t.Fatalf("expected env xdp object path env.o, got %q", cfg.Dataplane.XDPObjectPath)
	}
	if cfg.Dataplane.XDPProgramName != "env_xdp" {
		t.Fatalf("expected env xdp program name env_xdp, got %q", cfg.Dataplane.XDPProgramName)
	}
	if cfg.Dataplane.FailOpen {
		t.Fatal("expected env dataplane fail open override to false")
	}
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	return path
}

func clearConfigEnv(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"AEGIS_WAF_SERVER_HOST",
		"AEGIS_WAF_SERVER_PORT",
		"AEGIS_WAF_SERVER_MODE",
		"AEGIS_WAF_SECURITY_MAX_BODY_SIZE",
		"AEGIS_WAF_SECURITY_MAXBODYSIZE",
		"AEGIS_WAF_SECURITY_ENABLE_SEMANTIC",
		"AEGIS_WAF_SECURITY_ENABLESEMANTIC",
		"AEGIS_WAF_SECURITY_ENABLE_XDP",
		"AEGIS_WAF_SECURITY_ENABLEXDP",
		"AEGIS_WAF_CONTROL_ENABLED",
		"AEGIS_WAF_CONTROL_NETWORK",
		"AEGIS_WAF_CONTROL_ADDRESS",
		"AEGIS_WAF_DATABASE_DRIVER",
		"AEGIS_WAF_DATABASE_DSN",
		"AEGIS_WAF_LOGGING_LEVEL",
		"AEGIS_WAF_LOGGING_FORMAT",
		"AEGIS_WAF_RULES_DIRECTORY",
		"AEGIS_WAF_RULES_CUSTOM_FILES",
		"AEGIS_WAF_RULES_CUSTOMFILES",
		"AEGIS_WAF_RULES_DISABLED_RULE_IDS",
		"AEGIS_WAF_RULES_DISABLEDRULEIDS",
		"AEGIS_WAF_RULES_AUTO_RELOAD",
		"AEGIS_WAF_RULES_AUTORELOAD",
		"AEGIS_WAF_DATAPLANE_ENABLED",
		"AEGIS_WAF_DATAPLANE_MODE",
		"AEGIS_WAF_DATAPLANE_INTERFACE",
		"AEGIS_WAF_DATAPLANE_XDP_OBJECT_PATH",
		"AEGIS_WAF_DATAPLANE_XDPOBJECTPATH",
		"AEGIS_WAF_DATAPLANE_XDP_PROGRAM_NAME",
		"AEGIS_WAF_DATAPLANE_XDPPROGRAMNAME",
		"AEGIS_WAF_DATAPLANE_FAIL_OPEN",
		"AEGIS_WAF_DATAPLANE_FAILOPEN",
	} {
		t.Setenv(key, "")
	}
}
