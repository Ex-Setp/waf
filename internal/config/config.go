package config

import (
	"strings"

	"github.com/spf13/viper"
)

const envPrefix = "AEGIS_WAF"

// Config contains the runtime configuration for Aegis-WAF.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Control   ControlConfig   `mapstructure:"control"`
	Security  SecurityConfig  `mapstructure:"security"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Rules     RulesConfig     `mapstructure:"rules"`
	CRS       CRSConfig       `mapstructure:"crs"`
	Dataplane DataplaneConfig `mapstructure:"dataplane"`
}

type ServerConfig struct {
	Host string    `mapstructure:"host"`
	Port int       `mapstructure:"port"`
	Mode string    `mapstructure:"mode"`
	TLS  TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled bool       `mapstructure:"enabled"`
	Port    int        `mapstructure:"port"`
	ACME    ACMEConfig `mapstructure:"acme"`
}

type ACMEConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Email     string   `mapstructure:"email"`
	CacheDir  string   `mapstructure:"cacheDir"`
	Directory string   `mapstructure:"directory"`
	AcceptTOS bool     `mapstructure:"acceptTOS"`
	HTTPPort  int      `mapstructure:"httpPort"`
	Domains   []string `mapstructure:"domains"`
}

type ControlConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Network string `mapstructure:"network"`
	Address string `mapstructure:"address"`
}

type SecurityConfig struct {
	MaxBodySize       int64 `mapstructure:"maxBodySize"`
	EnableSemantic    bool  `mapstructure:"enableSemantic"`
	EnableXDP         bool  `mapstructure:"enableXDP"`
	FailOpen          bool  `mapstructure:"failOpen"`
	UpstreamRetries   int   `mapstructure:"upstreamRetries"`
	UpstreamTimeoutMS int   `mapstructure:"upstreamTimeoutMs"`
}

type DatabaseConfig struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type RulesConfig struct {
	Directory       string   `mapstructure:"directory"`
	CustomFiles     []string `mapstructure:"customFiles"`
	DisabledRuleIDs []int    `mapstructure:"disabledRuleIDs"`
	AutoReload      bool     `mapstructure:"autoReload"`
}

type CRSConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	RulesDir          string `mapstructure:"rulesDir"`
	ParanoiaLevel     int    `mapstructure:"paranoiaLevel"`
	InboundThreshold  int    `mapstructure:"inboundThreshold"`
	OutboundThreshold int    `mapstructure:"outboundThreshold"`
	RequestBodyLimit  int64  `mapstructure:"requestBodyLimit"`
	AuditLogEnabled   bool   `mapstructure:"auditLogEnabled"`
	FailOpen          bool   `mapstructure:"failOpen"`
}

type DataplaneConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Mode           string `mapstructure:"mode"`
	InterfaceName  string `mapstructure:"interfaceName"`
	XDPObjectPath  string `mapstructure:"xdpObjectPath"`
	XDPProgramName string `mapstructure:"xdpProgramName"`
	FailOpen       bool   `mapstructure:"failOpen"`
}

// Load reads configuration from defaults, an optional YAML file, and
// AEGIS_WAF-prefixed environment variables.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)
	if err := bindEnv(v); err != nil {
		return nil, err
	}

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.mode", "release")
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.tls.port", 8443)
	v.SetDefault("server.tls.acme.enabled", false)
	v.SetDefault("server.tls.acme.email", "")
	v.SetDefault("server.tls.acme.cacheDir", "data/acme")
	v.SetDefault("server.tls.acme.directory", "https://acme-v02.api.letsencrypt.org/directory")
	v.SetDefault("server.tls.acme.acceptTOS", false)
	v.SetDefault("server.tls.acme.httpPort", 80)
	v.SetDefault("server.tls.acme.domains", []string{})

	v.SetDefault("control.enabled", true)
	v.SetDefault("control.network", "unix")
	v.SetDefault("control.address", "data/aegis-waf.sock")

	v.SetDefault("security.maxBodySize", int64(10*1024*1024))
	v.SetDefault("security.enableSemantic", true)
	v.SetDefault("security.enableXDP", false)
	v.SetDefault("security.failOpen", false)
	v.SetDefault("security.upstreamRetries", 0)
	v.SetDefault("security.upstreamTimeoutMs", 5000)

	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "data/aegis-waf.db")

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")

	v.SetDefault("rules.directory", "rules")
	v.SetDefault("rules.customFiles", []string{})
	v.SetDefault("rules.disabledRuleIDs", []int{})
	v.SetDefault("rules.autoReload", true)

	v.SetDefault("crs.enabled", false)
	v.SetDefault("crs.rulesDir", "rules/crs")
	v.SetDefault("crs.paranoiaLevel", 1)
	v.SetDefault("crs.inboundThreshold", 5)
	v.SetDefault("crs.outboundThreshold", 5)
	v.SetDefault("crs.requestBodyLimit", int64(10*1024*1024))
	v.SetDefault("crs.auditLogEnabled", false)
	v.SetDefault("crs.failOpen", true)

	v.SetDefault("dataplane.enabled", false)
	v.SetDefault("dataplane.mode", "mock")
	v.SetDefault("dataplane.interfaceName", "")
	v.SetDefault("dataplane.xdpObjectPath", "")
	v.SetDefault("dataplane.xdpProgramName", "")
	v.SetDefault("dataplane.failOpen", true)
}

func bindEnv(v *viper.Viper) error {
	envBindings := map[string][]string{
		"server.host":                {"AEGIS_WAF_SERVER_HOST"},
		"server.port":                {"AEGIS_WAF_SERVER_PORT"},
		"server.mode":                {"AEGIS_WAF_SERVER_MODE"},
		"server.tls.enabled":         {"AEGIS_WAF_SERVER_TLS_ENABLED"},
		"server.tls.port":            {"AEGIS_WAF_SERVER_TLS_PORT"},
		"server.tls.acme.enabled":    {"AEGIS_WAF_SERVER_TLS_ACME_ENABLED"},
		"server.tls.acme.email":      {"AEGIS_WAF_SERVER_TLS_ACME_EMAIL"},
		"server.tls.acme.cacheDir":   {"AEGIS_WAF_SERVER_TLS_ACME_CACHE_DIR", "AEGIS_WAF_SERVER_TLS_ACME_CACHEDIR"},
		"server.tls.acme.directory":  {"AEGIS_WAF_SERVER_TLS_ACME_DIRECTORY"},
		"server.tls.acme.acceptTOS":  {"AEGIS_WAF_SERVER_TLS_ACME_ACCEPT_TOS", "AEGIS_WAF_SERVER_TLS_ACME_ACCEPTTOS"},
		"server.tls.acme.httpPort":   {"AEGIS_WAF_SERVER_TLS_ACME_HTTP_PORT", "AEGIS_WAF_SERVER_TLS_ACME_HTTPPORT"},
		"control.enabled":            {"AEGIS_WAF_CONTROL_ENABLED"},
		"control.network":            {"AEGIS_WAF_CONTROL_NETWORK"},
		"control.address":            {"AEGIS_WAF_CONTROL_ADDRESS"},
		"security.maxBodySize":       {"AEGIS_WAF_SECURITY_MAX_BODY_SIZE", "AEGIS_WAF_SECURITY_MAXBODYSIZE"},
		"security.enableSemantic":    {"AEGIS_WAF_SECURITY_ENABLE_SEMANTIC", "AEGIS_WAF_SECURITY_ENABLESEMANTIC"},
		"security.enableXDP":         {"AEGIS_WAF_SECURITY_ENABLE_XDP", "AEGIS_WAF_SECURITY_ENABLEXDP"},
		"security.failOpen":          {"AEGIS_WAF_SECURITY_FAIL_OPEN", "AEGIS_WAF_SECURITY_FAILOPEN"},
		"security.upstreamRetries":   {"AEGIS_WAF_SECURITY_UPSTREAM_RETRIES", "AEGIS_WAF_SECURITY_UPSTREAMRETRIES"},
		"security.upstreamTimeoutMs": {"AEGIS_WAF_SECURITY_UPSTREAM_TIMEOUT_MS", "AEGIS_WAF_SECURITY_UPSTREAMTIMEOUTMS"},
		"database.driver":            {"AEGIS_WAF_DATABASE_DRIVER"},
		"database.dsn":               {"AEGIS_WAF_DATABASE_DSN"},
		"logging.level":              {"AEGIS_WAF_LOGGING_LEVEL"},
		"logging.format":             {"AEGIS_WAF_LOGGING_FORMAT"},
		"rules.directory":            {"AEGIS_WAF_RULES_DIRECTORY"},
		"rules.customFiles":          {"AEGIS_WAF_RULES_CUSTOM_FILES", "AEGIS_WAF_RULES_CUSTOMFILES"},
		"rules.disabledRuleIDs":      {"AEGIS_WAF_RULES_DISABLED_RULE_IDS", "AEGIS_WAF_RULES_DISABLEDRULEIDS"},
		"rules.autoReload":           {"AEGIS_WAF_RULES_AUTO_RELOAD", "AEGIS_WAF_RULES_AUTORELOAD"},
		"crs.enabled":                {"AEGIS_WAF_CRS_ENABLED"},
		"crs.rulesDir":               {"AEGIS_WAF_CRS_RULES_DIR", "AEGIS_WAF_CRS_RULESDIR"},
		"crs.paranoiaLevel":          {"AEGIS_WAF_CRS_PARANOIA_LEVEL", "AEGIS_WAF_CRS_PARANOIALEVEL"},
		"crs.inboundThreshold":       {"AEGIS_WAF_CRS_INBOUND_THRESHOLD", "AEGIS_WAF_CRS_INBOUNDTHRESHOLD"},
		"crs.outboundThreshold":      {"AEGIS_WAF_CRS_OUTBOUND_THRESHOLD", "AEGIS_WAF_CRS_OUTBOUNDTHRESHOLD"},
		"crs.requestBodyLimit":       {"AEGIS_WAF_CRS_REQUEST_BODY_LIMIT", "AEGIS_WAF_CRS_REQUESTBODYLIMIT"},
		"crs.auditLogEnabled":        {"AEGIS_WAF_CRS_AUDIT_LOG_ENABLED", "AEGIS_WAF_CRS_AUDITLOGENABLED"},
		"crs.failOpen":               {"AEGIS_WAF_CRS_FAIL_OPEN", "AEGIS_WAF_CRS_FAILOPEN"},
		"dataplane.enabled":          {"AEGIS_WAF_DATAPLANE_ENABLED"},
		"dataplane.mode":             {"AEGIS_WAF_DATAPLANE_MODE"},
		"dataplane.interfaceName":    {"AEGIS_WAF_DATAPLANE_INTERFACE"},
		"dataplane.xdpObjectPath":    {"AEGIS_WAF_DATAPLANE_XDP_OBJECT_PATH", "AEGIS_WAF_DATAPLANE_XDPOBJECTPATH"},
		"dataplane.xdpProgramName":   {"AEGIS_WAF_DATAPLANE_XDP_PROGRAM_NAME", "AEGIS_WAF_DATAPLANE_XDPPROGRAMNAME"},
		"dataplane.failOpen":         {"AEGIS_WAF_DATAPLANE_FAIL_OPEN", "AEGIS_WAF_DATAPLANE_FAILOPEN"},
	}

	for key, envs := range envBindings {
		bindings := append([]string{key}, envs...)
		if err := v.BindEnv(bindings...); err != nil {
			return err
		}
	}

	return nil
}
