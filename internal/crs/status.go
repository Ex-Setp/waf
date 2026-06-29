package crs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled           bool   `json:"enabled"`
	RulesDir          string `json:"rulesDir"`
	ParanoiaLevel     int    `json:"paranoiaLevel"`
	InboundThreshold  int    `json:"inboundThreshold"`
	OutboundThreshold int    `json:"outboundThreshold"`
	RequestBodyLimit  int64  `json:"requestBodyLimit"`
	AuditLogEnabled   bool   `json:"auditLogEnabled"`
	FailOpen          bool   `json:"failOpen"`
}

type Status struct {
	Enabled           bool      `json:"enabled"`
	Loaded            bool      `json:"loaded"`
	RulesDir          string    `json:"rulesDir"`
	RuleCount         int       `json:"ruleCount"`
	FileCount         int       `json:"fileCount"`
	Version           string    `json:"version"`
	ParanoiaLevel     int       `json:"paranoiaLevel"`
	InboundThreshold  int       `json:"inboundThreshold"`
	OutboundThreshold int       `json:"outboundThreshold"`
	LastReloadAt      time.Time `json:"lastReloadAt,omitempty"`
	LastError         string    `json:"lastError,omitempty"`
}

type Manager struct {
	mu     sync.RWMutex
	config Config
	status Status
}

func NewManager(config Config) *Manager {
	m := &Manager{config: normalizeConfig(config)}
	m.status = Status{Enabled: m.config.Enabled, RulesDir: m.config.RulesDir, ParanoiaLevel: m.config.ParanoiaLevel, InboundThreshold: m.config.InboundThreshold, OutboundThreshold: m.config.OutboundThreshold}
	_ = m.Reload(context.Background())
	return m
}

func (m *Manager) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) RuleFiles() []string {
	m.mu.RLock()
	dir := m.config.RulesDir
	m.mu.RUnlock()
	files, _ := ScanRuleFiles(dir)
	return files
}

func (m *Manager) Reload(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	status := Status{Enabled: cfg.Enabled, RulesDir: cfg.RulesDir, ParanoiaLevel: cfg.ParanoiaLevel, InboundThreshold: cfg.InboundThreshold, OutboundThreshold: cfg.OutboundThreshold, LastReloadAt: time.Now()}
	if !cfg.Enabled {
		m.mu.Lock()
		m.status = status
		m.mu.Unlock()
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	files, err := ScanRuleFiles(cfg.RulesDir)
	if err != nil {
		status.LastError = err.Error()
		m.mu.Lock()
		m.status = status
		m.mu.Unlock()
		return err
	}
	meta, err := inspectFiles(files)
	if err != nil {
		status.LastError = err.Error()
		m.mu.Lock()
		m.status = status
		m.mu.Unlock()
		return err
	}
	status.Loaded = true
	status.FileCount = len(files)
	status.RuleCount = meta.ruleCount
	status.Version = meta.version
	m.mu.Lock()
	m.status = status
	m.mu.Unlock()
	return nil
}

func ScanRuleFiles(dir string) ([]string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := strings.ToLower(entry.Name())
			if name == ".git" || name == "node_modules" || name == "tmp_safeline" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".conf") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan CRS rules: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

type fileMeta struct {
	ruleCount int
	version   string
}

var (
	secRuleRE = regexp.MustCompile(`(?m)^\s*SecRule\b`)
	versionRE = regexp.MustCompile(`(?i)(?:OWASP[\s_-]*CRS|Core Rule Set|crs)[^0-9]*(\d+\.\d+(?:\.\d+)?)`)
)

func inspectFiles(files []string) (fileMeta, error) {
	meta := fileMeta{}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return meta, fmt.Errorf("read CRS file %s: %w", file, err)
		}
		text := string(content)
		meta.ruleCount += len(secRuleRE.FindAllStringIndex(text, -1))
		if meta.version == "" {
			if match := versionRE.FindStringSubmatch(text); len(match) > 1 {
				meta.version = match[1]
			}
		}
	}
	if meta.version == "" && len(files) > 0 {
		meta.version = "custom"
	}
	return meta, nil
}

func normalizeConfig(config Config) Config {
	if config.RulesDir == "" {
		config.RulesDir = "rules/crs"
	}
	if config.ParanoiaLevel <= 0 {
		config.ParanoiaLevel = 1
	}
	if config.InboundThreshold <= 0 {
		config.InboundThreshold = 5
	}
	if config.OutboundThreshold <= 0 {
		config.OutboundThreshold = config.InboundThreshold
	}
	if config.RequestBodyLimit <= 0 {
		config.RequestBodyLimit = 10 * 1024 * 1024
	}
	return config
}
