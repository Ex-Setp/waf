package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"aegis-waf/internal/config"

	"golang.org/x/crypto/acme/autocert"
)

type autocertProvider struct {
	manager *autocert.Manager
}

func newACMEProvider(cfg config.ACMEConfig) (*autocertProvider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if !cfg.AcceptTOS {
		return nil, fmt.Errorf("ACME requires server.tls.acme.acceptTOS=true")
	}
	cacheDir := strings.TrimSpace(cfg.CacheDir)
	if cacheDir == "" {
		cacheDir = "data/acme"
	}
	manager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		Email:  strings.TrimSpace(cfg.Email),
	}
	if len(cfg.Domains) > 0 {
		manager.HostPolicy = autocert.HostWhitelist(cfg.Domains...)
	}
	return &autocertProvider{manager: manager}, nil
}

func (p *autocertProvider) GetCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	if p == nil || p.manager == nil {
		return nil, fmt.Errorf("ACME manager is unavailable")
	}
	_ = ctx
	return p.manager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
}
