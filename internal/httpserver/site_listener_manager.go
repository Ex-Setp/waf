package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"aegis-waf/internal/database"
)

type siteListenerManager struct {
	mu        sync.Mutex
	server    *Server
	started   bool
	listeners map[int]*sitePortListener
}

type sitePortListener struct {
	port    int
	tls     bool
	server  *http.Server
	started bool
}

func newSiteListenerManager(server *Server) *siteListenerManager {
	return &siteListenerManager{server: server, listeners: map[int]*sitePortListener{}}
}

func (m *siteListenerManager) Reconcile(ctx context.Context, sites []database.Site) error {
	if m == nil || m.server == nil {
		return nil
	}
	desired := desiredSitePorts(sites)
	var toStart []*sitePortListener
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, listener := range m.listeners {
		wantTLS, ok := desired[port]
		if !ok || wantTLS != listener.tls {
			_ = listener.shutdown(ctx)
			delete(m.listeners, port)
		}
	}
	for port, wantTLS := range desired {
		if _, ok := m.listeners[port]; ok {
			continue
		}
		listener := &sitePortListener{port: port, tls: wantTLS, server: &http.Server{Addr: m.server.sitePortAddr(port), Handler: m.server.Handler()}}
		if wantTLS {
			listener.server.TLSConfig = m.server.TLSConfig()
		}
		m.listeners[port] = listener
		if m.started {
			listener.started = true
			toStart = append(toStart, listener)
		}
	}
	for _, listener := range toStart {
		go listener.serve()
	}
	return nil
}

func (m *siteListenerManager) Start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.started = true
	listeners := make([]*sitePortListener, 0, len(m.listeners))
	for _, listener := range m.listeners {
		if listener.started {
			continue
		}
		listener.started = true
		listeners = append(listeners, listener)
	}
	m.mu.Unlock()
	for _, listener := range listeners {
		go listener.serve()
	}
}

func (m *siteListenerManager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.started = false
	listeners := make([]*sitePortListener, 0, len(m.listeners))
	for port, listener := range m.listeners {
		listeners = append(listeners, listener)
		delete(m.listeners, port)
	}
	m.mu.Unlock()
	var stopErr error
	for _, listener := range listeners {
		if err := listener.shutdown(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}
	return stopErr
}

func (m *siteListenerManager) Ports() []int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ports := make([]int, 0, len(m.listeners))
	for port := range m.listeners {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func (l *sitePortListener) serve() {
	if l == nil || l.server == nil {
		return
	}
	if l.tls {
		_ = l.server.ListenAndServeTLS("", "")
		return
	}
	_ = l.server.ListenAndServe()
}

func (l *sitePortListener) shutdown(ctx context.Context) error {
	if l == nil || l.server == nil {
		return nil
	}
	return l.server.Shutdown(ctx)
}

func desiredSitePorts(sites []database.Site) map[int]bool {
	desired := map[int]bool{}
	for _, site := range sites {
		if site.Status == database.SiteStatusDisabled || site.ListenPort <= 0 {
			continue
		}
		if strings.EqualFold(site.TLSMode, "custom") || strings.EqualFold(site.TLSMode, "auto") {
			desired[site.ListenPort] = true
			continue
		}
		if _, ok := desired[site.ListenPort]; !ok {
			desired[site.ListenPort] = false
		}
	}
	return desired
}

func (s *Server) sitePortAddr(port int) string {
	host := strings.TrimSpace(s.cfg.Host)
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (s *Server) syncSiteListeners(ctx context.Context) error {
	if s == nil || s.sites == nil || s.siteListeners == nil {
		return nil
	}
	sites, err := s.sites.List(ctx)
	if err != nil {
		return err
	}
	return s.siteListeners.Reconcile(ctx, sites)
}

func (s *Server) SiteListenerPorts() []int {
	if s == nil || s.siteListeners == nil {
		return nil
	}
	return s.siteListeners.Ports()
}
