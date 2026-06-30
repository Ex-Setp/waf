package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"aegis-waf/internal/database"
	"aegis-waf/internal/proxy"
)

type SiteRuntime struct {
	ID                  uint
	Name                string
	Domains             []string
	Upstream            *url.URL
	UpstreamRaw         string
	Status              string
	WAFEnabled          bool
	CCProtection        bool
	CertificateID       uint
	CertificateName     string
	TLSMode             string
	SemanticProtection  bool
	PolicyMode          string
	BlockScoreThreshold int
	RuleGroups          []string
	RuntimeVersion      string
	Proxy               *httputil.ReverseProxy
}

type RuntimeSnapshot struct {
	SitesByHost map[string]*SiteRuntime
	SitesByID   map[uint]*SiteRuntime
	LoadedAt    time.Time
}

type SiteLister interface {
	List(context.Context) ([]database.Site, error)
}

type RuntimeManager struct {
	sites SiteLister
	value atomic.Value
}

func NewRuntimeManager(sites SiteLister) (*RuntimeManager, error) {
	m := &RuntimeManager{sites: sites}
	m.value.Store(&RuntimeSnapshot{SitesByHost: map[string]*SiteRuntime{}, SitesByID: map[uint]*SiteRuntime{}, LoadedAt: time.Now()})
	if sites != nil {
		if err := m.Reload(context.Background()); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *RuntimeManager) Reload(ctx context.Context) error {
	if m == nil || m.sites == nil {
		return nil
	}
	sites, err := m.sites.List(ctx)
	if err != nil {
		return err
	}
	snapshot, err := BuildSnapshot(sites)
	if err != nil {
		return err
	}
	m.value.Store(snapshot)
	return nil
}

func (m *RuntimeManager) MatchSite(host string) (*SiteRuntime, bool) {
	if m == nil {
		return nil, false
	}
	site, ok := m.Snapshot().SitesByHost[NormalizeHost(host)]
	return site, ok
}

func (m *RuntimeManager) Snapshot() *RuntimeSnapshot {
	if m == nil {
		return &RuntimeSnapshot{SitesByHost: map[string]*SiteRuntime{}, SitesByID: map[uint]*SiteRuntime{}, LoadedAt: time.Now()}
	}
	if v := m.value.Load(); v != nil {
		return v.(*RuntimeSnapshot)
	}
	return &RuntimeSnapshot{SitesByHost: map[string]*SiteRuntime{}, SitesByID: map[uint]*SiteRuntime{}, LoadedAt: time.Now()}
}

func BuildSnapshot(sites []database.Site) (*RuntimeSnapshot, error) {
	snapshot := &RuntimeSnapshot{SitesByHost: map[string]*SiteRuntime{}, SitesByID: map[uint]*SiteRuntime{}, LoadedAt: time.Now()}
	for _, site := range sites {
		runtimeSite, err := FromSite(site)
		if err != nil {
			return nil, err
		}
		snapshot.SitesByID[runtimeSite.ID] = runtimeSite
		for _, domain := range runtimeSite.Domains {
			normalized := NormalizeHost(domain)
			if normalized != "" {
				snapshot.SitesByHost[normalized] = runtimeSite
			}
		}
	}
	return snapshot, nil
}

func FromSite(site database.Site) (*SiteRuntime, error) {
	upstream, err := url.Parse(site.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid upstream for site %d: %s", site.ID, site.Upstream)
	}
	domains := site.Domains()
	policyMode, ok := database.NormalizePolicyMode(site.PolicyMode)
	if !ok {
		policyMode = database.PolicyModeStandard
	}
	defaults, _ := database.PolicyModeDefaultsFor(policyMode)
	threshold := site.BlockScoreThreshold
	if threshold <= 0 {
		threshold = defaults.BlockScoreThreshold
	}
	var ruleGroups []string
	if policyMode == database.PolicyModeCustom {
		ruleGroups = site.RuleGroups()
	}
	return &SiteRuntime{
		ID:                  site.ID,
		Name:                site.Name,
		Domains:             domains,
		Upstream:            upstream,
		UpstreamRaw:         site.Upstream,
		Status:              site.Status,
		WAFEnabled:          site.WAFEnabled,
		CCProtection:        site.CCProtection,
		CertificateID:       site.CertificateID,
		CertificateName:     site.CertificateName,
		TLSMode:             site.TLSMode,
		SemanticProtection:  site.SemanticProtection,
		PolicyMode:          policyMode,
		BlockScoreThreshold: threshold,
		RuleGroups:          ruleGroups,
		RuntimeVersion:      fmt.Sprintf("site-%d-%d", site.ID, site.UpdatedAt),
		Proxy:               proxy.NewReverseProxy(upstream),
	}, nil
}

func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return strings.Trim(host, ".")
}
