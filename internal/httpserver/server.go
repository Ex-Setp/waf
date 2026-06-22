package httpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegis-waf/internal/accesscontrol"
	"aegis-waf/internal/auditlog"
	"aegis-waf/internal/captcha"
	"aegis-waf/internal/cc"
	"aegis-waf/internal/config"
	"aegis-waf/internal/crs"
	"aegis-waf/internal/database"
	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
	"aegis-waf/internal/reports"
	"aegis-waf/internal/requestparser"

	"gorm.io/gorm"
)

var ErrBodyTooLarge = errors.New("request body exceeds configured max size")
var processStartedAt = time.Now()

type Processor interface {
	Process(context.Context, pipeline.Request) (pipeline.Result, error)
}

type Server struct {
	cfg             config.ServerConfig
	security        config.SecurityConfig
	processor       Processor
	server          *http.Server
	tlsServer       *http.Server
	db              *gorm.DB
	sites           *database.SiteRepository
	runtime         *gateway.RuntimeManager
	audit           *auditlog.Writer
	reports         *reports.Store
	ccLimiter       *cc.Limiter
	captcha         *captcha.Manager
	fastBlocker     dataplane.FastBlocker
	detectionEngine protectionRuleRuntime
	crsManager      *crs.Manager
	policies        atomic.Value
	certificates    atomic.Value
	captchaConfig   atomic.Value
	acmeManager     acmeCertificateProvider
	safetyMu        sync.Mutex
	safetyBackups   map[int]safetyBackup
	nextSafetyID    int
	emergencyBypass atomic.Bool
}

type policySnapshot struct {
	AccessRules []database.AccessRule
	CCPolicies  []database.CCPolicy
}

type protectionRuleRuntime interface {
	Reload(context.Context) error
	Rules() []detection.Rule
	EnableRule(int) error
	DisableRule(int) error
	UpsertRuntimeRule(detection.Rule) error
	DeleteRuntimeRule(int) error
}

type certificateSnapshot struct {
	ByID     map[uint]database.Certificate
	ByDomain map[string]database.Certificate
}

type acmeCertificateProvider interface {
	GetCertificate(context.Context, string) (*tls.Certificate, error)
}

type Option func(*Server) error

func WithDatabase(db *gorm.DB) Option {
	return func(s *Server) error {
		s.db = db
		s.sites = database.NewSiteRepository(db)
		manager, err := gateway.NewRuntimeManager(s.sites)
		if err != nil {
			return err
		}
		s.runtime = manager
		s.audit = auditlog.NewWriter(db)
		s.reports = reports.NewStore(db)
		if err := s.reloadPolicies(context.Background()); err != nil {
			return err
		}
		if err := s.reloadCertificates(context.Background()); err != nil {
			return err
		}
		if err := s.reloadProtectionRules(context.Background()); err != nil {
			return err
		}
		return nil
	}
}

func WithRuntime(manager *gateway.RuntimeManager) Option {
	return func(s *Server) error { s.runtime = manager; return nil }
}
func WithAudit(writer *auditlog.Writer) Option {
	return func(s *Server) error { s.audit = writer; return nil }
}
func WithCCLimiter(limiter *cc.Limiter) Option {
	return func(s *Server) error { s.ccLimiter = limiter; return nil }
}
func WithCaptcha(manager *captcha.Manager) Option {
	return func(s *Server) error { s.captcha = manager; return nil }
}
func WithFastBlocker(blocker dataplane.FastBlocker) Option {
	return func(s *Server) error { s.fastBlocker = blocker; return nil }
}
func WithDetectionEngine(engine protectionRuleRuntime) Option {
	return func(s *Server) error {
		s.detectionEngine = engine
		return s.reloadProtectionRules(context.Background())
	}
}

func WithCRSManager(manager *crs.Manager) Option {
	return func(s *Server) error {
		s.crsManager = manager
		return nil
	}
}

type Response struct {
	Decision       pipeline.Decision `json:"decision"`
	Reason         string            `json:"reason,omitempty"`
	BlockedByStage string            `json:"blockedByStage,omitempty"`
	Metrics        []Metric          `json:"metrics,omitempty"`
	Score          int               `json:"score,omitempty"`
	Threshold      int               `json:"threshold,omitempty"`
	Severity       string            `json:"severity,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
}

type Metric struct {
	Stage      string            `json:"stage"`
	DurationMS float64           `json:"durationMs"`
	Error      string            `json:"error,omitempty"`
	Decision   pipeline.Decision `json:"decision,omitempty"`
}

func New(cfg config.ServerConfig, security config.SecurityConfig, processor Processor, options ...Option) *Server {
	s := &Server{cfg: cfg, security: security, processor: processor, ccLimiter: cc.NewLimiter(), captcha: captcha.NewManager("", 5*time.Minute), safetyBackups: map[int]safetyBackup{}, nextSafetyID: 1}
	s.policies.Store(policySnapshot{})
	s.certificates.Store(certificateSnapshot{ByID: map[uint]database.Certificate{}, ByDomain: map[string]database.Certificate{}})
	if cfg.TLS.ACME.Enabled {
		provider, err := newACMEProvider(cfg.TLS.ACME)
		if err != nil {
			panic(err)
		}
		s.acmeManager = provider
	}
	for _, option := range options {
		if err := option(s); err != nil {
			panic(err)
		}
	}
	s.server = &http.Server{Addr: s.address(), Handler: s.Handler()}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/", s.handleAPI)
	mux.HandleFunc("/challenge", s.handleChallenge)
	mux.HandleFunc("/challenge/verify", s.handleChallengeVerify)
	mux.HandleFunc("/", s.handleWAF)
	return withCORS(mux)
}

func (s *Server) Start() error {
	if s.server == nil {
		s.server = &http.Server{Addr: s.address(), Handler: s.Handler()}
	}
	errCh := make(chan error, 2)
	if s.HTTPSAddrEnabled() {
		s.tlsServer = &http.Server{Addr: s.HTTPSAddr(), Handler: s.Handler(), TLSConfig: s.TLSConfig()}
		go func() {
			if err := s.tlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}
	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	err := <-errCh
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) Stop(ctx context.Context) error {
	if s.audit != nil {
		_ = s.audit.Stop(ctx)
	}
	var stopErr error
	if s.tlsServer != nil {
		stopErr = s.tlsServer.Shutdown(ctx)
	}
	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil && stopErr == nil {
			stopErr = err
		}
	}
	return stopErr
}
func (s *Server) Addr() string { return s.address() }

func (s *Server) HTTPSAddrEnabled() bool { return s != nil && s.cfg.TLS.Enabled }

func (s *Server) HTTPSAddr() string {
	host := strings.TrimSpace(s.cfg.Host)
	if host == "" {
		host = "0.0.0.0"
	}
	port := s.cfg.TLS.Port
	if port == 0 {
		port = 8443
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.getCertificateForClientHello}
}

func (s *Server) getCertificateForClientHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := gateway.NormalizeHost(hello.ServerName)
	if domain == "" {
		return nil, fmt.Errorf("tls server name is required")
	}
	if cert, ok := s.certificateForDomain(domain); ok {
		parsed, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("load certificate for %s: %w", domain, err)
		}
		return &parsed, nil
	}
	if s.cfg.TLS.ACME.Enabled && s.acmeManager != nil && s.siteAllowsAutoTLS(domain) {
		return s.acmeManager.GetCertificate(context.Background(), domain)
	}
	return nil, fmt.Errorf("no certificate configured for %s", domain)
}

func (s *Server) certificateForDomain(domain string) (database.Certificate, bool) {
	value := s.certificates.Load()
	if value == nil {
		return database.Certificate{}, false
	}
	snapshot := value.(certificateSnapshot)
	if cert, ok := snapshot.ByDomain[domain]; ok && strings.TrimSpace(cert.CertPEM) != "" && strings.TrimSpace(cert.KeyPEM) != "" {
		return cert, true
	}
	if s.runtime != nil {
		if site, ok := s.runtime.MatchSite(domain); ok && site.CertificateID > 0 {
			cert, ok := snapshot.ByID[site.CertificateID]
			if ok && strings.TrimSpace(cert.CertPEM) != "" && strings.TrimSpace(cert.KeyPEM) != "" {
				return cert, true
			}
		}
	}
	return database.Certificate{}, false
}

func (s *Server) siteAllowsAutoTLS(domain string) bool {
	if s.runtime == nil {
		return false
	}
	site, ok := s.runtime.MatchSite(domain)
	return ok && strings.EqualFold(site.TLSMode, "auto")
}

func (s *Server) address() string {
	host := strings.TrimSpace(s.cfg.Host)
	if host == "" {
		host = "0.0.0.0"
	}
	port := s.cfg.Port
	if port == 0 {
		port = 8080
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleWAF(w http.ResponseWriter, r *http.Request) {
	if s.runtime == nil {
		s.handlePipelineJSON(w, r)
		return
	}
	started := time.Now()
	site, ok := s.runtime.MatchSite(r.Host)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "site not found"})
		return
	}
	if site.Status == database.SiteStatusDisabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "site disabled"})
		return
	}
	req, err := s.toPipelineRequest(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, Response{Decision: pipeline.DecisionBlock, Reason: err.Error()})
		return
	}
	bytesIn := int64(len(req.Body))
	applySitePolicy(site, &req)
	req.DisabledRuleIDs = s.disabledRuleIDsForSite(site.ID)
	r.Body = io.NopCloser(strings.NewReader(req.Body))
	if s.emergencyBypass.Load() {
		s.proxyAllowResult(w, r, site, req, pipeline.Result{Decision: pipeline.DecisionAllow, Reason: "emergency bypass"}, started, bytesIn)
		return
	}

	if s.shouldRequireGlobalCaptcha(site, req) {
		if s.captcha.Valid(r, site.ID, req.RemoteIP.String()) {
			s.proxyAllow(w, r, site, req, started, bytesIn)
			return
		}
		pipeResult := pipeline.Result{Decision: pipeline.DecisionBlock, Reason: "captcha required", BlockedByStage: "captcha"}
		_ = s.writeLogs(r.Context(), site, req, pipeResult, http.StatusFound, started, bytesIn, 0)
		http.Redirect(w, r, "/challenge", http.StatusFound)
		return
	}

	if acResult := s.evaluateAccessControl(r.Context(), site, req); acResult.Decision != accesscontrol.DecisionNone {
		s.handleAccessDecision(w, r, site, req, acResult, started, bytesIn)
		return
	}
	if site.CCProtection || site.PolicyMode == database.PolicyModeStrict {
		if ccResult := s.evaluateCC(r.Context(), site, req); ccResult.Decision != cc.DecisionAllow {
			s.handleCCDecision(w, r, site, req, ccResult, started, bytesIn)
			return
		}
	}
	var result pipeline.Result
	if site.WAFEnabled && s.processor != nil {
		var processErr error
		result, processErr = s.processor.Process(r.Context(), req)
		if result.Decision == pipeline.DecisionBlock || processErr != nil {
			if processErr != nil && result.Decision != pipeline.DecisionBlock && s.security.FailOpen {
				result = pipeline.Result{Decision: pipeline.DecisionAllow, Reason: "allowed by fail-open: " + processErr.Error()}
				s.proxyAllowResult(w, r, site, req, result, started, bytesIn)
				return
			}
			status := http.StatusForbidden
			if processErr != nil && result.Decision != pipeline.DecisionBlock {
				status = http.StatusServiceUnavailable
				result = pipeline.Result{Decision: pipeline.DecisionBlock, Reason: "fail-closed: " + processErr.Error(), BlockedByStage: "pipeline"}
			}
			s.writeBlock(w, site, req, result, processErr, status, started, bytesIn)
			return
		}
	}
	s.proxyAllowResult(w, r, site, req, result, started, bytesIn)
}

func (s *Server) handlePipelineJSON(w http.ResponseWriter, r *http.Request) {
	if s.processor == nil {
		writeJSON(w, http.StatusServiceUnavailable, Response{Decision: pipeline.DecisionBlock, Reason: "pipeline processor is unavailable"})
		return
	}
	req, err := s.toPipelineRequest(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, Response{Decision: pipeline.DecisionBlock, Reason: err.Error()})
		return
	}
	result, processErr := s.processor.Process(r.Context(), req)
	status := http.StatusOK
	if result.Decision == pipeline.DecisionBlock {
		status = http.StatusForbidden
	}
	if processErr != nil && result.Decision != pipeline.DecisionBlock {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, responseFromResult(result, processErr))
}

func (s *Server) shouldRequireGlobalCaptcha(site *gateway.SiteRuntime, req pipeline.Request) bool {
	if s == nil || site == nil {
		return false
	}
	settings := s.captchaSettings()
	if !settings.ImageCaptcha && !settings.SliderCaptcha {
		return false
	}
	path := strings.Split(req.Path, "?")[0]
	if path == "/challenge" || path == "/challenge/verify" || strings.HasPrefix(path, "/api/") || path == "/healthz" {
		return false
	}
	if len(settings.Triggers) == 0 {
		return true
	}
	for _, trigger := range settings.Triggers {
		if !trigger.Enabled {
			continue
		}
		condition := strings.TrimSpace(trigger.Condition)
		if condition == "" || condition == "*" || condition == "global" || condition == "true" {
			return true
		}
	}
	return false
}

func (s *Server) evaluateAccessControl(_ context.Context, site *gateway.SiteRuntime, req pipeline.Request) accesscontrol.Result {
	if s == nil {
		return accesscontrol.Result{Decision: accesscontrol.DecisionNone}
	}
	snapshot := s.policySnapshot()
	rules := make([]database.AccessRule, 0, len(snapshot.AccessRules))
	now := time.Now().UnixMilli()
	for _, rule := range snapshot.AccessRules {
		if ruleAppliesToRequest(rule, site.ID, req.Path, now) {
			rules = append(rules, rule)
		}
	}
	return accesscontrol.NewEvaluator(rules).Evaluate(accesscontrol.Request{SiteID: site.ID, SourceIP: req.RemoteIP, Path: req.Path, Args: req.Args, Headers: req.Headers, Method: req.Method, UserAgent: req.Headers.Get("User-Agent")})
}

func (s *Server) handleAccessDecision(w http.ResponseWriter, r *http.Request, site *gateway.SiteRuntime, req pipeline.Request, result accesscontrol.Result, started time.Time, bytesIn int64) {
	switch result.Decision {
	case accesscontrol.DecisionBlock:
		pipeResult := pipeline.Result{Decision: pipeline.DecisionBlock, Reason: result.Reason, BlockedByStage: "accesscontrol"}
		s.writeBlock(w, site, req, pipeResult, nil, http.StatusForbidden, started, bytesIn)
	case accesscontrol.DecisionAllow, accesscontrol.DecisionSkipDetection:
		s.recordAuditEvent(r.Context(), "whitelist_hit", site.ID, site.Name, fmt.Sprintf("access-rule:%d", result.Rule.ID), string(result.Decision), result.Reason)
		s.proxyAllow(w, r, site, req, started, bytesIn)
	}
}

func (s *Server) evaluateCC(_ context.Context, site *gateway.SiteRuntime, req pipeline.Request) cc.Result {
	return s.evaluateCCWithStatus(site, req, 0)
}

func (s *Server) evaluateCCWithStatus(site *gateway.SiteRuntime, req pipeline.Request, statusCode int) cc.Result {
	if s == nil || s.ccLimiter == nil {
		return cc.Result{Decision: cc.DecisionAllow}
	}
	snapshot := s.policySnapshot()
	policies := make([]database.CCPolicy, 0, len(snapshot.CCPolicies))
	for _, policy := range snapshot.CCPolicies {
		if !policy.Enabled || (policy.SiteID != 0 && policy.SiteID != site.ID) {
			continue
		}
		if statusCode > 0 && !isPostCCScope(policy.Scope) {
			continue
		}
		if statusCode == 0 && isPostCCScope(policy.Scope) {
			continue
		}
		policies = append(policies, policy)
	}
	return s.ccLimiter.Evaluate(cc.Request{SiteID: site.ID, SourceIP: req.RemoteIP.String(), Path: req.Path, UserAgent: req.Headers.Get("User-Agent"), StatusCode: statusCode}, policies)
}

func isPostCCScope(scope string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	return scope == "404" || scope == "not-found" || strings.HasPrefix(scope, "login-failure")
}

func (s *Server) handleCCDecision(w http.ResponseWriter, r *http.Request, site *gateway.SiteRuntime, req pipeline.Request, result cc.Result, started time.Time, bytesIn int64) {
	if result.Decision == cc.DecisionObserve {
		s.proxyAllowResult(w, r, site, req, ccPipelineResult(result, pipeline.DecisionAllow), started, bytesIn)
		return
	}
	if result.Decision == cc.DecisionCaptcha {
		s.fastBlockIP(r.Context(), req.RemoteIP, "cc captcha challenge")
		if s.captcha.Valid(r, site.ID, req.RemoteIP.String()) {
			s.proxyAllow(w, r, site, req, started, bytesIn)
			return
		}
		pipeResult := ccPipelineResult(result, pipeline.DecisionBlock)
		_ = s.writeLogs(r.Context(), site, req, pipeResult, http.StatusFound, started, bytesIn, 0)
		http.Redirect(w, r, "/challenge", http.StatusFound)
		return
	}
	reason := "cc rate limit exceeded"
	if result.Decision == cc.DecisionTempBlock {
		reason = "cc temporary block"
	} else if result.Decision == cc.DecisionLongBlock {
		reason = "cc long block"
	}
	pipeResult := ccPipelineResult(result, pipeline.DecisionBlock)
	if pipeResult.Reason == "" {
		pipeResult.Reason = reason
	}
	s.fastBlockIP(r.Context(), req.RemoteIP, reason)
	s.writeBlock(w, site, req, pipeResult, nil, http.StatusForbidden, started, bytesIn)
}

func ccPipelineResult(result cc.Result, decision pipeline.Decision) pipeline.Result {
	reason := strings.TrimSpace(string(result.Decision))
	if reason == "" || reason == string(cc.DecisionAllow) {
		reason = "cc policy matched"
	} else {
		reason = "cc " + reason
	}
	message := fmt.Sprintf("policy=%d name=%s scope=%s key=%s count=%d threshold=%d action=%s", result.Policy.ID, result.Policy.Name, result.Policy.Scope, result.Key, result.Count, result.Policy.Threshold, result.Decision)
	if !result.BlockUntil.IsZero() {
		message += " blockUntil=" + result.BlockUntil.Format(time.RFC3339)
	}
	return pipeline.Result{Decision: decision, Reason: reason, BlockedByStage: "cc", Detection: detection.Result{Score: result.Count, Severity: ccSeverity(result.Decision), Matches: []detection.MatchedRule{{ID: int(result.Policy.ID), Message: message, Source: fmt.Sprintf("cc:%d", result.Policy.ID), Group: ccAttackType(result), Severity: ccSeverity(result.Decision), Score: result.Count, Action: detection.RuleAction(string(result.Decision))}}}}
}

func ccSeverity(decision cc.Decision) string {
	switch decision {
	case cc.DecisionLongBlock, cc.DecisionTempBlock, cc.DecisionBlock:
		return "high"
	case cc.DecisionCaptcha:
		return "medium"
	default:
		return "low"
	}
}

func ccAttackType(result cc.Result) string {
	scope := strings.ToLower(strings.TrimSpace(result.Policy.Scope))
	switch {
	case scope == "404" || scope == "not-found":
		return "scanner-404"
	case strings.HasPrefix(scope, "login-failure"):
		return "login-bruteforce"
	default:
		return "cc"
	}
}

func (s *Server) disabledRuleIDsForSite(siteID uint) map[int]bool {
	snapshot := s.policySnapshot()
	disabled := map[int]bool{}
	for _, rule := range snapshot.AccessRules {
		if !ruleAppliesToRequest(rule, siteID, "", time.Now().UnixMilli()) || rule.Type != database.AccessRuleRuleDisable {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(firstNonEmpty(rule.RuleID, rule.Value)))
		if err == nil && id > 0 {
			disabled[id] = true
		}
	}
	if len(disabled) == 0 {
		return nil
	}
	return disabled
}

func ruleAppliesToRequest(rule database.AccessRule, siteID uint, requestPath string, nowMillis int64) bool {
	if !rule.Enabled || (rule.SiteID != 0 && rule.SiteID != siteID) {
		return false
	}
	if rule.ExpiresAt > 0 && nowMillis > rule.ExpiresAt {
		return false
	}
	scope := strings.ToLower(strings.TrimSpace(rule.Scope))
	if scope == "" || scope == "site" || scope == "global" || requestPath == "" {
		return true
	}
	if scope == "path" {
		return pathMatchesRequest(requestPath, rule.Value)
	}
	return true
}

func pathMatchesRequest(requestPath, pattern string) bool {
	requestPath = strings.Split(requestPath, "?")[0]
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if ok, _ := path.Match(pattern, requestPath); ok {
		return true
	}
	return requestPath == pattern || strings.HasPrefix(requestPath, strings.TrimSuffix(pattern, "*"))
}

func applySitePolicy(site *gateway.SiteRuntime, req *pipeline.Request) {
	if site == nil || req == nil {
		return
	}
	req.BlockScoreThreshold = site.BlockScoreThreshold
	req.EnabledRuleGroups = ruleGroupsMap(site.RuleGroups)
	if req.BlockScoreThreshold <= 0 {
		switch site.PolicyMode {
		case database.PolicyModeLoose:
			req.BlockScoreThreshold = 100
		case database.PolicyModeStrict:
			req.BlockScoreThreshold = 5
		default:
			req.BlockScoreThreshold = 7
		}
	}
	req.ForceSemantic = site.SemanticProtection || site.PolicyMode == database.PolicyModeStrict && strings.HasPrefix(strings.Split(req.Path, "?")[0], "/api")
}

func ruleGroupsMap(groups []string) map[string]bool {
	if len(groups) == 0 {
		return nil
	}
	out := make(map[string]bool, len(groups))
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group != "" {
			out[group] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) recordAuditEvent(ctx context.Context, eventType string, siteID uint, siteName, resource, action, detail string) {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.WithContext(ctx).Create(&database.AuditEvent{Type: eventType, Actor: "system", SiteID: siteID, SiteName: siteName, Resource: resource, Action: action, Detail: detail}).Error
}

func (s *Server) fastBlockIP(ctx context.Context, ip net.IP, reason string) {
	if s == nil || s.fastBlocker == nil || ip == nil {
		return
	}
	_ = s.fastBlocker.UpsertBlockedIP(ctx, dataplane.BlockedIP{IP: ip, Reason: reason, ExpiresAt: time.Now().Add(10 * time.Minute)})
}

func (s *Server) writeBlock(w http.ResponseWriter, site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, processErr error, status int, started time.Time, bytesIn int64) {
	_ = s.writeLogs(context.Background(), site, req, result, status, started, bytesIn, 0)
	writeJSON(w, status, responseFromResult(result, processErr))
}

func (s *Server) proxyAllow(w http.ResponseWriter, r *http.Request, site *gateway.SiteRuntime, req pipeline.Request, started time.Time, bytesIn int64) {
	s.proxyAllowResult(w, r, site, req, pipeline.Result{Decision: pipeline.DecisionAllow, Reason: "allowed"}, started, bytesIn)
}

func (s *Server) proxyAllowResult(w http.ResponseWriter, r *http.Request, site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, started time.Time, bytesIn int64) {
	recorder := &statusRecorder{ResponseWriter: w, header: http.Header{}, status: http.StatusOK}
	if site == nil || site.Upstream == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "upstream proxy unavailable"})
		return
	}
	s.serveUpstreamWithRetry(recorder, r, site, req)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	if result.Decision == "" {
		result.Decision = pipeline.DecisionAllow
	}
	if result.Reason == "" {
		result.Reason = "allowed"
	}
	if site.CCProtection || site.PolicyMode == database.PolicyModeStrict {
		if ccResult := s.evaluateCCWithStatus(site, req, status); ccResult.Decision != cc.DecisionAllow {
			ccPipe := ccPipelineResult(ccResult, pipeline.DecisionAllow)
			if ccResult.Decision == cc.DecisionCaptcha {
				ccPipe.Decision = pipeline.DecisionBlock
				_ = s.writeLogs(r.Context(), site, req, ccPipe, http.StatusFound, started, bytesIn, recorder.bytes)
				http.Redirect(w, r, "/challenge", http.StatusFound)
				return
			}
			if ccResult.Decision == cc.DecisionTempBlock || ccResult.Decision == cc.DecisionLongBlock || ccResult.Decision == cc.DecisionBlock {
				ccPipe.Decision = pipeline.DecisionBlock
				s.fastBlockIP(r.Context(), req.RemoteIP, ccPipe.Reason)
				_ = s.writeLogs(r.Context(), site, req, ccPipe, http.StatusForbidden, started, bytesIn, recorder.bytes)
				writeJSON(w, http.StatusForbidden, responseFromResult(ccPipe, nil))
				return
			}
			result = ccPipe
		}
	}
	recorder.Flush()
	_ = s.writeLogs(r.Context(), site, req, result, status, started, bytesIn, recorder.bytes)
}

func (s *Server) writeLogs(ctx context.Context, site *gateway.SiteRuntime, req pipeline.Request, result pipeline.Result, status int, started time.Time, bytesIn, bytesOut int64) error {
	if s.audit == nil {
		return nil
	}
	access := auditlog.AccessLogFrom(site, req, status, result.Decision, site.UpstreamRaw, time.Since(started), bytesIn)
	access.BytesOut = bytesOut
	if err := s.audit.WriteAccess(ctx, access); err != nil {
		return err
	}
	if result.Decision == pipeline.DecisionBlock || len(result.Detection.Matches) > 0 || len(result.Semantic.Matches) > 0 {
		s.observeSemanticFingerprints(ctx, site.ID, site.Name, req, result)
		return s.audit.WriteAttack(ctx, auditlog.AttackLogFrom(site, req, result, status, time.Since(started)))
	}
	return nil
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(s.captcha.ChallengeHTML()))
}

func (s *Server) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if s.runtime == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "site runtime unavailable"})
		return
	}
	site, ok := s.runtime.MatchSite(r.Host)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "site not found"})
		return
	}
	s.captcha.SetToken(w, site.ID, remoteIP(r.RemoteAddr).String())
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) toPipelineRequest(r *http.Request) (pipeline.Request, error) {
	body, err := readLimitedBody(r.Body, s.security.MaxBodySize)
	if err != nil {
		return pipeline.Request{}, err
	}
	parsed := requestparser.Parse(r.Method, requestURI(r), r.Header.Clone(), body, requestparser.Options{MaxBodySize: s.security.MaxBodySize, FailOpen: s.security.FailOpen})
	args := cloneValues(r.URL.Query())
	mergeBodyArgs(args, r.Header.Get("Content-Type"), body)
	mergeParsedArgs(args, parsed)
	return pipeline.Request{ID: fmt.Sprintf("req-%d", time.Now().UnixNano()), Method: r.Method, Path: requestURI(r), Host: r.Host, RemoteIP: remoteIP(r.RemoteAddr), Headers: r.Header.Clone(), Args: args, Body: string(body), Timestamp: time.Now(), ParsedRequest: parsed}, nil
}

func mergeParsedArgs(args map[string][]string, parsed requestparser.ParsedRequest) {
	seen := map[string]map[string]bool{}
	for key, values := range args {
		seen[key] = map[string]bool{}
		for _, value := range values {
			seen[key][value] = true
		}
	}
	addUnique := func(key, value string) {
		if strings.TrimSpace(key) == "" || value == "" {
			return
		}
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		if seen[key][value] {
			return
		}
		seen[key][value] = true
		addArg(args, key, value)
	}
	for _, field := range parsed.Fields {
		switch field.Source {
		case "query", "form", "multipart":
			addUnique(field.Name, field.NormalizedValue)
		case "json":
			addUnique("json."+field.Name, field.NormalizedValue)
		}
	}
}

func cloneValues(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(values))
	for key, items := range values {
		out[key] = append([]string(nil), items...)
	}
	return out
}

func mergeBodyArgs(args map[string][]string, contentType string, body []byte) {
	if len(body) == 0 {
		return
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch mediaType {
	case "application/json":
		mergeJSONArgs(args, body)
	case "multipart/form-data":
		mergeMultipartArgs(args, body, params["boundary"])
	case "application/x-www-form-urlencoded":
		mergeFormURLEncodedArgs(args, body)
	}
}

func mergeJSONArgs(args map[string][]string, body []byte) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return
	}
	flattenJSONArg(args, "json", value)
}

func flattenJSONArg(args map[string][]string, key string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			flattenJSONArg(args, joinArgKey(key, childKey), childValue)
		}
	case []any:
		for _, item := range typed {
			flattenJSONArg(args, key, item)
		}
	case string:
		addArg(args, key, typed)
	case json.Number:
		addArg(args, key, typed.String())
	case bool:
		addArg(args, key, strconv.FormatBool(typed))
	case nil:
		return
	default:
		addArg(args, key, fmt.Sprint(typed))
	}
}

func mergeMultipartArgs(args map[string][]string, body []byte, boundary string) {
	if boundary == "" {
		return
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	form, err := reader.ReadForm(1 << 20)
	if err != nil {
		return
	}
	defer form.RemoveAll()
	for key, values := range form.Value {
		for _, value := range values {
			addArg(args, key, value)
		}
	}
	for key, files := range form.File {
		for _, file := range files {
			addArg(args, key, file.Filename)
			if file.Header.Get("Content-Type") != "" {
				addArg(args, key+".content_type", file.Header.Get("Content-Type"))
			}
		}
	}
}

func mergeFormURLEncodedArgs(args map[string][]string, body []byte) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return
	}
	for key, items := range values {
		for _, item := range items {
			addArg(args, key, item)
		}
	}
}

func joinArgKey(parent, child string) string {
	child = strings.TrimSpace(child)
	if parent == "" || parent == "json" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "." + child
}

func addArg(args map[string][]string, key, value string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	args[key] = append(args[key], value)
}

func readLimitedBody(body io.ReadCloser, maxSize int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	defer body.Close()
	if maxSize <= 0 {
		return io.ReadAll(body)
	}
	limited := io.LimitReader(body, maxSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, ErrBodyTooLarge
	}
	return data, nil
}
func requestURI(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	if r.URL.RequestURI() != "" {
		return r.URL.RequestURI()
	}
	return r.URL.Path
}
func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.ParseIP("0.0.0.0")
	}
	return ip
}

func responseFromResult(result pipeline.Result, processErr error) Response {
	resp := Response{Decision: result.Decision, Reason: result.Reason, BlockedByStage: result.BlockedByStage, Metrics: metricsFromResult(result.StageMetrics), Score: result.Detection.Score, Threshold: result.ScoreThreshold, Severity: result.Detection.Severity, Errors: errorStrings(result.Errors)}
	if processErr != nil {
		resp.Errors = append(resp.Errors, processErr.Error())
	}
	return resp
}
func metricsFromResult(metrics []pipeline.StageMetric) []Metric {
	out := make([]Metric, 0, len(metrics))
	for _, metric := range metrics {
		out = append(out, Metric{Stage: metric.Stage, DurationMS: float64(metric.Duration) / float64(time.Millisecond), Error: metric.Error, Decision: metric.Decision})
	}
	return out
}
func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	header http.Header
	body   bytes.Buffer
	status int
	bytes  int64
}

func (r *statusRecorder) Header() http.Header {
	return r.header
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
}
func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.body.Write(data)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() {
	for key, values := range r.header {
		for _, value := range values {
			r.ResponseWriter.Header().Add(key, value)
		}
	}
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.ResponseWriter.WriteHeader(r.status)
	_, _ = r.ResponseWriter.Write(r.body.Bytes())
}
