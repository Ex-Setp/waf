package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegis-waf/internal/database"
	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/featureloop"
	"aegis-waf/internal/pipeline"
	"aegis-waf/internal/semantic/skeleton"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const stableSemanticFingerprintHits = 3

type semanticFingerprintMapSyncer interface {
	UpsertSemanticFingerprint(context.Context, dataplane.SemanticFingerprint) error
	DeleteSemanticFingerprint(context.Context, string) error
}

type semanticFingerprintAPIResponse struct {
	Fingerprints []semanticFingerprintEntry `json:"fingerprints"`
	Total        int                        `json:"total"`
}

type semanticFingerprintEntry struct {
	ID                string   `json:"id"`
	Hash              string   `json:"hash"`
	Language          string   `json:"language"`
	Skeleton          string   `json:"skeleton"`
	NodeTypes         []string `json:"nodeTypes"`
	SamplePayload     string   `json:"samplePayload"`
	Action            string   `json:"action"`
	Status            string   `json:"status"`
	RuleID            int      `json:"ruleId"`
	GeneratedRule     string   `json:"generatedRule"`
	Hits              int64    `json:"hits"`
	FalsePositiveRate float64  `json:"falsePositiveRate"`
	Source            string   `json:"source"`
	XdpSyncStatus     string   `json:"xdpSyncStatus"`
	LastSeenAt        string   `json:"lastSeenAt"`
	UpdatedAt         string   `json:"updatedAt"`
}

func (s *Server) handleSemanticFingerprintsAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, semanticFingerprintAPIResponse{Fingerprints: []semanticFingerprintEntry{}, Total: 0})
		return
	}
	trimmed := strings.Trim(suffix, "/")
	if trimmed == "" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.semanticFingerprints(r.Context()))
		return
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "semantic fingerprint endpoint not found"})
		return
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || id == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid fingerprint id"})
		return
	}
	fp, status, err := s.applySemanticFingerprintAction(r.Context(), uint(id), parts[1])
	if err != nil {
		writeJSON(w, status, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, semanticFingerprintToAPI(fp))
}

func (s *Server) semanticFingerprints(ctx context.Context) semanticFingerprintAPIResponse {
	var fps []database.SemanticFingerprint
	_ = s.db.WithContext(ctx).Order("updated_at desc, id desc").Find(&fps).Error
	out := make([]semanticFingerprintEntry, 0, len(fps))
	for _, fp := range fps {
		out = append(out, semanticFingerprintToAPI(fp))
	}
	return semanticFingerprintAPIResponse{Fingerprints: out, Total: len(out)}
}

func (s *Server) applySemanticFingerprintAction(ctx context.Context, id uint, action string) (database.SemanticFingerprint, int, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	var fp database.SemanticFingerprint
	if err := s.db.WithContext(ctx).First(&fp, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fp, http.StatusNotFound, fmt.Errorf("semantic fingerprint not found")
		}
		return fp, http.StatusInternalServerError, err
	}
	switch action {
	case "observe":
		fp.Status = database.SemanticFingerprintStatusObserving
		fp.Action = "log"
		fp.XDPSyncStatus = "not_required"
		if err := s.deleteSemanticFingerprintFromXDP(ctx, fp.Hash); err != nil {
			fp.XDPSyncStatus = "delete_failed: " + err.Error()
		}
	case "activate":
		fp.Status = database.SemanticFingerprintStatusActive
		fp.Action = "deny"
		if fp.RuleID == 0 {
			fp.RuleID = featureloop.StableRuleID(fp.Hash)
		}
		if strings.TrimSpace(fp.GeneratedRule) == "" {
			fp.GeneratedRule = generatedSemanticRuleText(fp)
		}
		fp.XDPSyncStatus = s.syncSemanticFingerprintToXDP(ctx, fp)
	case "promote-rule":
		rule, err := s.promoteSemanticFingerprintRule(ctx, &fp)
		if err != nil {
			return fp, http.StatusInternalServerError, err
		}
		fp.Status = database.SemanticFingerprintStatusActive
		fp.Action = "deny"
		fp.RuleID = rule.RuleID
		fp.GeneratedRule = generatedSemanticRuleText(fp)
		fp.XDPSyncStatus = s.syncSemanticFingerprintToXDP(ctx, fp)
	case "rollback":
		fp.Status = database.SemanticFingerprintStatusRollback
		fp.Action = "pass"
		if fp.RuleID > 0 {
			_ = s.db.WithContext(ctx).Where("rule_id = ? AND source = ?", fp.RuleID, "semantic").Delete(&database.ProtectionRule{}).Error
			if s.detectionEngine != nil {
				_ = s.detectionEngine.DeleteRuntimeRule(fp.RuleID)
				_ = s.detectionEngine.Reload(ctx)
			}
		}
		if err := s.deleteSemanticFingerprintFromXDP(ctx, fp.Hash); err != nil {
			fp.XDPSyncStatus = "delete_failed: " + err.Error()
		} else {
			fp.XDPSyncStatus = "deleted"
		}
	default:
		return fp, http.StatusBadRequest, fmt.Errorf("unsupported semantic fingerprint action %q", action)
	}
	if err := s.db.WithContext(ctx).Save(&fp).Error; err != nil {
		return fp, http.StatusInternalServerError, err
	}
	s.recordAuditEvent(ctx, "semantic_fingerprint", fp.SiteID, fp.SiteName, fmt.Sprintf("semantic-fingerprint:%d", fp.ID), action, fmt.Sprintf("hash=%s status=%s xdp=%s", fp.Hash, fp.Status, fp.XDPSyncStatus))
	return fp, http.StatusOK, nil
}

func (s *Server) promoteSemanticFingerprintRule(ctx context.Context, fp *database.SemanticFingerprint) (database.ProtectionRule, error) {
	if fp.RuleID == 0 {
		fp.RuleID = featureloop.StableRuleID(fp.Hash)
	}
	pattern := strings.TrimSpace(fp.SamplePayload)
	if pattern == "" {
		pattern = fp.Hash
	}
	rule := database.ProtectionRule{RuleID: fp.RuleID, Name: fmt.Sprintf("semantic %s fingerprint %s", normalizeSemanticLanguage(fp.Language), shortSemanticHash(fp.Hash)), Description: fmt.Sprintf("Promoted semantic fingerprint from %d observations", fp.Hits), Category: "semantic", Variable: "ARGS", Operator: "@contains", Pattern: truncateString(pattern, 512), Action: "deny", Severity: semanticRuleSeverity(fp), Score: semanticRuleScore(fp), Source: "semantic", Enabled: true}
	var existing database.ProtectionRule
	err := s.db.WithContext(ctx).Where("rule_id = ?", rule.RuleID).First(&existing).Error
	if err == nil {
		rule.ID = existing.ID
		rule.CreatedAt = existing.CreatedAt
		err = s.db.WithContext(ctx).Save(&rule).Error
	} else if err == gorm.ErrRecordNotFound {
		err = s.db.WithContext(ctx).Create(&rule).Error
	}
	if err != nil {
		return rule, err
	}
	if s.detectionEngine != nil {
		if err := s.detectionEngine.UpsertRuntimeRule(protectionRuleToDetection(rule)); err != nil {
			return rule, err
		}
		if err := s.detectionEngine.Reload(ctx); err != nil {
			return rule, err
		}
	}
	s.recordAuditEvent(ctx, "protection_rule", fp.SiteID, fp.SiteName, fmt.Sprintf("rule:%d", rule.RuleID), "promote-semantic", rule.Name)
	return rule, nil
}

func (s *Server) observeSemanticFingerprints(ctx context.Context, siteID uint, siteName string, req pipeline.Request, result pipeline.Result) {
	if s == nil || s.db == nil || len(result.Semantic.Matches) == 0 {
		return
	}
	for _, fp := range semanticFingerprintsFromRequest(req) {
		fp.SiteID = siteID
		fp.SiteName = siteName
		fp.Source = "semantic-detection"
		s.upsertObservedSemanticFingerprint(ctx, fp)
	}
}

func (s *Server) upsertObservedSemanticFingerprint(ctx context.Context, observed database.SemanticFingerprint) {
	if strings.TrimSpace(observed.Hash) == "" {
		return
	}
	now := time.Now().UnixMilli()
	var existing database.SemanticFingerprint
	err := s.db.WithContext(ctx).Where("hash = ?", observed.Hash).First(&existing).Error
	if err == nil {
		existing.Hits++
		existing.LastSeenAt = now
		if existing.SamplePayload == "" {
			existing.SamplePayload = observed.SamplePayload
		}
		if existing.Skeleton == "" {
			existing.Skeleton = observed.Skeleton
		}
		if existing.NodeTypesJSON == "" {
			existing.NodeTypesJSON = observed.NodeTypesJSON
		}
		if existing.Status == "" {
			existing.Status = database.SemanticFingerprintStatusObserving
		}
		if existing.Action == "" {
			existing.Action = "log"
		}
		if existing.Hits >= stableSemanticFingerprintHits && existing.Status == database.SemanticFingerprintStatusObserving {
			existing.Status = database.SemanticFingerprintStatusActive
			existing.Action = "deny"
			existing.RuleID = featureloop.StableRuleID(existing.Hash)
			existing.GeneratedRule = generatedSemanticRuleText(existing)
			existing.XDPSyncStatus = s.syncSemanticFingerprintToXDP(ctx, existing)
		} else if existing.XDPSyncStatus == "" {
			existing.XDPSyncStatus = "not_required"
		}
		_ = s.db.WithContext(ctx).Save(&existing).Error
		return
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return
	}
	observed.Hits = 1
	observed.Status = database.SemanticFingerprintStatusObserving
	observed.Action = "log"
	observed.LastSeenAt = now
	observed.XDPSyncStatus = "not_required"
	_ = s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&observed).Error
}

func semanticFingerprintsFromRequest(req pipeline.Request) []database.SemanticFingerprint {
	payloads := semanticCandidatePayloads(req)
	seen := map[string]struct{}{}
	out := make([]database.SemanticFingerprint, 0, len(payloads))
	for _, payload := range payloads {
		for _, parsed := range parseSemanticPayload(payload) {
			if _, ok := seen[parsed.Hash]; ok {
				continue
			}
			seen[parsed.Hash] = struct{}{}
			nodes, _ := json.Marshal(parsed.NodeTypes)
			out = append(out, database.SemanticFingerprint{Hash: parsed.Hash, Language: normalizeSemanticLanguage(parsed.Language), Skeleton: parsed.Structure, NodeTypesJSON: string(nodes), SamplePayload: truncateString(payload, 1024)})
		}
	}
	return out
}

func semanticCandidatePayloads(req pipeline.Request) []string {
	var values []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	add(req.Path)
	add(req.Body)
	for key, items := range req.Args {
		add(key)
		for _, item := range items {
			add(item)
		}
	}
	if req.Headers != nil {
		for _, value := range req.Headers.Values("User-Agent") {
			add(value)
		}
	}
	return uniqueSemanticStrings(values)
}

func parseSemanticPayload(payload string) []*skeleton.ASTSkeleton {
	var fps []*skeleton.ASTSkeleton
	if fp, err := skeleton.ParseSQL(payload); err == nil && fp != nil && fp.Hash != "" {
		fps = append(fps, fp)
	}
	if fp, err := skeleton.ParseJS(payload); err == nil && fp != nil && fp.Hash != "" {
		fps = append(fps, fp)
	}
	return fps
}

func semanticFingerprintToAPI(fp database.SemanticFingerprint) semanticFingerprintEntry {
	var nodes []string
	_ = json.Unmarshal([]byte(fp.NodeTypesJSON), &nodes)
	return semanticFingerprintEntry{ID: idString(fp.ID), Hash: fp.Hash, Language: normalizeSemanticLanguage(fp.Language), Skeleton: fp.Skeleton, NodeTypes: nodes, SamplePayload: fp.SamplePayload, Action: fp.Action, Status: fp.Status, RuleID: fp.RuleID, GeneratedRule: fp.GeneratedRule, Hits: fp.Hits, FalsePositiveRate: fp.FalsePositiveRate, Source: fp.Source, XdpSyncStatus: fp.XDPSyncStatus, LastSeenAt: formatMillis(fp.LastSeenAt), UpdatedAt: formatMillis(fp.UpdatedAt)}
}

func generatedSemanticRuleText(fp database.SemanticFingerprint) string {
	return fmt.Sprintf("SecRule ARGS \"@contains %s\" \"id:%d,phase:2,deny,status:403,log,msg:'Promoted %s semantic fingerprint'\"\n", fp.Hash, fp.RuleID, strings.ToUpper(normalizeSemanticLanguage(fp.Language)))
}

func (s *Server) syncSemanticFingerprintToXDP(ctx context.Context, fp database.SemanticFingerprint) string {
	syncer, ok := s.fastBlocker.(semanticFingerprintMapSyncer)
	if !ok || syncer == nil {
		return "not_configured"
	}
	if err := syncer.UpsertSemanticFingerprint(ctx, dataplane.SemanticFingerprint{Hash: fp.Hash, Action: 1, Severity: semanticSeverity(fp), ExpiresAt: time.Now().Add(24 * time.Hour)}); err != nil {
		return "failed: " + err.Error()
	}
	return "synced"
}

func (s *Server) deleteSemanticFingerprintFromXDP(ctx context.Context, hash string) error {
	syncer, ok := s.fastBlocker.(semanticFingerprintMapSyncer)
	if !ok || syncer == nil {
		return nil
	}
	return syncer.DeleteSemanticFingerprint(ctx, hash)
}

func semanticSeverity(fp database.SemanticFingerprint) uint32 {
	if fp.Hits >= 10 {
		return 95
	}
	if fp.Hits >= stableSemanticFingerprintHits {
		return 85
	}
	return 60
}

func semanticRuleSeverity(fp *database.SemanticFingerprint) string {
	if fp.Hits >= 10 {
		return "critical"
	}
	return "high"
}

func semanticRuleScore(fp *database.SemanticFingerprint) int {
	if fp.Hits >= 10 {
		return 10
	}
	return 8
}

func shortSemanticHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func normalizeSemanticLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "js", "javascript":
		return "javascript"
	case "sql":
		return "sql"
	default:
		return "unknown"
	}
}

func truncateString(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func uniqueSemanticStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
