package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aegis-waf/internal/database"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
)

type safetyBackup struct {
	ID          int                   `json:"id"`
	CreatedAt   int64                 `json:"createdAt"`
	Sites       []database.Site       `json:"sites"`
	AccessRules []database.AccessRule `json:"accessRules"`
	CCPolicies  []database.CCPolicy   `json:"ccPolicies"`
}

func (s *Server) handleSafetyAPI(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/upstreams/health" {
		s.handleUpstreamHealth(w, r)
		return
	}
	if path == "/safety/emergency-bypass" {
		s.handleEmergencyBypass(w, r)
		return
	}
	if path == "/safety/backups" {
		if r.Method == http.MethodPost {
			s.createSafetyBackup(w, r)
			return
		}
		if r.Method == http.MethodGet {
			s.listSafetyBackups(w, r)
			return
		}
	}
	if strings.HasPrefix(path, "/safety/backups/") && r.Method == http.MethodPost {
		parts := strings.Split(strings.TrimPrefix(path, "/safety/backups/"), "/")
		if len(parts) >= 2 {
			id, err := strconv.Atoi(parts[0])
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid backup id"})
				return
			}
			if len(parts) == 2 && parts[1] == "rollback" {
				s.rollbackSafetyBackup(w, r, id, false)
				return
			}
			if len(parts) == 3 && parts[1] == "rules" && parts[2] == "rollback" {
				s.rollbackSafetyBackup(w, r, id, true)
				return
			}
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "api endpoint not found"})
}

func (s *Server) createSafetyBackup(w http.ResponseWriter, r *http.Request) {
	backup, err := s.snapshotSafetyBackup(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": err.Error()})
		return
	}
	s.safetyMu.Lock()
	backup.ID = s.nextSafetyID
	s.nextSafetyID++
	s.safetyBackups[backup.ID] = backup
	s.safetyMu.Unlock()
	s.recordAuditEvent(r.Context(), "config_backup", 0, "", fmt.Sprintf("backup:%d", backup.ID), "create", "configuration snapshot created")
	writeJSON(w, http.StatusCreated, backup)
}

func (s *Server) snapshotSafetyBackup(ctx context.Context) (safetyBackup, error) {
	if s == nil || s.db == nil {
		return safetyBackup{}, fmt.Errorf("database unavailable")
	}
	backup := safetyBackup{CreatedAt: time.Now().UnixMilli()}
	if err := s.db.WithContext(ctx).Order("id asc").Find(&backup.Sites).Error; err != nil {
		return backup, err
	}
	if err := s.db.WithContext(ctx).Order("id asc").Find(&backup.AccessRules).Error; err != nil {
		return backup, err
	}
	if err := s.db.WithContext(ctx).Order("id asc").Find(&backup.CCPolicies).Error; err != nil {
		return backup, err
	}
	return backup, nil
}

func (s *Server) listSafetyBackups(w http.ResponseWriter, _ *http.Request) {
	s.safetyMu.Lock()
	items := make([]safetyBackup, 0, len(s.safetyBackups))
	for _, backup := range s.safetyBackups {
		items = append(items, backup)
	}
	s.safetyMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"backups": items, "total": len(items)})
}

func (s *Server) rollbackSafetyBackup(w http.ResponseWriter, r *http.Request, id int, rulesOnly bool) {
	if s == nil || s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	s.safetyMu.Lock()
	backup, ok := s.safetyBackups[id]
	s.safetyMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "backup not found"})
		return
	}
	tx := s.db.WithContext(r.Context()).Begin()
	if err := tx.Where("1 = 1").Delete(&database.AccessRule{}).Error; err != nil {
		tx.Rollback()
		writeJSON(w, 500, map[string]string{"message": err.Error()})
		return
	}
	for _, rule := range backup.AccessRules {
		if err := tx.Save(&rule).Error; err != nil {
			tx.Rollback()
			writeJSON(w, 500, map[string]string{"message": err.Error()})
			return
		}
	}
	if !rulesOnly {
		if err := tx.Where("1 = 1").Delete(&database.CCPolicy{}).Error; err != nil {
			tx.Rollback()
			writeJSON(w, 500, map[string]string{"message": err.Error()})
			return
		}
		for _, policy := range backup.CCPolicies {
			if err := tx.Save(&policy).Error; err != nil {
				tx.Rollback()
				writeJSON(w, 500, map[string]string{"message": err.Error()})
				return
			}
		}
		if err := tx.Where("1 = 1").Delete(&database.Site{}).Error; err != nil {
			tx.Rollback()
			writeJSON(w, 500, map[string]string{"message": err.Error()})
			return
		}
		for _, site := range backup.Sites {
			if err := tx.Save(&site).Error; err != nil {
				tx.Rollback()
				writeJSON(w, 500, map[string]string{"message": err.Error()})
				return
			}
		}
	}
	if err := tx.Commit().Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	s.reloadRuntime(r)
	action := "rollback"
	if rulesOnly {
		action = "rules_rollback"
	}
	s.recordAuditEvent(r.Context(), "config_rollback", 0, "", fmt.Sprintf("backup:%d", id), action, "safety rollback applied")
	writeJSON(w, http.StatusOK, map[string]any{"status": "restored", "id": id, "rulesOnly": rulesOnly})
}

func (s *Server) handleEmergencyBypass(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if r.Method == http.MethodPost {
		var payload struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		s.emergencyBypass.Store(payload.Enabled)
		s.recordAuditEvent(r.Context(), "emergency_bypass", 0, "", "waf", fmt.Sprintf("enabled:%v", payload.Enabled), "global emergency bypass toggled")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": s.emergencyBypass.Load()})
}

func (s *Server) handleSiteEnableDisable(w http.ResponseWriter, r *http.Request, id uint, action string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if s == nil || s.sites == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "site repository unavailable"})
		return
	}
	site, err := s.sites.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "site not found"})
		return
	}
	if action == "disable" {
		site.Status = database.SiteStatusDisabled
	} else {
		site.Status = database.SiteStatusEnabled
	}
	if err := s.sites.Update(r.Context(), &site); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	s.reloadRuntime(r)
	s.recordAuditEvent(r.Context(), "site_toggle", site.ID, site.Name, fmt.Sprintf("site:%d", site.ID), action, "site protection status changed")
	writeJSON(w, http.StatusOK, s.siteToProtected(site))
}

func (s *Server) handleUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	items := []map[string]any{}
	if s != nil && s.runtime != nil {
		for _, site := range s.runtime.Snapshot().SitesByID {
			status := s.checkUpstreamHealth(r.Context(), site.UpstreamRaw)
			items = append(items, map[string]any{"siteId": site.ID, "siteName": site.Name, "upstream": site.UpstreamRaw, "status": status})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"upstreams": items, "total": len(items)})
}

func (s *Server) checkUpstreamHealth(ctx context.Context, upstream string) string {
	timeout := s.upstreamTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, upstream, nil)
	if err != nil {
		return "unhealthy"
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unhealthy"
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return "unhealthy"
	}
	return "healthy"
}

func (s *Server) upstreamTimeout() time.Duration {
	ms := s.security.UpstreamTimeoutMS
	if ms <= 0 {
		ms = 5000
	}
	return time.Duration(ms) * time.Millisecond
}

func (s *Server) serveUpstreamWithRetry(w http.ResponseWriter, r *http.Request, site *gateway.SiteRuntime, req pipeline.Request) {
	retries := s.security.UpstreamRetries
	if retries < 0 {
		retries = 0
	}
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt <= retries; attempt++ {
		body := strings.NewReader(req.Body)
		ctx, cancel := context.WithTimeout(r.Context(), s.upstreamTimeout())
		upReq, err := http.NewRequestWithContext(ctx, r.Method, site.Upstream.String()+r.URL.RequestURI(), body)
		if err != nil {
			cancel()
			break
		}
		upReq.Header = r.Header.Clone()
		upReq.Host = site.Upstream.Host
		upReq.Header.Set("X-Forwarded-Host", r.Host)
		if ip := remoteIP(r.RemoteAddr); ip != nil {
			upReq.Header.Set("X-Forwarded-For", ip.String())
		}
		resp, err := http.DefaultClient.Do(upReq)
		cancel()
		if err != nil {
			lastStatus, lastBody = http.StatusBadGateway, []byte(err.Error())
			continue
		}
		lastStatus = resp.StatusCode
		lastBody, _ = io.ReadAll(resp.Body)
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		resp.Body.Close()
		if resp.StatusCode < 500 || attempt == retries {
			break
		}
	}
	if lastStatus == 0 {
		lastStatus = http.StatusBadGateway
	}
	w.WriteHeader(lastStatus)
	_, _ = io.Copy(w, bytes.NewReader(lastBody))
}
