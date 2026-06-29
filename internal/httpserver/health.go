package httpserver

import (
	"context"
	"fmt"
	"time"

	"aegis-waf/internal/database"
)

type healthSummary struct {
	Status     string           `json:"status"`
	CheckedAt  string           `json:"checkedAt"`
	Uptime     string           `json:"uptime"`
	Listener   listenerHealth   `json:"listener"`
	Database   componentHealth  `json:"database"`
	Runtime    runtimeHealth    `json:"runtime"`
	RuleEngine ruleEngineHealth `json:"ruleEngine"`
	LogQueue   logQueueHealth   `json:"logQueue"`
}

type componentHealth struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type listenerHealth struct {
	Status          string `json:"status"`
	ActivePorts     []int  `json:"activePorts"`
	ActiveCount     int    `json:"activeCount"`
	ConfiguredSites int    `json:"configuredSites"`
	Message         string `json:"message,omitempty"`
}

type runtimeHealth struct {
	Status           string `json:"status"`
	SiteCount        int    `json:"siteCount"`
	EnabledSiteCount int    `json:"enabledSiteCount"`
	HostCount        int    `json:"hostCount"`
	LoadedAt         string `json:"loadedAt,omitempty"`
	Message          string `json:"message,omitempty"`
}

type ruleEngineHealth struct {
	Status           string `json:"status"`
	RuleCount        int    `json:"ruleCount"`
	EnabledRuleCount int    `json:"enabledRuleCount"`
	Message          string `json:"message,omitempty"`
}

type logQueueHealth struct {
	Status        string `json:"status"`
	QueuedAccess  int    `json:"queuedAccess"`
	QueuedAttack  int    `json:"queuedAttack"`
	DroppedAccess int64  `json:"droppedAccess"`
	Message       string `json:"message,omitempty"`
}

func (s *Server) healthSummary(ctx context.Context) healthSummary {
	summary := healthSummary{
		Status:     "ok",
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		Uptime:     time.Since(processStartedAt).Round(time.Second).String(),
		Listener:   s.listenerHealth(),
		Database:   s.databaseHealth(ctx),
		Runtime:    s.runtimeHealth(),
		RuleEngine: s.ruleEngineHealth(),
		LogQueue:   s.logQueueHealth(),
	}
	if summary.Listener.Status != "ok" ||
		summary.Database.Status != "ok" ||
		summary.Runtime.Status != "ok" ||
		summary.RuleEngine.Status != "ok" ||
		summary.LogQueue.Status != "ok" {
		summary.Status = "degraded"
	}
	return summary
}

func (s *Server) listenerHealth() listenerHealth {
	ports := s.SiteListenerPorts()
	status := listenerHealth{Status: "ok", ActivePorts: ports, ActiveCount: len(ports)}
	if s.runtime == nil {
		status.Status = "unavailable"
		status.Message = "runtime unavailable"
		return status
	}
	snapshot := s.runtime.Snapshot()
	for _, site := range snapshot.SitesByID {
		if site.Status == database.SiteStatusEnabled {
			status.ConfiguredSites++
		}
	}
	if status.ConfiguredSites > 0 && status.ActiveCount == 0 {
		status.Status = "degraded"
		status.Message = "no dynamic site listeners active"
	}
	return status
}

func (s *Server) databaseHealth(ctx context.Context) componentHealth {
	if s.db == nil {
		return componentHealth{Status: "unavailable", Message: "database handle is nil"}
	}
	sqlDB, err := s.db.DB()
	if err != nil {
		return componentHealth{Status: "error", Message: err.Error()}
	}
	pingCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		return componentHealth{Status: "error", Message: err.Error()}
	}
	return componentHealth{Status: "ok"}
}

func (s *Server) runtimeHealth() runtimeHealth {
	if s.runtime == nil {
		return runtimeHealth{Status: "unavailable", Message: "runtime manager unavailable"}
	}
	snapshot := s.runtime.Snapshot()
	status := runtimeHealth{Status: "ok", SiteCount: len(snapshot.SitesByID), HostCount: len(snapshot.SitesByHost), LoadedAt: snapshot.LoadedAt.UTC().Format(time.RFC3339)}
	for _, site := range snapshot.SitesByID {
		if site.Status == database.SiteStatusEnabled {
			status.EnabledSiteCount++
		}
	}
	return status
}

func (s *Server) ruleEngineHealth() ruleEngineHealth {
	if s.detectionEngine == nil {
		return ruleEngineHealth{Status: "unavailable", Message: "rule engine unavailable"}
	}
	rules := s.detectionEngine.Rules()
	status := ruleEngineHealth{Status: "ok", RuleCount: len(rules)}
	for _, rule := range rules {
		if rule.Enabled {
			status.EnabledRuleCount++
		}
	}
	return status
}

func (s *Server) logQueueHealth() logQueueHealth {
	if s.audit == nil {
		return logQueueHealth{Status: "unavailable", Message: "audit writer unavailable"}
	}
	stats := s.audit.Stats()
	status := logQueueHealth{Status: "ok", QueuedAccess: stats.QueuedAccess, QueuedAttack: stats.QueuedAttack, DroppedAccess: stats.DroppedAccess}
	if stats.DroppedAccess > 0 {
		status.Status = "degraded"
		status.Message = fmt.Sprintf("%d access logs dropped", stats.DroppedAccess)
	}
	return status
}
