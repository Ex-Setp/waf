package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"aegis-waf/internal/accesscontrol"
	"aegis-waf/internal/cc"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/gateway"
	"aegis-waf/internal/pipeline"
	"aegis-waf/internal/requestparser"
	"aegis-waf/internal/securityeval"

	"gorm.io/gorm"
)

type dashboardOverview struct {
	Status         systemStatus          `json:"status"`
	Metrics        []dashboardMetric     `json:"metrics"`
	Pipeline       []pipelineStageMetric `json:"pipeline"`
	AttackTrend    []attackTrendPoint    `json:"attackTrend"`
	RecentEvents   []securityEvent       `json:"recentEvents"`
	QPS            float64               `json:"qps"`
	BlockRate      float64               `json:"blockRate"`
	TopIPs         []topItem             `json:"topIps"`
	TopPaths       []topItem             `json:"topPaths"`
	TopAttackTypes []topItem             `json:"topAttackTypes"`
}
type topItem struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}
type systemStatus struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`
	Mode    string `json:"mode"`
	Health  string `json:"health"`
}
type dashboardMetric struct {
	Key    string   `json:"key"`
	Label  string   `json:"label"`
	Value  float64  `json:"value"`
	Unit   string   `json:"unit,omitempty"`
	Trend  *float64 `json:"trend,omitempty"`
	Status string   `json:"status"`
}
type pipelineStageMetric struct {
	Stage     string  `json:"stage"`
	Label     string  `json:"label"`
	QPS       int     `json:"qps"`
	P95MS     float64 `json:"p95Ms"`
	Blocked   int     `json:"blocked"`
	ErrorRate float64 `json:"errorRate"`
	Enabled   bool    `json:"enabled"`
}
type attackTrendPoint struct {
	Time     string `json:"time"`
	Requests int    `json:"requests"`
	Blocked  int    `json:"blocked"`
}
type securityEvent struct {
	ID       string `json:"id"`
	Time     string `json:"time"`
	SourceIP string `json:"sourceIp"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Stage    string `json:"stage"`
}
type siteListResponse struct {
	Summary siteSummary     `json:"summary"`
	Sites   []protectedSite `json:"sites"`
}
type siteSummary struct {
	Total            int `json:"total"`
	Enabled          int `json:"enabled"`
	ProtectedDomains int `json:"protectedDomains"`
	BlockedToday     int `json:"blockedToday"`
}
type protectedSite struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Domains             []string `json:"domains"`
	Upstream            string   `json:"upstream"`
	ListenPort          int      `json:"listenPort"`
	Status              string   `json:"status"`
	TLSMode             string   `json:"tlsMode"`
	ListenStatus        string   `json:"listenStatus,omitempty"`
	ListenProtocol      string   `json:"listenProtocol,omitempty"`
	ListenReason        string   `json:"listenReason,omitempty"`
	CertificateID       string   `json:"certificateId,omitempty"`
	CertificateName     string   `json:"certificateName,omitempty"`
	WAFEnabled          bool     `json:"wafEnabled"`
	CCProtection        bool     `json:"ccProtection"`
	SemanticProtection  bool     `json:"semanticProtection"`
	PolicyMode          string   `json:"policyMode"`
	BlockScoreThreshold int      `json:"blockScoreThreshold"`
	RuleGroups          []string `json:"ruleGroups"`
	QPS                 int      `json:"qps"`
	BlockedToday        int      `json:"blockedToday"`
	UpdatedAt           string   `json:"updatedAt"`
}

type siteRuntimeStatus struct {
	ID             string `json:"id"`
	ListenPort     int    `json:"listenPort"`
	Status         string `json:"status"`
	ListenStatus   string `json:"listenStatus"`
	ListenProtocol string `json:"listenProtocol,omitempty"`
	ListenReason   string `json:"listenReason,omitempty"`
	ListenerPorts  []int  `json:"listenerPorts,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}

type listenerSummary struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	SiteID   string `json:"siteId,omitempty"`
	SiteName string `json:"siteName,omitempty"`
}

type listenersResponse struct {
	Items []listenerSummary `json:"items"`
	Total int               `json:"total"`
}
type attackLogResponse struct {
	Summary attackLogSummary `json:"summary"`
	Logs    []attackLogEntry `json:"logs"`
	Total   int              `json:"total"`
}
type attackLogSummary struct {
	Total    int `json:"total"`
	Blocked  int `json:"blocked"`
	Observed int `json:"observed"`
	Critical int `json:"critical"`
}
type attackLogEntry struct {
	ID                 string  `json:"id"`
	Time               string  `json:"time"`
	SiteName           string  `json:"siteName"`
	SourceIP           string  `json:"sourceIp"`
	Method             string  `json:"method"`
	Path               string  `json:"path"`
	AttackType         string  `json:"attackType"`
	Severity           string  `json:"severity"`
	Action             string  `json:"action"`
	FinalAction        string  `json:"finalAction,omitempty"`
	Stage              string  `json:"stage"`
	RuleID             string  `json:"ruleId"`
	Score              int     `json:"score"`
	ScoreBreakdown     string  `json:"scoreBreakdown,omitempty"`
	ExplanationJSON    string  `json:"explanationJson,omitempty"`
	OperatorSuggestion string  `json:"operatorSuggestion,omitempty"`
	StatusCode         int     `json:"statusCode"`
	LatencyMS          float64 `json:"latencyMs"`
	PayloadSnippet     string  `json:"payloadSnippet"`
	RuleMessage        string  `json:"ruleMessage,omitempty"`
	PolicyMode         string  `json:"policyMode,omitempty"`
	Threshold          int     `json:"threshold,omitempty"`
	RuntimeVersion     string  `json:"runtimeVersion,omitempty"`
}
type accessLogResponse struct {
	Logs  []accessLogEntry `json:"logs"`
	Total int              `json:"total"`
}
type accessLogEntry struct {
	ID                 string  `json:"id"`
	Time               string  `json:"time"`
	SiteName           string  `json:"siteName"`
	Host               string  `json:"host"`
	SourceIP           string  `json:"sourceIp"`
	Method             string  `json:"method"`
	Path               string  `json:"path"`
	Query              string  `json:"query,omitempty"`
	UserAgent          string  `json:"userAgent,omitempty"`
	Status             int     `json:"status"`
	Decision           string  `json:"decision"`
	Upstream           string  `json:"upstream"`
	LatencyMS          float64 `json:"latencyMs"`
	BytesIn            int64   `json:"bytesIn"`
	BytesOut           int64   `json:"bytesOut"`
	PolicyMode         string  `json:"policyMode,omitempty"`
	Threshold          int     `json:"threshold,omitempty"`
	RuntimeVersion     string  `json:"runtimeVersion,omitempty"`
	ScoreBreakdown     string  `json:"scoreBreakdown,omitempty"`
	ExplanationJSON    string  `json:"explanationJson,omitempty"`
	OperatorSuggestion string  `json:"operatorSuggestion,omitempty"`
}
type whitelistSuggestion struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Scope       string `json:"scope,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	Variable    string `json:"variable,omitempty"`
	SiteID      string `json:"siteId,omitempty"`
	Path        string `json:"path,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}
type whitelistSuggestionResponse struct {
	Suggestions []whitelistSuggestion `json:"suggestions"`
}
type whitelistValidationResponse struct {
	AttackLogID      string `json:"attackLogId"`
	RuleID           string `json:"ruleId"`
	BeforeDecision   string `json:"beforeDecision"`
	AfterDecision    string `json:"afterDecision"`
	EquivalentStatus string `json:"equivalentStatus"`
	Reason           string `json:"reason"`
}
type whitelistApplyPayload struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Scope       string `json:"scope"`
	RuleID      string `json:"ruleId"`
	Variable    string `json:"variable"`
	ExpiresAt   string `json:"expiresAt"`
	SiteID      string `json:"siteId"`
}

type auditEventEntry struct {
	ID       string `json:"id"`
	Time     string `json:"time"`
	Type     string `json:"type"`
	Actor    string `json:"actor"`
	SiteName string `json:"siteName"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}
type auditEventResponse struct {
	Events []auditEventEntry `json:"events"`
	Total  int               `json:"total"`
}
type certificateResponse struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Domains       []string `json:"domains"`
	HasPrivateKey bool     `json:"hasPrivateKey"`
	UpdatedAt     string   `json:"updatedAt"`
}
type certificateListResponse struct {
	Certificates []certificateResponse `json:"certificates"`
	Total        int                   `json:"total"`
}
type certificatePayload struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	CertPEM string   `json:"certPem"`
	KeyPEM  string   `json:"keyPem"`
}

type accessControlResponse struct {
	Rules []accessRule `json:"rules"`
	Total int          `json:"total"`
}
type accessRule struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Hits        int    `json:"hits"`
	UpdatedAt   string `json:"updatedAt"`
}
type ccProtectionResponse struct {
	Stats    ccStats    `json:"stats"`
	Policies []ccPolicy `json:"policies"`
}
type ccStats struct {
	QPS             int `json:"qps"`
	BlockedToday    int `json:"blockedToday"`
	ChallengedToday int `json:"challengedToday"`
	ActivePolicies  int `json:"activePolicies"`
}
type ccPolicy struct {
	ID            string `json:"id"`
	SiteID        string `json:"siteId,omitempty"`
	Name          string `json:"name"`
	Scope         string `json:"scope"`
	Threshold     int    `json:"threshold"`
	WindowSeconds int    `json:"windowSeconds"`
	Action        string `json:"action"`
	Priority      int    `json:"priority"`
	Enabled       bool   `json:"enabled"`
	HitsToday     int    `json:"hitsToday"`
}

type ccBlockEntry struct {
	Key              string `json:"key"`
	SourceIP         string `json:"sourceIp"`
	PolicyID         string `json:"policyId,omitempty"`
	PolicyName       string `json:"policyName,omitempty"`
	Scope            string `json:"scope,omitempty"`
	Action           string `json:"action"`
	Count            int    `json:"count"`
	BlockUntil       string `json:"blockUntil"`
	RemainingSeconds int64  `json:"remainingSeconds"`
	RecentPath       string `json:"recentPath,omitempty"`
	UserAgent        string `json:"userAgent,omitempty"`
}

type ccBlockResponse struct {
	Blocks []ccBlockEntry `json:"blocks"`
	Total  int            `json:"total"`
}
type captchaSettings struct {
	ImageCaptcha  bool             `json:"imageCaptcha"`
	SliderCaptcha bool             `json:"sliderCaptcha"`
	TTLSeconds    int              `json:"ttlSeconds"`
	MaxAttempts   int              `json:"maxAttempts"`
	Triggers      []captchaTrigger `json:"triggers"`
}
type captchaTrigger struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Condition       string  `json:"condition"`
	Method          string  `json:"method"`
	Enabled         bool    `json:"enabled"`
	PassRate        float64 `json:"passRate"`
	ChallengesToday int     `json:"challengesToday"`
}

type accessRulePayload struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Enabled     *bool  `json:"enabled"`
}
type ccPolicyPayload struct {
	SiteID        string `json:"siteId"`
	Name          string `json:"name"`
	Scope         string `json:"scope"`
	Threshold     int    `json:"threshold"`
	WindowSeconds int    `json:"windowSeconds"`
	Action        string `json:"action"`
	Priority      int    `json:"priority"`
	Enabled       *bool  `json:"enabled"`
}
type protectionRuleResponse struct {
	ID             string `json:"id"`
	RuleID         string `json:"ruleId"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	Variable       string `json:"variable"`
	Operator       string `json:"operator"`
	Pattern        string `json:"pattern"`
	Severity       string `json:"severity"`
	Score          int    `json:"score"`
	Action         string `json:"action"`
	Source         string `json:"source"`
	Enabled        bool   `json:"enabled"`
	Hits           int64  `json:"hits,omitempty"`
	RuntimeVersion string `json:"runtimeVersion,omitempty"`
	HotReload      bool   `json:"hotReload,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}
type protectionRuleListResponse struct {
	Rules          []protectionRuleResponse `json:"rules"`
	Total          int                      `json:"total"`
	RuntimeVersion string                   `json:"runtimeVersion,omitempty"`
	HotReload      bool                     `json:"hotReload,omitempty"`
}
type protectionRuleSetResponse struct {
	RuleSets []protectionRuleSet `json:"ruleSets"`
	Total    int                 `json:"total"`
}
type protectionRuleSet struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Version   string `json:"version"`
	Enabled   bool   `json:"enabled"`
	RuleCount int    `json:"ruleCount"`
	UpdatedAt string `json:"updatedAt"`
}
type securityCoverageResponse struct {
	GeneratedAt           string                       `json:"generatedAt"`
	RuleFileCount         int                          `json:"ruleFileCount"`
	RuleCount             int                          `json:"ruleCount"`
	AttackTotal           int                          `json:"attackTotal"`
	AttackBlocked         int                          `json:"attackBlocked"`
	AttackBlockRate       float64                      `json:"attackBlockRate"`
	BenignTotal           int                          `json:"benignTotal"`
	BenignFalsePositives  int                          `json:"benignFalsePositives"`
	BenignFalseRate       float64                      `json:"benignFalseRate"`
	MissedAttacks         []securityeval.SampleOutcome `json:"missedAttacks"`
	FalsePositives        []securityeval.SampleOutcome `json:"falsePositives"`
	AttackBlockRateTarget float64                      `json:"attackBlockRateTarget"`
	FalsePositiveLimit    int                          `json:"falsePositiveLimit"`
}
type siteProtectionPolicyResponse struct {
	Policies []siteProtectionPolicy `json:"policies"`
	Total    int                    `json:"total"`
}
type siteProtectionPolicy struct {
	SiteID            string   `json:"siteId"`
	SiteName          string   `json:"siteName"`
	Mode              string   `json:"mode"`
	EnabledRuleGroups []string `json:"enabledRuleGroups"`
	RuleGroups        []string `json:"ruleGroups"`
	CRSParanoiaLevel  int      `json:"crsParanoiaLevel"`
	InboundThreshold  int      `json:"inboundThreshold"`
	OutboundThreshold int      `json:"outboundThreshold"`
	DefaultAction     string   `json:"defaultAction"`
	RuntimeVersion    string   `json:"runtimeVersion"`
	PublishedAt       string   `json:"publishedAt"`
	UpdatedAt         string   `json:"updatedAt"`
}

type siteProtectionPolicyPayload struct {
	Mode              string   `json:"mode"`
	EnabledRuleGroups []string `json:"enabledRuleGroups"`
	RuleGroups        []string `json:"ruleGroups"`
	CRSParanoiaLevel  int      `json:"crsParanoiaLevel"`
	InboundThreshold  int      `json:"inboundThreshold"`
	OutboundThreshold int      `json:"outboundThreshold"`
	DefaultAction     string   `json:"defaultAction"`
}

type sitePolicyAuditResponse struct {
	Events []sitePolicyAuditEntry `json:"events"`
	Total  int                    `json:"total"`
}

type sitePolicyAuditEntry struct {
	ID       string `json:"id"`
	Time     string `json:"time"`
	SiteID   string `json:"siteId"`
	SiteName string `json:"siteName"`
	Version  string `json:"version"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}
type protectionWhitelistResponse struct {
	Whitelists []protectionWhitelist `json:"whitelists"`
	Total      int                   `json:"total"`
}
type protectionWhitelist struct {
	ID          string `json:"id"`
	SiteID      string `json:"siteId,omitempty"`
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Reason      string `json:"reason"`
	Scope       string `json:"scope,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	Variable    string `json:"variable,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Enabled     bool   `json:"enabled"`
	CreatedFrom string `json:"createdFrom"`
	UpdatedAt   string `json:"updatedAt"`
}
type requestParserPreviewPayload struct {
	RawRequest string            `json:"rawRequest"`
	Method     string            `json:"method"`
	URI        string            `json:"uri"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	FailOpen   bool              `json:"failOpen"`
}
type requestParserPreviewResponse struct {
	RawRequest        string                      `json:"rawRequest,omitempty"`
	Method            string                      `json:"method,omitempty"`
	RawURI            string                      `json:"rawUri,omitempty"`
	NormalizedURI     string                      `json:"normalizedURI"`
	NormalizedQuery   string                      `json:"normalizedQuery"`
	Path              string                      `json:"path,omitempty"`
	NormalizedPath    string                      `json:"normalizedPath,omitempty"`
	ContentType       string                      `json:"contentType,omitempty"`
	Headers           map[string]string           `json:"headers"`
	Cookies           map[string]string           `json:"cookies"`
	BodyText          string                      `json:"bodyText"`
	JSONFields        []string                    `json:"jsonFields"`
	MultipartFields   []string                    `json:"multipartFields"`
	MatchedVariables  []string                    `json:"matchedVariables"`
	Fields            []requestparser.ParsedField `json:"fields"`
	DecodeSteps       []requestparser.DecodeStep  `json:"decodeSteps"`
	ParseErrors       []requestparser.ParseError  `json:"parseErrors"`
	BodyTooLarge      bool                        `json:"bodyTooLarge"`
	FailOpen          bool                        `json:"failOpen"`
	InspectionAllowed bool                        `json:"inspectionAllowed"`
}
type ccBotEventResponse struct {
	Events []ccBotEvent `json:"events"`
	Total  int          `json:"total"`
}
type ccBotEvent struct {
	ID         string `json:"id"`
	Time       string `json:"time"`
	SiteName   string `json:"siteName"`
	SourceIP   string `json:"sourceIp"`
	PolicyName string `json:"policyName"`
	Scope      string `json:"scope"`
	Action     string `json:"action"`
	Count      int    `json:"count"`
	Threshold  int    `json:"threshold"`
}
type protectionRulePayload struct {
	RuleID      int    `json:"ruleId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Variable    string `json:"variable"`
	Operator    string `json:"operator"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	Source      string `json:"source"`
	Enabled     *bool  `json:"enabled"`
}

type protectionRuleValidationError struct {
	Field   string `json:"field,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

type protectionRuleWriteResponse struct {
	Rule           protectionRuleResponse `json:"rule"`
	RuntimeVersion string                 `json:"runtimeVersion,omitempty"`
	HotReload      bool                   `json:"hotReload,omitempty"`
}

type protectionRuleValidationResponse struct {
	Valid          bool                            `json:"valid"`
	Errors         []protectionRuleValidationError `json:"errors"`
	RuntimeVersion string                          `json:"runtimeVersion,omitempty"`
	HotReload      bool                            `json:"hotReload,omitempty"`
}

type protectionRuleImportResponse struct {
	Rules          []protectionRuleResponse        `json:"rules"`
	Total          int                             `json:"total"`
	Valid          bool                            `json:"valid"`
	Errors         []protectionRuleValidationError `json:"errors,omitempty"`
	RuntimeVersion string                          `json:"runtimeVersion,omitempty"`
	HotReload      bool                            `json:"hotReload,omitempty"`
}

type protectionRuleRollbackResponse struct {
	Rules          []protectionRuleResponse `json:"rules"`
	Total          int                      `json:"total"`
	RolledBackTo   string                   `json:"rolledBackTo"`
	RuntimeVersion string                   `json:"runtimeVersion,omitempty"`
	HotReload      bool                     `json:"hotReload,omitempty"`
}

type ruleUpdateSourceResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	URL            string `json:"url"`
	Mode           string `json:"mode"`
	Enabled        bool   `json:"enabled"`
	ExpectedHash   string `json:"expectedHash,omitempty"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	CurrentHash    string `json:"currentHash,omitempty"`
	LastStatus     string `json:"lastStatus,omitempty"`
	LastError      string `json:"lastError,omitempty"`
	LastSuccessAt  string `json:"lastSuccessAt,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type ruleUpdateDiffItem struct {
	RuleID     string                  `json:"ruleId"`
	Name       string                  `json:"name,omitempty"`
	ChangeType string                  `json:"changeType"`
	Before     *protectionRuleResponse `json:"before,omitempty"`
	After      *protectionRuleResponse `json:"after,omitempty"`
}

type ruleUpdateEvaluationResponse struct {
	Passed                    bool                         `json:"passed"`
	Summary                   string                       `json:"summary,omitempty"`
	BlockedReason             string                       `json:"blockedReason,omitempty"`
	AttackBlockRate           float64                      `json:"attackBlockRate"`
	AttackBlockRateDelta      float64                      `json:"attackBlockRateDelta"`
	BenignFalsePositives      int                          `json:"benignFalsePositives"`
	BenignFalsePositivesDelta int                          `json:"benignFalsePositivesDelta"`
	MissedAttacks             []securityeval.SampleOutcome `json:"missedAttacks,omitempty"`
	FalsePositives            []securityeval.SampleOutcome `json:"falsePositives,omitempty"`
}

type ruleUpdateLogResponse struct {
	ID              string                       `json:"id"`
	UpdateID        string                       `json:"updateId"`
	SourceID        string                       `json:"sourceId,omitempty"`
	SourceName      string                       `json:"sourceName,omitempty"`
	Trigger         string                       `json:"trigger"`
	Type            string                       `json:"type"`
	Status          string                       `json:"status"`
	Mode            string                       `json:"mode"`
	PackageVersion  string                       `json:"packageVersion,omitempty"`
	PackageHash     string                       `json:"packageHash,omitempty"`
	PackageURL      string                       `json:"packageUrl,omitempty"`
	RuntimeVersion  string                       `json:"runtimeVersion,omitempty"`
	Published       bool                         `json:"published"`
	Emergency       bool                         `json:"emergency"`
	EmergencyCVE    string                       `json:"emergencyCve,omitempty"`
	RuleCount       int                          `json:"ruleCount"`
	NewRules        int                          `json:"newRules"`
	RemovedRules    int                          `json:"removedRules"`
	ModifiedRules   int                          `json:"modifiedRules"`
	BlockedReason   string                       `json:"blockedReason,omitempty"`
	ErrorMessage    string                       `json:"errorMessage,omitempty"`
	RollbackFrom    string                       `json:"rollbackFrom,omitempty"`
	RolledBackTo    string                       `json:"rolledBackTo,omitempty"`
	SnapshotVersion string                       `json:"snapshotVersion,omitempty"`
	Evaluation      ruleUpdateEvaluationResponse `json:"evaluation"`
	Diff            []ruleUpdateDiffItem         `json:"diff,omitempty"`
	PublishedRules  []protectionRuleResponse     `json:"publishedRules,omitempty"`
	CreatedAt       string                       `json:"createdAt"`
	UpdatedAt       string                       `json:"updatedAt"`
}

type ruleUpdateSummaryResponse struct {
	CurrentVersion    string                     `json:"currentVersion,omitempty"`
	CurrentHash       string                     `json:"currentHash,omitempty"`
	CurrentRuleCount  int                        `json:"currentRuleCount"`
	CurrentStatus     string                     `json:"currentStatus,omitempty"`
	LastPublishedAt   string                     `json:"lastPublishedAt,omitempty"`
	LastBlockedReason string                     `json:"lastBlockedReason,omitempty"`
	LastFailureReason string                     `json:"lastFailureReason,omitempty"`
	Latest            *ruleUpdateLogResponse     `json:"latest,omitempty"`
	Sources           []ruleUpdateSourceResponse `json:"sources"`
	Logs              []ruleUpdateLogResponse    `json:"logs"`
	RuntimeVersion    string                     `json:"runtimeVersion,omitempty"`
	HotReload         bool                       `json:"hotReload,omitempty"`
}

type ruleUpdatePackagePayload struct {
	Type    string                  `json:"type"`
	Version string                  `json:"version"`
	Hash    string                  `json:"hash"`
	Mode    string                  `json:"mode"`
	Rules   []protectionRulePayload `json:"rules"`
}

type ruleUpdateManualPayload struct {
	SourceID     string                    `json:"sourceId"`
	UseSource    bool                      `json:"useSource"`
	ObserveOnly  bool                      `json:"observeOnly"`
	GrayMode     bool                      `json:"grayMode"`
	PackageURL   string                    `json:"packageUrl"`
	ExpectedHash string                    `json:"expectedHash"`
	Type         string                    `json:"type"`
	Package      *ruleUpdatePackagePayload `json:"package"`
}

type ruleUpdateSourcePayload struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	Mode         string `json:"mode"`
	Enabled      *bool  `json:"enabled"`
	ExpectedHash string `json:"expectedHash"`
}

type ruleUpdateRollbackPayload struct {
	UpdateID string `json:"updateId"`
	Version  string `json:"version"`
}

type emergencyRulePublishPayload struct {
	CVE         string                `json:"cve"`
	Version     string                `json:"version"`
	Hash        string                `json:"hash"`
	Description string                `json:"description"`
	ObserveOnly bool                  `json:"observeOnly"`
	Rule        protectionRulePayload `json:"rule"`
}

type protectionRuleTestPayload struct {
	Method  string                 `json:"method"`
	Path    string                 `json:"path"`
	URI     string                 `json:"uri"`
	Headers map[string]string      `json:"headers"`
	Body    string                 `json:"body"`
	Args    map[string][]string    `json:"args"`
	Rule    *protectionRulePayload `json:"rule,omitempty"`
}

type protectionRuleTestResponse struct {
	Matched        bool                            `json:"matched"`
	Decision       string                          `json:"decision"`
	Score          int                             `json:"score"`
	Severity       string                          `json:"severity,omitempty"`
	Matches        []detection.MatchedRule         `json:"matches"`
	Errors         []protectionRuleValidationError `json:"errors,omitempty"`
	RuntimeVersion string                          `json:"runtimeVersion,omitempty"`
	HotReload      bool                            `json:"hotReload,omitempty"`
}

type trafficOverviewResponse struct {
	TotalRequests     int     `json:"totalRequests"`
	BlockedRequests   int     `json:"blockedRequests"`
	ObservedRequests  int     `json:"observedRequests"`
	CaptchaRequests   int     `json:"captchaRequests"`
	TempBlockRequests int     `json:"tempBlockRequests"`
	BlockRate         float64 `json:"blockRate"`
	QPS               float64 `json:"qps"`
}

type trafficRankItem struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Value int    `json:"value"`
	Count int    `json:"count"`
}

type trafficRankResponse struct {
	Items []trafficRankItem `json:"items"`
	Total int               `json:"total"`
}

type trafficTrendResponse struct {
	Trend []attackTrendPoint `json:"trend"`
	Total int                `json:"total"`
}

type systemSettings struct {
	ServerHost     string        `json:"serverHost"`
	ServerPort     int           `json:"serverPort"`
	Mode           string        `json:"mode"`
	FailOpen       bool          `json:"failOpen"`
	MaxBodySize    int64         `json:"maxBodySize"`
	EnableSemantic bool          `json:"enableSemantic"`
	EnableXDP      bool          `json:"enableXdp"`
	DatabaseDriver string        `json:"databaseDriver"`
	RulesDirectory string        `json:"rulesDirectory"`
	LoggingLevel   string        `json:"loggingLevel"`
	RuntimeStatus  healthSummary `json:"runtimeStatus"`
}
type fingerprintResponse struct {
	Fingerprints []semanticFingerprint `json:"fingerprints"`
	Total        int                   `json:"total"`
}
type semanticFingerprint struct {
	ID                string  `json:"id"`
	Hash              string  `json:"hash"`
	Language          string  `json:"language"`
	Action            string  `json:"action"`
	Status            string  `json:"status"`
	RuleID            int     `json:"ruleId"`
	Hits              int     `json:"hits"`
	FalsePositiveRate float64 `json:"falsePositiveRate"`
	Source            string  `json:"source"`
	UpdatedAt         string  `json:"updatedAt"`
}

type sitePayload struct {
	Name                string   `json:"name"`
	Domains             []string `json:"domains"`
	Domain              string   `json:"domain"`
	Upstream            string   `json:"upstream"`
	ListenPort          int      `json:"listenPort"`
	Status              string   `json:"status"`
	TLSMode             string   `json:"tlsMode"`
	CertificateID       string   `json:"certificateId"`
	WAFEnabled          *bool    `json:"wafEnabled"`
	CCProtection        *bool    `json:"ccProtection"`
	SemanticProtection  *bool    `json:"semanticProtection"`
	PolicyMode          string   `json:"policyMode"`
	BlockScoreThreshold int      `json:"blockScoreThreshold"`
	RuleGroups          []string `json:"ruleGroups"`
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if path == "/sites" || strings.HasPrefix(path, "/sites/") {
		s.handleSitesAPI(w, r, strings.TrimPrefix(path, "/sites"))
		return
	}
	if path == "/system/listeners" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, s.listenersResponse(r.Context()))
		return
	}
	if path == "/certificates" || strings.HasPrefix(path, "/certificates/") {
		s.handleCertificatesAPI(w, r, strings.TrimPrefix(path, "/certificates"))
		return
	}
	if path == "/access-rules" || strings.HasPrefix(path, "/access-rules/") {
		s.handleAccessRulesAPI(w, r, strings.TrimPrefix(path, "/access-rules"))
		return
	}
	if path == "/cc-protection" || strings.HasPrefix(path, "/cc-protection/") {
		s.handleCCProtectionAPI(w, r, strings.TrimPrefix(path, "/cc-protection"))
		return
	}
	if path == "/captcha" {
		s.handleCaptchaAPI(w, r)
		return
	}
	if path == "/protection/site-policies" || strings.HasPrefix(path, "/protection/site-policies/") {
		s.handleProtectionSitePoliciesAPI(w, r, strings.TrimPrefix(path, "/protection/site-policies"))
		return
	}
	if path == "/protection/whitelists" || strings.HasPrefix(path, "/protection/whitelists/") {
		s.handleProtectionWhitelistsAPI(w, r)
		return
	}
	if path == "/protection/request-parser/preview" {
		s.handleProtectionRequestParserPreviewAPI(w, r)
		return
	}
	if path == "/protection/cc-policies" {
		s.handleProtectionCCPoliciesAPI(w, r)
		return
	}
	if path == "/protection/cc-events" || strings.HasPrefix(path, "/protection/cc-events/") {
		s.handleProtectionCCEventsAPI(w, r, strings.TrimPrefix(path, "/protection/cc-events"))
		return
	}
	if path == "/protection/cc-blocks" || strings.HasPrefix(path, "/protection/cc-blocks/") {
		s.handleProtectionCCBlocksAPI(w, r, strings.TrimPrefix(path, "/protection/cc-blocks"))
		return
	}
	if path == "/protection/semantic-fingerprints" || strings.HasPrefix(path, "/protection/semantic-fingerprints/") {
		s.handleSemanticFingerprintsAPI(w, r, strings.TrimPrefix(path, "/protection/semantic-fingerprints"))
		return
	}
	if path == "/protection/rules" || strings.HasPrefix(path, "/protection/rules/") {
		s.handleProtectionRulesAPI(w, r, strings.TrimPrefix(path, "/protection/rules"))
		return
	}
	if path == "/protection/rule-updates" || strings.HasPrefix(path, "/protection/rule-updates/") {
		s.handleProtectionRuleUpdatesAPI(w, r, strings.TrimPrefix(path, "/protection/rule-updates"))
		return
	}
	if path == "/protection/rule-sets" {
		s.handleProtectionRuleSetsAPI(w, r)
		return
	}
	if path == "/protection/security-coverage" {
		s.handleProtectionSecurityCoverageAPI(w, r)
		return
	}
	if path == "/protection/crs/status" || path == "/protection/crs/reload" {
		s.handleProtectionCRSAPI(w, r, path)
		return
	}
	if path == "/protection/attack-events" || strings.HasPrefix(path, "/protection/traffic/") {
		s.handleProtectionTrafficAPI(w, r, path)
		return
	}
	if path == "/safety/backups" || strings.HasPrefix(path, "/safety/backups/") || path == "/safety/emergency-bypass" || path == "/upstreams/health" {
		s.handleSafetyAPI(w, r, path)
		return
	}
	if path == "/attack-logs/export" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		s.exportAttackLogs(w, r)
		return
	}
	if strings.HasPrefix(path, "/attack-logs/") {
		s.handleAttackLogActionAPI(w, r, strings.TrimPrefix(path, "/attack-logs/"))
		return
	}
	if path == "/semantic-fingerprints" || strings.HasPrefix(path, "/semantic-fingerprints/") {
		s.handleSemanticFingerprintsAPI(w, r, strings.TrimPrefix(path, "/semantic-fingerprints"))
		return
	}
	if path == "/audit-events" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.auditEvents(r))
		return
	}
	if path == "/logs/retention" {
		s.handleLogRetentionAPI(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	switch r.URL.Path {
	case "/api/dashboard/overview":
		writeJSON(w, http.StatusOK, s.dashboardOverview())
	case "/api/attack-logs":
		writeJSON(w, http.StatusOK, s.attackLogs(r))
	case "/api/attack-logs/export":
		s.exportAttackLogs(w, r)
	case "/api/access-logs":
		writeJSON(w, http.StatusOK, s.accessLogs(r))
	case "/api/settings":
		writeJSON(w, http.StatusOK, s.systemSettings())
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "api endpoint not found"})
	}
}

func (s *Server) handleSitesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.sites == nil {
		if r.Method == http.MethodGet && (suffix == "" || suffix == "/") {
			writeJSON(w, http.StatusOK, sampleSites())
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "site repository unavailable"})
		return
	}
	id, action, isAction, err := parseSiteAction(suffix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid site id"})
		return
	}
	if isAction {
		s.handleSiteEnableDisable(w, r, id, action)
		return
	}
	tail := strings.Trim(suffix, "/")
	if tail != "" && strings.HasSuffix(tail, "/runtime-status") {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		base := strings.TrimSuffix(tail, "/runtime-status")
		id, err := parseUint(base)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid site id"})
			return
		}
		writeJSON(w, http.StatusOK, s.siteRuntimeStatusResponse(r.Context(), id))
		return
	}
	id, hasID, err := parseID(strings.Trim(suffix, "/"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid site id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if hasID {
			site, err := s.sites.Get(r.Context(), id)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"message": "site not found"})
				return
			}
			writeJSON(w, http.StatusOK, s.siteToProtected(site))
			return
		}
		sites, err := s.sites.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s.sitesResponse(sites, s.blockedToday()))
	case http.MethodPost:
		var payload sitePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		if _, err := validatePolicyMode(payload.PolicyMode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		site, err := payload.toSite(0)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.applyPolicyDefaults(&site)
		_ = s.bindCertificateName(r.Context(), &site)
		if err := s.sites.Create(r.Context(), &site); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusCreated, s.siteToProtected(site))
	case http.MethodPut:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "site id required"})
			return
		}
		existing, err := s.sites.Get(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "site not found"})
			return
		}
		var payload sitePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		if strings.TrimSpace(payload.PolicyMode) != "" {
			if _, err := validatePolicyMode(payload.PolicyMode); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
		}
		updated, err := payload.merge(existing)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.applyPolicyDefaults(&updated)
		_ = s.bindCertificateName(r.Context(), &updated)
		if err := s.sites.Update(r.Context(), &updated); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, s.siteToProtected(updated))
	case http.MethodDelete:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "site id required"})
			return
		}
		if err := s.sites.Delete(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func (s *Server) handleCertificatesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		var certs []database.Certificate
		_ = s.db.WithContext(r.Context()).Order("id asc").Find(&certs).Error
		out := make([]certificateResponse, 0, len(certs))
		for _, cert := range certs {
			out = append(out, certificateToAPI(cert))
		}
		writeJSON(w, http.StatusOK, certificateListResponse{Certificates: out, Total: len(out)})
	case http.MethodPost:
		var payload certificatePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		cert := database.Certificate{Name: strings.TrimSpace(payload.Name), CertPEM: payload.CertPEM, KeyPEM: payload.KeyPEM}
		if cert.Name == "" || strings.TrimSpace(cert.CertPEM) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "name and certPem are required"})
			return
		}
		if err := cert.SetDomains(payload.Domains); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Create(&cert).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		_ = s.reloadCertificates(r.Context())
		writeJSON(w, http.StatusCreated, certificateToAPI(cert))
	case http.MethodDelete:
		id, hasID, err := parseID(strings.Trim(suffix, "/"))
		if err != nil || !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "certificate id required"})
			return
		}
		if err := s.db.WithContext(r.Context()).Delete(&database.Certificate{}, id).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		_ = s.reloadCertificates(r.Context())
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func certificateToAPI(cert database.Certificate) certificateResponse {
	return certificateResponse{ID: fmt.Sprintf("%d", cert.ID), Name: cert.Name, Domains: cert.Domains(), HasPrivateKey: strings.TrimSpace(cert.KeyPEM) != "", UpdatedAt: formatMillis(cert.UpdatedAt)}
}

func (s *Server) bindCertificateName(ctx context.Context, site *database.Site) error {
	if s == nil || s.db == nil || site == nil || site.CertificateID == 0 {
		return nil
	}
	var cert database.Certificate
	if err := s.db.WithContext(ctx).First(&cert, site.CertificateID).Error; err != nil {
		return err
	}
	site.CertificateName = cert.Name
	return nil
}

func idString(id uint) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("%d", id)
}

func normalizePolicyMode(mode string) string {
	normalized, ok := database.NormalizePolicyMode(mode)
	if !ok {
		return database.PolicyModeStandard
	}
	return normalized
}

func validatePolicyMode(mode string) (string, error) {
	normalized, ok := database.NormalizePolicyMode(mode)
	if !ok {
		return "", fmt.Errorf("invalid policyMode")
	}
	return normalized, nil
}

func policyModeDescription(mode string) string {
	switch normalizePolicyMode(mode) {
	case database.PolicyModeObserve:
		return "observe only, minimal intervention"
	case database.PolicyModeLoose:
		return "loose default, higher threshold"
	case database.PolicyModeStandard:
		return "balanced production default"
	case database.PolicyModeStrict:
		return "strict blocking, stronger semantic/cc"
	case database.PolicyModeCustom:
		return "custom site policy"
	default:
		return "balanced production default"
	}
}

func policyModeDefaults(mode string) database.PolicyModeDefaults {
	defaults, ok := database.PolicyModeDefaultsFor(mode)
	if !ok {
		defaults, _ = database.PolicyModeDefaultsFor(database.PolicyModeStandard)
	}
	return defaults
}

func (s *Server) applyPolicyDefaults(site *database.Site) {
	if site == nil {
		return
	}
	mode := normalizePolicyMode(site.PolicyMode)
	defaults := policyModeDefaults(mode)
	site.PolicyMode = mode
	if site.BlockScoreThreshold <= 0 || mode != database.PolicyModeCustom {
		site.BlockScoreThreshold = defaults.BlockScoreThreshold
	}
	if mode != database.PolicyModeCustom {
		_ = site.SetRuleGroups(defaults.RuleGroups)
	} else if len(site.RuleGroups()) == 0 {
		_ = site.SetRuleGroups(defaults.RuleGroups)
	}
	if site.Status == "" {
		site.Status = database.SiteStatusEnabled
	}
}

func (s *Server) handleAccessRulesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		if r.Method == http.MethodGet && (suffix == "" || suffix == "/") {
			writeJSON(w, http.StatusOK, accessControlResponse{Rules: []accessRule{}, Total: 0})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	id, hasID, err := parseID(strings.Trim(suffix, "/"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid rule id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.accessRules())
	case http.MethodPost:
		var payload accessRulePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		rule, err := payload.toModel(0)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Create(&rule).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusCreated, accessRuleToAPI(rule))
	case http.MethodPut:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "rule id required"})
			return
		}
		var existing database.AccessRule
		if err := s.db.WithContext(r.Context()).First(&existing, id).Error; err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "rule not found"})
			return
		}
		var payload accessRulePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		updated, err := payload.merge(existing)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Save(&updated).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, accessRuleToAPI(updated))
	case http.MethodDelete:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "rule id required"})
			return
		}
		if err := s.db.WithContext(r.Context()).Delete(&database.AccessRule{}, id).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func (p accessRulePayload) toModel(id uint) (database.AccessRule, error) {
	rule := database.AccessRule{ID: id, Type: strings.TrimSpace(p.Type), Value: strings.TrimSpace(p.Value), Description: strings.TrimSpace(p.Description), Enabled: true}
	if p.Enabled != nil {
		rule.Enabled = *p.Enabled
	} else if strings.TrimSpace(p.Status) != "" {
		rule.Enabled = p.Status == "enabled"
	}
	if rule.Type == "" || rule.Value == "" {
		return rule, fmt.Errorf("type and value are required")
	}
	switch rule.Type {
	case database.AccessRuleIPBlacklist, database.AccessRuleIPWhitelist, database.AccessRuleURLWhitelist, database.AccessRuleParamWhitelist, database.AccessRuleRuleDisable, database.AccessRuleUABlacklist, database.AccessRuleMethodBlock:
	default:
		return rule, fmt.Errorf("unsupported access rule type")
	}
	return rule, nil
}
func (p accessRulePayload) merge(existing database.AccessRule) (database.AccessRule, error) {
	next, err := p.toModel(existing.ID)
	if err != nil {
		return existing, err
	}
	next.SiteID = existing.SiteID
	next.Hits = existing.Hits
	next.CreatedAt = existing.CreatedAt
	return next, nil
}
func accessRuleToAPI(rule database.AccessRule) accessRule {
	status := "disabled"
	if rule.Enabled {
		status = "enabled"
	}
	return accessRule{ID: fmt.Sprintf("%d", rule.ID), Type: rule.Type, Value: rule.Value, Description: rule.Description, Status: status, Hits: int(rule.Hits), UpdatedAt: formatMillis(rule.UpdatedAt)}
}

func (s *Server) handleCCProtectionAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		if r.Method == http.MethodGet && (suffix == "" || suffix == "/") {
			writeJSON(w, http.StatusOK, ccProtectionResponse{Stats: ccStats{}, Policies: []ccPolicy{}})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	id, hasID, err := parseID(strings.Trim(suffix, "/"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid policy id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.ccProtection())
	case http.MethodPost:
		var payload ccPolicyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		policy, err := payload.toModel(0)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Create(&policy).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusCreated, ccPolicyToAPI(policy))
	case http.MethodPut:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "policy id required"})
			return
		}
		var existing database.CCPolicy
		if err := s.db.WithContext(r.Context()).First(&existing, id).Error; err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "policy not found"})
			return
		}
		var payload ccPolicyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		updated, err := payload.merge(existing)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Save(&updated).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, ccPolicyToAPI(updated))
	case http.MethodDelete:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "policy id required"})
			return
		}
		if err := s.db.WithContext(r.Context()).Delete(&database.CCPolicy{}, id).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}
func (p ccPolicyPayload) toModel(id uint) (database.CCPolicy, error) {
	policy := database.CCPolicy{ID: id, Name: strings.TrimSpace(p.Name), Scope: strings.TrimSpace(p.Scope), Threshold: p.Threshold, WindowSeconds: p.WindowSeconds, Action: strings.TrimSpace(p.Action), Priority: p.Priority, Enabled: true}
	if strings.TrimSpace(p.SiteID) != "" {
		siteID, err := strconv.ParseUint(strings.TrimSpace(p.SiteID), 10, 64)
		if err != nil {
			return policy, fmt.Errorf("invalid siteId")
		}
		policy.SiteID = uint(siteID)
	}
	if policy.Priority <= 0 {
		policy.Priority = 100
	}
	if p.Enabled != nil {
		policy.Enabled = *p.Enabled
	}
	if policy.Name == "" || policy.Scope == "" {
		return policy, fmt.Errorf("name and scope are required")
	}
	if policy.Threshold <= 0 {
		return policy, fmt.Errorf("threshold must be positive")
	}
	if policy.WindowSeconds <= 0 {
		return policy, fmt.Errorf("windowSeconds must be positive")
	}
	if !validCCActionChain(policy.Action) {
		return policy, fmt.Errorf("unsupported cc action")
	}
	return policy, nil
}

func validCCActionChain(action string) bool {
	parts := strings.FieldsFunc(action, func(r rune) bool { return r == '>' || r == ',' || r == '|' })
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case database.CCActionObserve, database.CCActionBlock, database.CCActionCaptcha, database.CCActionTempBlock, database.CCActionLongBlock:
		default:
			return false
		}
	}
	return true
}

func (p ccPolicyPayload) merge(existing database.CCPolicy) (database.CCPolicy, error) {
	next, err := p.toModel(existing.ID)
	if err != nil {
		return existing, err
	}
	if strings.TrimSpace(p.SiteID) == "" {
		next.SiteID = existing.SiteID
	}
	next.Hits = existing.Hits
	next.CreatedAt = existing.CreatedAt
	return next, nil
}
func ccPolicyToAPI(policy database.CCPolicy) ccPolicy {
	return ccPolicy{ID: fmt.Sprintf("%d", policy.ID), SiteID: idString(policy.SiteID), Name: policy.Name, Scope: policy.Scope, Threshold: policy.Threshold, WindowSeconds: policy.WindowSeconds, Action: policy.Action, Priority: policy.Priority, Enabled: policy.Enabled, HitsToday: int(policy.Hits)}
}

func (s *Server) handleProtectionSitePoliciesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, siteProtectionPolicyResponse{Policies: []siteProtectionPolicy{}, Total: 0})
		return
	}
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = nil
	}
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.listSiteProtectionPolicies(r.Context()))
		return
	}
	siteID, _, err := parseID(parts[0])
	if err != nil || siteID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid site id"})
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			policy, err := s.siteProtectionPolicyForSite(r.Context(), siteID)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"message": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, policy)
		case http.MethodPut:
			policy, err := s.saveSiteProtectionPolicyDraft(r.Context(), siteID, r)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, policy)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		}
		return
	}
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "site policy endpoint not found"})
		return
	}
	switch parts[1] {
	case "versions":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.sitePolicyVersions(r.Context(), siteID))
	case "publish":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		policy, err := s.publishSiteProtectionPolicy(r.Context(), siteID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, policy)
	case "rollback":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		policy, err := s.rollbackSiteProtectionPolicy(r.Context(), siteID, r.URL.Query().Get("version"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, policy)
	case "audit":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.sitePolicyAudit(r.Context(), siteID))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "site policy endpoint not found"})
	}
}

func (s *Server) listSiteProtectionPolicies(ctx context.Context) siteProtectionPolicyResponse {
	var sites []database.Site
	_ = s.db.WithContext(ctx).Order("id asc").Find(&sites).Error
	policies := make([]siteProtectionPolicy, 0, len(sites))
	for _, site := range sites {
		policy, err := s.siteProtectionPolicyForSite(ctx, site.ID)
		if err != nil {
			groups := site.RuleGroups()
			defaults := policyModeDefaults(site.PolicyMode)
			policies = append(policies, siteProtectionPolicy{SiteID: fmt.Sprintf("%d", site.ID), SiteName: site.Name, Mode: defaults.Mode, EnabledRuleGroups: groups, RuleGroups: groups, CRSParanoiaLevel: 1, InboundThreshold: site.BlockScoreThreshold, OutboundThreshold: site.BlockScoreThreshold, DefaultAction: defaults.DefaultAction, RuntimeVersion: fmt.Sprintf("site-%d-%d", site.ID, site.UpdatedAt), PublishedAt: formatMillis(site.UpdatedAt), UpdatedAt: formatMillis(site.UpdatedAt)})
			continue
		}
		policies = append(policies, policy)
	}
	return siteProtectionPolicyResponse{Policies: policies, Total: len(policies)}
}

func (s *Server) siteProtectionPolicyForSite(ctx context.Context, siteID uint) (siteProtectionPolicy, error) {
	var site database.Site
	if err := s.db.WithContext(ctx).First(&site, siteID).Error; err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("site not found")
	}
	var policy database.SiteProtectionPolicy
	if err := s.db.WithContext(ctx).Where("site_id = ?", siteID).First(&policy).Error; err != nil {
		policy = s.defaultSiteProtectionPolicy(site)
	}
	return sitePolicyToAPI(policy), nil
}

func (s *Server) defaultSiteProtectionPolicy(site database.Site) database.SiteProtectionPolicy {
	mode := normalizePolicyMode(site.PolicyMode)
	defaults := policyModeDefaults(mode)
	threshold := site.BlockScoreThreshold
	if threshold <= 0 {
		threshold = defaults.BlockScoreThreshold
	}
	policy := database.SiteProtectionPolicy{SiteID: site.ID, SiteName: site.Name, Mode: mode, CRSParanoiaLevel: 1, InboundThreshold: threshold, OutboundThreshold: threshold, DefaultAction: defaults.DefaultAction, RuntimeVersion: fmt.Sprintf("site-%d-%d", site.ID, site.UpdatedAt), PublishedAt: site.UpdatedAt}
	_ = policy.SetEnabledRuleGroups(normalizeRuleGroups(site.RuleGroups()))
	return policy
}

func (s *Server) saveSiteProtectionPolicyDraft(ctx context.Context, siteID uint, r *http.Request) (siteProtectionPolicy, error) {
	var site database.Site
	if err := s.db.WithContext(ctx).First(&site, siteID).Error; err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("site not found")
	}
	var payload siteProtectionPolicyPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("invalid json")
	}
	policy := s.defaultSiteProtectionPolicy(site)
	_ = s.db.WithContext(ctx).Where("site_id = ?", siteID).First(&policy).Error
	if err := applySiteProtectionPolicyPayload(&policy, payload); err != nil {
		return siteProtectionPolicy{}, err
	}
	policy.SiteID = site.ID
	policy.SiteName = site.Name
	if err := s.db.WithContext(ctx).Where("site_id = ?", siteID).Save(&policy).Error; err != nil {
		return siteProtectionPolicy{}, err
	}
	return sitePolicyToAPI(policy), nil
}

func applySiteProtectionPolicyPayload(policy *database.SiteProtectionPolicy, payload siteProtectionPolicyPayload) error {
	mode, err := validatePolicyMode(payload.Mode)
	if err != nil {
		return err
	}
	defaults := policyModeDefaults(mode)
	policy.Mode = mode
	groups := payload.EnabledRuleGroups
	if len(groups) == 0 {
		groups = payload.RuleGroups
	}
	if mode != database.PolicyModeCustom || len(groups) == 0 {
		groups = defaults.RuleGroups
	}
	_ = policy.SetEnabledRuleGroups(normalizeRuleGroups(groups))
	if payload.CRSParanoiaLevel > 0 {
		policy.CRSParanoiaLevel = payload.CRSParanoiaLevel
	} else if policy.CRSParanoiaLevel <= 0 {
		policy.CRSParanoiaLevel = 1
	}
	if mode != database.PolicyModeCustom {
		policy.InboundThreshold = defaults.BlockScoreThreshold
	} else if payload.InboundThreshold > 0 {
		policy.InboundThreshold = payload.InboundThreshold
	} else if policy.InboundThreshold <= 0 {
		policy.InboundThreshold = defaults.BlockScoreThreshold
	}
	if mode != database.PolicyModeCustom {
		policy.OutboundThreshold = policy.InboundThreshold
	} else if payload.OutboundThreshold > 0 {
		policy.OutboundThreshold = payload.OutboundThreshold
	} else if policy.OutboundThreshold <= 0 {
		policy.OutboundThreshold = policy.InboundThreshold
	}
	if mode != database.PolicyModeCustom || strings.TrimSpace(payload.DefaultAction) == "" {
		policy.DefaultAction = defaults.DefaultAction
	} else {
		policy.DefaultAction = normalizePolicyAction(payload.DefaultAction)
	}
	return nil
}

func normalizePolicyAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "log", "observe", "block":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return "block"
	}
}

func (s *Server) publishSiteProtectionPolicy(ctx context.Context, siteID uint) (siteProtectionPolicy, error) {
	var site database.Site
	if err := s.db.WithContext(ctx).First(&site, siteID).Error; err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("site not found")
	}
	policy := s.defaultSiteProtectionPolicy(site)
	_ = s.db.WithContext(ctx).Where("site_id = ?", siteID).First(&policy).Error
	policy.SiteID = site.ID
	policy.SiteName = site.Name
	if _, err := validatePolicyMode(policy.Mode); err != nil {
		return siteProtectionPolicy{}, err
	}
	policy.Mode = normalizePolicyMode(policy.Mode)
	defaults := policyModeDefaults(policy.Mode)
	if policy.Mode != database.PolicyModeCustom || policy.InboundThreshold <= 0 {
		policy.InboundThreshold = defaults.BlockScoreThreshold
	}
	if policy.Mode != database.PolicyModeCustom || policy.OutboundThreshold <= 0 {
		policy.OutboundThreshold = policy.InboundThreshold
	}
	if policy.CRSParanoiaLevel <= 0 {
		policy.CRSParanoiaLevel = 1
	}
	if policy.Mode != database.PolicyModeCustom {
		policy.DefaultAction = defaults.DefaultAction
		_ = policy.SetEnabledRuleGroups(defaults.RuleGroups)
	} else {
		policy.DefaultAction = normalizePolicyAction(policy.DefaultAction)
	}
	now := time.Now().UnixMilli()
	version := fmt.Sprintf("v%d", time.Now().UnixNano())
	policy.RuntimeVersion = version
	policy.PublishedAt = now
	if err := s.applyPublishedPolicyToSite(ctx, &site, policy); err != nil {
		return siteProtectionPolicy{}, err
	}
	if err := s.db.WithContext(ctx).Save(&policy).Error; err != nil {
		return siteProtectionPolicy{}, err
	}
	versionRow := database.PolicyVersion{SiteID: site.ID, Version: version, Mode: policy.Mode, CRSParanoiaLevel: policy.CRSParanoiaLevel, InboundThreshold: policy.InboundThreshold, OutboundThreshold: policy.OutboundThreshold, DefaultAction: policy.DefaultAction}
	_ = versionRow.SetEnabledRuleGroups(policy.EnabledRuleGroups())
	_ = s.db.WithContext(ctx).Create(&versionRow).Error
	_ = s.db.WithContext(ctx).Create(&database.PolicyAudit{SiteID: site.ID, SiteName: site.Name, Version: version, Action: "publish", Detail: fmt.Sprintf("mode=%s inbound=%d groups=%s", policy.Mode, policy.InboundThreshold, strings.Join(policy.EnabledRuleGroups(), ","))}).Error
	s.recordAuditEvent(ctx, "site_policy", site.ID, site.Name, fmt.Sprintf("site-policy:%d", site.ID), "publish", version)
	return sitePolicyToAPI(policy), nil
}

func (s *Server) rollbackSiteProtectionPolicy(ctx context.Context, siteID uint, version string) (siteProtectionPolicy, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return siteProtectionPolicy{}, fmt.Errorf("version is required")
	}
	var site database.Site
	if err := s.db.WithContext(ctx).First(&site, siteID).Error; err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("site not found")
	}
	var snapshot database.PolicyVersion
	if err := s.db.WithContext(ctx).Where("site_id = ? AND version = ?", siteID, version).Order("id desc").First(&snapshot).Error; err != nil {
		return siteProtectionPolicy{}, fmt.Errorf("policy version not found")
	}
	policy := database.SiteProtectionPolicy{SiteID: site.ID, SiteName: site.Name, Mode: normalizePolicyMode(snapshot.Mode), CRSParanoiaLevel: snapshot.CRSParanoiaLevel, InboundThreshold: snapshot.InboundThreshold, OutboundThreshold: snapshot.OutboundThreshold, DefaultAction: normalizePolicyAction(snapshot.DefaultAction), RuntimeVersion: fmt.Sprintf("rollback-%d", time.Now().UnixMilli()), PublishedAt: time.Now().UnixMilli()}
	_ = policy.SetEnabledRuleGroups(snapshot.EnabledRuleGroups())
	var existing database.SiteProtectionPolicy
	if err := s.db.WithContext(ctx).Where("site_id = ?", siteID).First(&existing).Error; err == nil {
		policy.ID = existing.ID
		policy.CreatedAt = existing.CreatedAt
	}
	if err := s.applyPublishedPolicyToSite(ctx, &site, policy); err != nil {
		return siteProtectionPolicy{}, err
	}
	if err := s.db.WithContext(ctx).Save(&policy).Error; err != nil {
		return siteProtectionPolicy{}, err
	}
	_ = s.db.WithContext(ctx).Create(&database.PolicyAudit{SiteID: site.ID, SiteName: site.Name, Version: version, Action: "rollback", Detail: fmt.Sprintf("rolled back to %s", version)}).Error
	s.recordAuditEvent(ctx, "site_policy", site.ID, site.Name, fmt.Sprintf("site-policy:%d", site.ID), "rollback", version)
	return sitePolicyToAPI(policy), nil
}

func (s *Server) applyPublishedPolicyToSite(ctx context.Context, site *database.Site, policy database.SiteProtectionPolicy) error {
	site.PolicyMode = normalizePolicyMode(policy.Mode)
	defaults := policyModeDefaults(site.PolicyMode)
	site.BlockScoreThreshold = policy.InboundThreshold
	if site.PolicyMode != database.PolicyModeCustom || site.BlockScoreThreshold <= 0 {
		site.BlockScoreThreshold = defaults.BlockScoreThreshold
	}
	site.WAFEnabled = normalizePolicyAction(policy.DefaultAction) != "allow"
	site.CCProtection = defaults.CCProtection
	site.SemanticProtection = defaults.SemanticProtection
	groups := policy.EnabledRuleGroups()
	if site.PolicyMode != database.PolicyModeCustom || len(groups) == 0 {
		groups = defaults.RuleGroups
	}
	if err := site.SetRuleGroups(normalizeRuleGroups(groups)); err != nil {
		return err
	}
	if s.sites != nil {
		return s.sites.Update(ctx, site)
	}
	return s.db.WithContext(ctx).Save(site).Error
}

func (s *Server) sitePolicyVersions(ctx context.Context, siteID uint) map[string]any {
	var versions []database.PolicyVersion
	_ = s.db.WithContext(ctx).Where("site_id = ?", siteID).Order("id desc").Find(&versions).Error
	out := make([]siteProtectionPolicy, 0, len(versions))
	for _, version := range versions {
		policy := database.SiteProtectionPolicy{SiteID: version.SiteID, Mode: version.Mode, CRSParanoiaLevel: version.CRSParanoiaLevel, InboundThreshold: version.InboundThreshold, OutboundThreshold: version.OutboundThreshold, DefaultAction: version.DefaultAction, RuntimeVersion: version.Version, PublishedAt: version.CreatedAt, UpdatedAt: version.CreatedAt}
		_ = policy.SetEnabledRuleGroups(version.EnabledRuleGroups())
		out = append(out, sitePolicyToAPI(policy))
	}
	return map[string]any{"versions": out, "total": len(out)}
}

func (s *Server) sitePolicyAudit(ctx context.Context, siteID uint) sitePolicyAuditResponse {
	var events []database.PolicyAudit
	_ = s.db.WithContext(ctx).Where("site_id = ?", siteID).Order("id desc").Limit(100).Find(&events).Error
	out := make([]sitePolicyAuditEntry, 0, len(events))
	for _, event := range events {
		out = append(out, sitePolicyAuditEntry{ID: fmt.Sprintf("%d", event.ID), Time: formatMillis(event.CreatedAt), SiteID: fmt.Sprintf("%d", event.SiteID), SiteName: event.SiteName, Version: event.Version, Action: event.Action, Detail: event.Detail})
	}
	return sitePolicyAuditResponse{Events: out, Total: len(out)}
}

func sitePolicyToAPI(policy database.SiteProtectionPolicy) siteProtectionPolicy {
	groups := normalizeRuleGroups(policy.EnabledRuleGroups())
	return siteProtectionPolicy{SiteID: fmt.Sprintf("%d", policy.SiteID), SiteName: policy.SiteName, Mode: normalizePolicyMode(policy.Mode), EnabledRuleGroups: groups, RuleGroups: groups, CRSParanoiaLevel: policy.CRSParanoiaLevel, InboundThreshold: policy.InboundThreshold, OutboundThreshold: policy.OutboundThreshold, DefaultAction: normalizePolicyAction(policy.DefaultAction), RuntimeVersion: policy.RuntimeVersion, PublishedAt: formatMillis(policy.PublishedAt), UpdatedAt: formatMillis(policy.UpdatedAt)}
}

func (s *Server) handleProtectionWhitelistsAPI(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, protectionWhitelistResponse{Whitelists: []protectionWhitelist{}, Total: 0})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	id, hasID, err := parseID(strings.Trim(r.URL.Path[strings.LastIndex(r.URL.Path, "/protection/whitelists")+len("/protection/whitelists"):], "/"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid whitelist id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.protectionWhitelists(r))
	case http.MethodPost:
		var payload whitelistApplyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		rule, err := whitelistPayloadToRule(payload, database.AttackLog{})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Create(&rule).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "whitelist_created", rule.SiteID, "", fmt.Sprintf("access-rule:%d", rule.ID), rule.Type, rule.Description)
		s.reloadRuntime(r)
		writeJSON(w, http.StatusCreated, accessRuleToAPI(rule))
	case http.MethodPut:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "whitelist id required"})
			return
		}
		var existing database.AccessRule
		if err := s.db.WithContext(r.Context()).First(&existing, id).Error; err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "whitelist not found"})
			return
		}
		var payload whitelistApplyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		updated, err := whitelistPayloadToRule(payload, database.AttackLog{SiteID: existing.SiteID})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		updated.ID, updated.Hits, updated.CreatedAt = existing.ID, existing.Hits, existing.CreatedAt
		if err := s.db.WithContext(r.Context()).Save(&updated).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "whitelist_updated", updated.SiteID, "", fmt.Sprintf("access-rule:%d", updated.ID), updated.Type, updated.Description)
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, accessRuleToAPI(updated))
	case http.MethodDelete:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "whitelist id required"})
			return
		}
		if err := s.db.WithContext(r.Context()).Delete(&database.AccessRule{}, id).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "whitelist_deleted", 0, "", fmt.Sprintf("access-rule:%d", id), "delete", "delete whitelist/exclusion")
		s.reloadRuntime(r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func (s *Server) protectionWhitelists(r *http.Request) protectionWhitelistResponse {
	var rules []database.AccessRule
	query := s.db.WithContext(r.Context()).Where("type IN ?", whitelistRuleTypes())
	if siteID := strings.TrimSpace(r.URL.Query().Get("siteId")); siteID != "" {
		query = query.Where("site_id = ?", siteID)
	}
	if enabled := strings.TrimSpace(r.URL.Query().Get("enabled")); enabled != "" {
		query = query.Where("enabled = ?", enabled == "true" || enabled == "1")
	}
	_ = query.Order("id asc").Find(&rules).Error
	whitelists := make([]protectionWhitelist, 0, len(rules))
	for _, rule := range rules {
		whitelists = append(whitelists, accessRuleToWhitelist(rule))
	}
	return protectionWhitelistResponse{Whitelists: whitelists, Total: len(whitelists)}
}

func whitelistRuleTypes() []string {
	return []string{database.AccessRuleIPWhitelist, database.AccessRuleCIDRWhitelist, database.AccessRuleURLWhitelist, database.AccessRuleParamWhitelist, database.AccessRuleHeaderWhitelist, database.AccessRuleCookieWhitelist, database.AccessRuleRuleDisable}
}

func accessRuleToWhitelist(rule database.AccessRule) protectionWhitelist {
	return protectionWhitelist{ID: fmt.Sprintf("%d", rule.ID), SiteID: idString(rule.SiteID), Type: rule.Type, Pattern: rule.Value, Reason: rule.Description, Scope: firstNonEmpty(rule.Scope, "site"), RuleID: rule.RuleID, Variable: rule.Variable, ExpiresAt: formatMillis(rule.ExpiresAt), Enabled: rule.Enabled, CreatedFrom: firstNonEmpty(rule.CreatedFrom, "access-rules"), UpdatedAt: formatMillis(rule.UpdatedAt)}
}

func (s *Server) handleProtectionRequestParserPreviewAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload requestParserPreviewPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	method, uri, headers, body := previewRequestParts(payload)
	parsed := requestparser.Parse(method, uri, headers, []byte(body), requestparser.Options{MaxBodySize: s.security.MaxBodySize, FailOpen: payload.FailOpen})
	writeJSON(w, http.StatusOK, previewResponseFromParsed(payload.RawRequest, body, headers, parsed))
}

func previewResponseFromParsed(rawRequest, body string, headers http.Header, parsed requestparser.ParsedRequest) requestParserPreviewResponse {
	response := requestParserPreviewResponse{RawRequest: rawRequest, Method: parsed.Method, RawURI: parsed.RawURI, NormalizedURI: parsed.NormalizedPath, Path: parsed.Path, NormalizedPath: parsed.NormalizedPath, ContentType: parsed.ContentType, Headers: map[string]string{}, Cookies: map[string]string{}, BodyText: body, JSONFields: []string{}, MultipartFields: []string{}, MatchedVariables: []string{}, Fields: parsed.Fields, DecodeSteps: parsed.DecodeSteps, ParseErrors: parsed.ParseErrors, BodyTooLarge: parsed.BodyTooLarge, FailOpen: parsed.FailOpen, InspectionAllowed: parsed.InspectionAllowed}
	if idx := strings.Index(parsed.RawURI, "?"); idx >= 0 && idx+1 < len(parsed.RawURI) {
		response.NormalizedQuery = parsed.RawURI[idx+1:]
	}
	for key, values := range headers {
		if len(values) > 0 {
			response.Headers[key] = values[0]
		}
	}
	for _, field := range parsed.Fields {
		if field.Variable != "" {
			response.MatchedVariables = append(response.MatchedVariables, field.Variable)
		}
		switch field.Source {
		case "cookie":
			response.Cookies[field.Name] = field.NormalizedValue
		case "json":
			response.JSONFields = append(response.JSONFields, field.Variable)
		case "multipart":
			response.MultipartFields = append(response.MultipartFields, field.Variable)
		}
	}
	return response
}

func previewRequestParts(payload requestParserPreviewPayload) (string, string, http.Header, string) {
	method := firstNonEmpty(payload.Method, http.MethodGet)
	uri := firstNonEmpty(payload.URI, "/")
	headers := http.Header{}
	for key, value := range payload.Headers {
		headers.Set(key, value)
	}
	body := payload.Body
	if strings.TrimSpace(payload.RawRequest) == "" {
		return method, uri, headers, body
	}
	lines := strings.Split(strings.ReplaceAll(payload.RawRequest, "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(strings.TrimSpace(lines[0]))
		if len(parts) >= 1 {
			method = parts[0]
		}
		if len(parts) >= 2 {
			uri = parts[1]
		}
	}
	bodyStart := -1
	for idx, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			bodyStart = idx + 2
			break
		}
		if key, value, ok := strings.Cut(line, ":"); ok {
			headers.Set(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	if bodyStart >= 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}
	return method, uri, headers, body
}

func (s *Server) handleProtectionCCPoliciesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	protection := s.ccProtection()
	writeJSON(w, http.StatusOK, map[string]any{"policies": protection.Policies, "total": len(protection.Policies)})
}

func (s *Server) handleProtectionCCEventsAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if s.db == nil {
		writeEmptyCCEventsResponse(w, suffix)
		return
	}
	suffix = strings.Trim(suffix, "/")
	var logs []database.AttackLog
	query := s.db.WithContext(r.Context()).Where("stage = ? OR attack_type LIKE ? OR attack_type LIKE ? OR attack_type LIKE ?", "cc", "%cc%", "%scanner%", "%bot%")
	if attackType := strings.TrimSpace(r.URL.Query().Get("attackType")); attackType != "" {
		query = query.Where("attack_type LIKE ?", "%"+attackType+"%")
	}
	_ = query.Order("created_at desc, id desc").Limit(1000).Find(&logs).Error
	switch suffix {
	case "trend":
		writeJSON(w, http.StatusOK, attackTrendFromLogs(logs))
	case "top-ip":
		writeJSON(w, http.StatusOK, attackRankFromLogs(logs, func(log database.AttackLog) string { return log.SourceIP }, 10))
	case "top-path":
		writeJSON(w, http.StatusOK, attackRankFromLogs(logs, func(log database.AttackLog) string { return log.Path }, 10))
	case "top-ua":
		writeJSON(w, http.StatusOK, attackRankFromLogs(logs, attackLogUserAgent, 10))
	case "":
		writeJSON(w, http.StatusOK, ccBotEventsFromLogs(logs))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "cc events endpoint not found"})
	}
}

func writeEmptyCCEventsResponse(w http.ResponseWriter, suffix string) {
	switch strings.Trim(suffix, "/") {
	case "trend":
		writeJSON(w, http.StatusOK, trafficTrendResponse{Trend: []attackTrendPoint{}, Total: 0})
	case "top-ip", "top-path", "top-ua":
		writeJSON(w, http.StatusOK, trafficRankResponse{Items: []trafficRankItem{}, Total: 0})
	default:
		writeJSON(w, http.StatusOK, ccBotEventResponse{Events: []ccBotEvent{}, Total: 0})
	}
}

func ccBotEventsFromLogs(logs []database.AttackLog) ccBotEventResponse {
	events := make([]ccBotEvent, 0, len(logs))
	for _, log := range logs {
		events = append(events, ccBotEvent{ID: fmt.Sprintf("%d", log.ID), Time: formatMillis(log.CreatedAt), SiteName: log.SiteName, SourceIP: log.SourceIP, PolicyName: firstNonEmpty(log.RuleMessage, log.RuleID), Scope: log.Path, Action: log.Action, Count: 1, Threshold: log.Score})
	}
	return ccBotEventResponse{Events: events, Total: len(events)}
}

func attackTrendFromLogs(logs []database.AttackLog) trafficTrendResponse {
	counts := map[string]int{}
	for _, log := range logs {
		day := time.UnixMilli(log.CreatedAt).Format("01-02")
		counts[day]++
	}
	days := make([]string, 0, len(counts))
	for day := range counts {
		days = append(days, day)
	}
	sort.Strings(days)
	trend := make([]attackTrendPoint, 0, len(days))
	for _, day := range days {
		count := counts[day]
		trend = append(trend, attackTrendPoint{Time: day, Requests: count, Blocked: count})
	}
	return trafficTrendResponse{Trend: trend, Total: len(trend)}
}

func attackRankFromLogs(logs []database.AttackLog, value func(database.AttackLog) string, limit int) trafficRankResponse {
	counts := map[string]int{}
	for _, log := range logs {
		key := strings.TrimSpace(value(log))
		if key != "" {
			counts[key]++
		}
	}
	items := make([]trafficRankItem, 0, len(counts))
	for key, count := range counts {
		items = append(items, trafficRankItem{Name: key, Key: key, Value: count, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return trafficRankResponse{Items: items, Total: len(items)}
}

func attackLogUserAgent(log database.AttackLog) string {
	marker := "User-Agent:"
	idx := strings.Index(log.PayloadSnippet, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(log.PayloadSnippet[idx+len(marker):])
	for _, sep := range []string{"\\n", "\n", "\r", "\""} {
		if lineEnd := strings.Index(rest, sep); lineEnd >= 0 {
			rest = rest[:lineEnd]
		}
	}
	return strings.TrimSpace(rest)
}

func (s *Server) handleProtectionCCBlocksAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.ccLimiter == nil {
		writeJSON(w, http.StatusOK, ccBlockResponse{Blocks: []ccBlockEntry{}, Total: 0})
		return
	}
	suffix = strings.Trim(suffix, "/")
	switch r.Method {
	case http.MethodGet:
		blocks := s.ccLimiter.ActiveBlocks(nil)
		entries := make([]ccBlockEntry, 0, len(blocks))
		for _, block := range blocks {
			entries = append(entries, ccActiveBlockToAPI(block))
		}
		writeJSON(w, http.StatusOK, ccBlockResponse{Blocks: entries, Total: len(entries)})
	case http.MethodDelete:
		if suffix == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "block key or ip is required"})
			return
		}
		value, err := url.PathUnescape(suffix)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid block key"})
			return
		}
		removed := 0
		if strings.HasPrefix(value, "ip/") {
			ip := net.ParseIP(strings.TrimPrefix(value, "ip/"))
			if ip == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid source ip"})
				return
			}
			removed = s.ccLimiter.UnblockIP(ip)
		} else if s.ccLimiter.Unblock(value) {
			removed = 1
		}
		if removed == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "cc block not found"})
			return
		}
		s.recordAuditEvent(r.Context(), "cc_block_unblock", 0, "", "cc-block", "unblock", fmt.Sprintf("unblocked %s removed=%d", value, removed))
		writeJSON(w, http.StatusOK, map[string]any{"status": "unblocked", "removed": removed})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func ccActiveBlockToAPI(block cc.ActiveBlock) ccBlockEntry {
	remaining := int64(time.Until(block.BlockUntil).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return ccBlockEntry{Key: block.Key, SourceIP: block.SourceIP, PolicyID: idString(block.Policy.ID), PolicyName: block.Policy.Name, Scope: block.Policy.Scope, Action: string(block.Decision), Count: block.Count, BlockUntil: block.BlockUntil.Format(time.RFC3339), RemainingSeconds: remaining, RecentPath: block.RecentPath, UserAgent: block.UserAgent}
}

func (s *Server) handleProtectionRuleSetsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	groups := map[string]*protectionRuleSet{}
	if s.crsManager != nil {
		status := s.crsManager.Status()
		groups["crs:owasp-crs"] = &protectionRuleSet{ID: "crs:owasp-crs", Name: firstNonEmpty(status.Version, "OWASP CRS"), Source: "crs", Version: status.Version, Enabled: status.Enabled && status.Loaded, RuleCount: status.RuleCount}
	}
	runtimeRules, _, _ := s.runtimeProtectionRules(r.Context())
	for _, rule := range runtimeRules {
		source := firstNonEmpty(rule.Source, "custom")
		category := firstNonEmpty(rule.Category, "default")
		key := source + ":" + category
		set := groups[key]
		if set == nil {
			set = &protectionRuleSet{ID: key, Name: category, Source: source, Version: "runtime", Enabled: true}
			groups[key] = set
		}
		set.RuleCount++
		set.Enabled = set.Enabled && rule.Enabled
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]protectionRuleSet, 0, len(keys))
	for _, key := range keys {
		out = append(out, *groups[key])
	}
	writeJSON(w, http.StatusOK, protectionRuleSetResponse{RuleSets: out, Total: len(out)})
}

func (s *Server) handleProtectionCRSAPI(w http.ResponseWriter, r *http.Request, path string) {
	if s.crsManager == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "loaded": false, "ruleCount": 0, "fileCount": 0})
		return
	}
	switch path {
	case "/protection/crs/status":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.crsManager.Status())
	case "/protection/crs/reload":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		if err := s.crsManager.Reload(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		if s.detectionEngine != nil {
			if err := s.detectionEngine.Reload(r.Context()); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
				return
			}
		}
		s.recordAuditEvent(r.Context(), "crs_reload", 0, "", "crs", "reload", "OWASP CRS rules reloaded")
		writeJSON(w, http.StatusOK, s.crsManager.Status())
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "api endpoint not found"})
	}
}

func (s *Server) handleProtectionSecurityCoverageAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	result, err := securityeval.Evaluate(r.Context(), securityeval.Options{})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, securityCoverageResponse{
		GeneratedAt:           result.GeneratedAt.Format("2006-01-02"),
		RuleFileCount:         result.RuleFileCount,
		RuleCount:             result.RuleCount,
		AttackTotal:           result.AttackTotal,
		AttackBlocked:         result.AttackBlocked,
		AttackBlockRate:       result.AttackBlockRate,
		BenignTotal:           result.BenignTotal,
		BenignFalsePositives:  result.BenignFalsePositives,
		BenignFalseRate:       result.BenignFalseRate,
		MissedAttacks:         result.MissedAttacks,
		FalsePositives:        result.FalsePositives,
		AttackBlockRateTarget: result.Thresholds.AttackBlockRate,
		FalsePositiveLimit:    result.Thresholds.BenignFalsePositives,
	})
}

func (s *Server) handleProtectionRuleUpdatesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	operation := strings.Trim(strings.TrimSpace(suffix), "/")
	switch operation {
	case "", "/":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.ruleUpdateSummary(r.Context()))
	case "sources":
		s.handleProtectionRuleUpdateSourcesAPI(w, r)
	case "publish":
		s.handleProtectionRuleUpdatePublishAPI(w, r)
	case "rollback":
		s.handleProtectionRuleUpdateRollbackAPI(w, r)
	case "emergency":
		s.handleProtectionEmergencyRuleAPI(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "rule update endpoint not found"})
	}
}

func (s *Server) handleProtectionRulesAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	if s.db == nil {
		if r.Method == http.MethodGet && (suffix == "" || suffix == "/") {
			rules, runtimeVersion, hotReload := s.runtimeProtectionRules(r.Context())
			writeJSON(w, http.StatusOK, protectionRuleListResponse{Rules: rules, Total: len(rules), RuntimeVersion: runtimeVersion, HotReload: hotReload})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	if handled := s.handleProtectionRuleOperationsAPI(w, r, suffix); handled {
		return
	}
	id, action, isAction, err := parseProtectionRuleAction(suffix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid rule id"})
		return
	}
	if isAction {
		s.handleProtectionRuleToggle(w, r, id, action)
		return
	}
	id, hasID, err := parseID(strings.Trim(suffix, "/"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid rule id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, runtimeVersion, hotReload := s.runtimeProtectionRules(r.Context())
		writeJSON(w, http.StatusOK, protectionRuleListResponse{Rules: rules, Total: len(rules), RuntimeVersion: runtimeVersion, HotReload: hotReload})
	case http.MethodPost:
		payload, errors := decodeSingleProtectionRulePayload(r.Body)
		if len(errors) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		rule, validationErrors := validateProtectionRulePayload(*payload, 0)
		if len(validationErrors) > 0 {
			writeJSON(w, http.StatusBadRequest, protectionRuleValidationResponse{Valid: false, Errors: validationErrors})
			return
		}
		runtimeVersion, hotReload, err := s.persistProtectionRuleChange(r.Context(), "create", func(tx *gorm.DB) error {
			return tx.Create(&rule).Error
		}, []database.ProtectionRule{rule})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "protection_rule", 0, "", fmt.Sprintf("rule:%d", rule.RuleID), "create", rule.Name)
		writeJSON(w, http.StatusCreated, protectionRuleWriteResponse{Rule: protectionRuleToAPI(rule, 0, runtimeVersion, hotReload), RuntimeVersion: runtimeVersion, HotReload: hotReload})
	case http.MethodPut:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "rule id required"})
			return
		}
		var existing database.ProtectionRule
		if err := s.db.WithContext(r.Context()).First(&existing, id).Error; err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "rule not found"})
			return
		}
		payload, errors := decodeSingleProtectionRulePayload(r.Body)
		if len(errors) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		updated, validationErrors := validateProtectionRulePayload(*payload, existing.ID)
		if len(validationErrors) > 0 {
			writeJSON(w, http.StatusBadRequest, protectionRuleValidationResponse{Valid: false, Errors: validationErrors})
			return
		}
		updated.CreatedAt = existing.CreatedAt
		runtimeVersion, hotReload, err := s.persistProtectionRuleChange(r.Context(), "update", func(tx *gorm.DB) error {
			return tx.Save(&updated).Error
		}, []database.ProtectionRule{updated})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "protection_rule", 0, "", fmt.Sprintf("rule:%d", updated.RuleID), "update", updated.Name)
		writeJSON(w, http.StatusOK, protectionRuleWriteResponse{Rule: protectionRuleToAPI(updated, 0, runtimeVersion, hotReload), RuntimeVersion: runtimeVersion, HotReload: hotReload})
	case http.MethodDelete:
		if !hasID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "rule id required"})
			return
		}
		var existing database.ProtectionRule
		_ = s.db.WithContext(r.Context()).First(&existing, id).Error
		_, _, err := s.persistProtectionRuleChange(r.Context(), "delete", func(tx *gorm.DB) error {
			return tx.Delete(&database.ProtectionRule{}, id).Error
		}, nil)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "protection_rule", 0, "", fmt.Sprintf("rule:%d", existing.RuleID), "delete", existing.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

func (s *Server) handleProtectionRuleToggle(w http.ResponseWriter, r *http.Request, id uint, action string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var rule database.ProtectionRule
	if err := s.db.WithContext(r.Context()).First(&rule, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "rule not found"})
		return
	}
	rule.Enabled = action == "enable"
	runtimeVersion, hotReload, err := s.persistProtectionRuleChange(r.Context(), action, func(tx *gorm.DB) error {
		return tx.Save(&rule).Error
	}, []database.ProtectionRule{rule})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	s.recordAuditEvent(r.Context(), "protection_rule", 0, "", fmt.Sprintf("rule:%d", rule.RuleID), action, rule.Name)
	writeJSON(w, http.StatusOK, protectionRuleWriteResponse{Rule: protectionRuleToAPI(rule, 0, runtimeVersion, hotReload), RuntimeVersion: runtimeVersion, HotReload: hotReload})
}

func (s *Server) runtimeProtectionRules(ctx context.Context) ([]protectionRuleResponse, string, bool) {
	fromRuntime := map[int]protectionRuleResponse{}
	runtimeVersion := currentProtectionRuleRuntimeVersion()
	hotReload := s.detectionEngine != nil
	if s.detectionEngine != nil {
		for _, rule := range s.detectionEngine.Rules() {
			fromRuntime[rule.ID] = protectionDetectionRuleToAPI(rule, runtimeVersion, hotReload)
		}
	}
	hitsByRuleID := s.ruleHitsByRuleID(ctx)
	if s.db != nil {
		var persisted []database.ProtectionRule
		_ = s.db.WithContext(ctx).Order("rule_id asc").Find(&persisted).Error
		for _, rule := range persisted {
			fromRuntime[rule.RuleID] = protectionRuleToAPI(rule, hitsByRuleID[rule.RuleID], runtimeVersion, hotReload)
		}
	}
	ids := make([]int, 0, len(fromRuntime))
	for id := range fromRuntime {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := make([]protectionRuleResponse, 0, len(ids))
	for _, id := range ids {
		out = append(out, fromRuntime[id])
	}
	return out, runtimeVersion, hotReload
}

func (s *Server) reloadProtectionRules(ctx context.Context) error {
	if s == nil || s.db == nil || s.detectionEngine == nil {
		return nil
	}
	var rules []database.ProtectionRule
	if err := s.db.WithContext(ctx).Order("rule_id asc").Find(&rules).Error; err != nil {
		return err
	}
	persisted := make(map[int]struct{}, len(rules))
	for _, rule := range rules {
		persisted[rule.RuleID] = struct{}{}
	}
	for _, existing := range s.detectionEngine.Rules() {
		switch strings.ToLower(strings.TrimSpace(existing.Source)) {
		case "custom", "semantic", "system":
			if _, ok := persisted[existing.ID]; ok {
				continue
			}
			if err := s.detectionEngine.DeleteRuntimeRule(existing.ID); err != nil {
				return err
			}
		}
	}
	for _, rule := range rules {
		if err := s.detectionEngine.UpsertRuntimeRule(protectionRuleToDetection(rule)); err != nil {
			return err
		}
	}
	return s.detectionEngine.Reload(ctx)
}

func (s *Server) applyProtectionRuleRuntime(ctx context.Context, rule database.ProtectionRule) error {
	if s.detectionEngine == nil {
		return nil
	}
	if err := s.detectionEngine.UpsertRuntimeRule(protectionRuleToDetection(rule)); err != nil {
		return err
	}
	return s.detectionEngine.Reload(ctx)
}

func (s *Server) handleProtectionRuleOperationsAPI(w http.ResponseWriter, r *http.Request, suffix string) bool {
	operation := strings.Trim(strings.TrimSpace(suffix), "/")
	switch operation {
	case "validate":
		s.handleProtectionRuleValidateAPI(w, r)
		return true
	case "test":
		s.handleProtectionRuleTestAPI(w, r)
		return true
	case "import":
		s.handleProtectionRuleImportAPI(w, r)
		return true
	case "export":
		s.handleProtectionRuleExportAPI(w, r)
		return true
	case "rollback":
		s.handleProtectionRuleRollbackAPI(w, r)
		return true
	default:
		return false
	}
}

func (s *Server) handleProtectionRuleValidateAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	_, errors, malformed := decodeProtectionRuleValidationBody(r.Body)
	if malformed {
		writeJSON(w, http.StatusBadRequest, protectionRuleValidationResponse{Valid: false, Errors: errors})
		return
	}
	valid := len(errors) == 0
	status := http.StatusOK
	if !valid {
		status = http.StatusBadRequest
	}
	runtimeVersion := currentProtectionRuleRuntimeVersion()
	writeJSON(w, status, protectionRuleValidationResponse{Valid: valid, Errors: errors, RuntimeVersion: runtimeVersion, HotReload: s.detectionEngine != nil})
}

func (s *Server) handleProtectionRuleTestAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload protectionRuleTestPayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	engine, targetRule, errors := s.protectionRuleTestEngine(payload)
	if len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, protectionRuleTestResponse{Errors: errors, RuntimeVersion: currentProtectionRuleRuntimeVersion(), HotReload: s.detectionEngine != nil})
		return
	}
	headers := http.Header{}
	for key, value := range payload.Headers {
		headers.Set(key, value)
	}
	uri := strings.TrimSpace(payload.URI)
	if uri == "" {
		uri = strings.TrimSpace(payload.Path)
	}
	if uri == "" {
		uri = "/"
	}
	result, err := engine.Inspect(r.Context(), detection.Request{
		Method:  firstNonEmpty(strings.TrimSpace(payload.Method), http.MethodGet),
		URI:     uri,
		Headers: headers,
		Body:    payload.Body,
		Args:    payload.Args,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	matched := false
	for _, match := range result.Matches {
		if targetRule == nil || match.ID == targetRule.RuleID {
			matched = true
			break
		}
	}
	writeJSON(w, http.StatusOK, protectionRuleTestResponse{
		Matched:        matched,
		Decision:       string(result.Decision),
		Score:          result.Score,
		Severity:       result.Severity,
		Matches:        result.Matches,
		RuntimeVersion: currentProtectionRuleRuntimeVersion(),
		HotReload:      s.detectionEngine != nil,
	})
}

func (s *Server) handleProtectionRuleImportAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	rules, errors, malformed := decodeProtectionRuleList(r.Body)
	if malformed {
		writeJSON(w, http.StatusBadRequest, protectionRuleImportResponse{Valid: false, Errors: append(errors, protectionRuleValidationError{Message: "invalid json"}), RuntimeVersion: currentProtectionRuleRuntimeVersion(), HotReload: s.detectionEngine != nil})
		return
	}
	if len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, protectionRuleImportResponse{Valid: false, Errors: errors, RuntimeVersion: currentProtectionRuleRuntimeVersion(), HotReload: s.detectionEngine != nil})
		return
	}
	runtimeVersion, hotReload, err := s.replaceCustomProtectionRules(r.Context(), "import", rules)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	for _, rule := range rules {
		s.recordAuditEvent(r.Context(), "protection_rule", 0, "", fmt.Sprintf("rule:%d", rule.RuleID), "import", rule.Name)
	}
	apiRules := make([]protectionRuleResponse, 0, len(rules))
	for _, rule := range rules {
		apiRules = append(apiRules, protectionRuleToAPI(rule, 0, runtimeVersion, hotReload))
	}
	writeJSON(w, http.StatusOK, protectionRuleImportResponse{Rules: apiRules, Total: len(apiRules), Valid: true, RuntimeVersion: runtimeVersion, HotReload: hotReload})
}

func (s *Server) handleProtectionRuleExportAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var rules []database.ProtectionRule
	if err := s.db.WithContext(r.Context()).Order("rule_id asc").Find(&rules).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleProtectionRuleRollbackAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var snapshot database.ProtectionRulePublishSnapshot
	if err := s.db.WithContext(r.Context()).Where("action IN ?", []string{"create", "update", "delete", "enable", "disable", "import"}).Order("id desc").First(&snapshot).Error; err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "no previous rule publish snapshot"})
		return
	}
	var rules []database.ProtectionRule
	if err := json.Unmarshal([]byte(snapshot.RulesJSON), &rules); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	runtimeVersion, hotReload, err := s.replaceProtectionRules(r.Context(), "rollback", rules)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	s.recordAuditEvent(r.Context(), "protection_rule", 0, "", "rules", "rollback", snapshot.Version)
	apiRules := make([]protectionRuleResponse, 0, len(rules))
	for _, rule := range rules {
		apiRules = append(apiRules, protectionRuleToAPI(rule, 0, runtimeVersion, hotReload))
	}
	writeJSON(w, http.StatusOK, protectionRuleRollbackResponse{
		Rules:          apiRules,
		Total:          len(apiRules),
		RolledBackTo:   snapshot.Version,
		RuntimeVersion: runtimeVersion,
		HotReload:      hotReload,
	})
}

func (s *Server) protectionRuleTestEngine(payload protectionRuleTestPayload) (detection.Engine, *database.ProtectionRule, []protectionRuleValidationError) {
	if payload.Rule != nil {
		rule, errors := validateProtectionRulePayload(*payload.Rule, 0)
		if len(errors) > 0 {
			return nil, nil, errors
		}
		manager, err := detection.NewManager("", nil, nil, false)
		if err != nil {
			return nil, nil, []protectionRuleValidationError{{Message: err.Error()}}
		}
		if err := manager.UpsertRuntimeRule(protectionRuleToDetection(rule)); err != nil {
			return nil, nil, []protectionRuleValidationError{{Message: err.Error()}}
		}
		return manager, &rule, nil
	}
	if s.detectionEngine == nil {
		manager, err := detection.NewManager("", nil, nil, false)
		if err != nil {
			return nil, nil, []protectionRuleValidationError{{Message: err.Error()}}
		}
		return manager, nil, nil
	}
	manager, err := detection.NewManager("", nil, nil, false)
	if err != nil {
		return nil, nil, []protectionRuleValidationError{{Message: err.Error()}}
	}
	for _, rule := range s.detectionEngine.Rules() {
		if err := manager.UpsertRuntimeRule(rule); err != nil {
			return nil, nil, []protectionRuleValidationError{{Message: err.Error()}}
		}
	}
	return manager, nil, nil
}

func decodeSingleProtectionRulePayload(body io.Reader) (*protectionRulePayload, []protectionRuleValidationError) {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var payload protectionRulePayload
	if err := decoder.Decode(&payload); err != nil {
		return nil, []protectionRuleValidationError{{Field: "body", Line: 1, Message: "invalid json"}}
	}
	return &payload, nil
}

func decodeProtectionRuleValidationBody(body io.Reader) ([]database.ProtectionRule, []protectionRuleValidationError, bool) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, []protectionRuleValidationError{{Field: "body", Line: 1, Message: err.Error()}}, true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, []protectionRuleValidationError{{Field: "body", Line: 1, Message: "rule payload is required"}}, true
	}
	if trimmed[0] == '[' {
		return decodeProtectionRuleList(bytes.NewReader(trimmed))
	}
	payload, errors := decodeSingleProtectionRulePayload(bytes.NewReader(trimmed))
	if len(errors) > 0 {
		return nil, errors, true
	}
	rule, validationErrors := validateProtectionRulePayload(*payload, 0)
	for i := range validationErrors {
		if validationErrors[i].Line == 0 {
			validationErrors[i].Line = 1
		}
	}
	if len(validationErrors) > 0 {
		return nil, validationErrors, false
	}
	return []database.ProtectionRule{rule}, nil, false
}

func decodeProtectionRuleList(body io.Reader) ([]database.ProtectionRule, []protectionRuleValidationError, bool) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, []protectionRuleValidationError{{Message: err.Error()}}, true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payloads []protectionRulePayload
	if err := decoder.Decode(&payloads); err != nil {
		return nil, []protectionRuleValidationError{{Field: "body", Line: 1, Message: "invalid json"}}, true
	}
	rules := make([]database.ProtectionRule, 0, len(payloads))
	errors := make([]protectionRuleValidationError, 0)
	seenRuleIDs := make(map[int]int, len(payloads))
	for idx, payload := range payloads {
		rule, validationErrors := validateProtectionRulePayload(payload, 0)
		for _, validationError := range validationErrors {
			validationError.Line = idx + 1
			errors = append(errors, validationError)
		}
		if len(validationErrors) > 0 {
			continue
		}
		if firstLine, ok := seenRuleIDs[rule.RuleID]; ok {
			errors = append(errors, protectionRuleValidationError{Field: "ruleId", Line: idx + 1, Message: fmt.Sprintf("duplicate ruleId already used at line %d", firstLine)})
			continue
		}
		seenRuleIDs[rule.RuleID] = idx + 1
		rules = append(rules, rule)
	}
	if len(payloads) == 0 {
		errors = append(errors, protectionRuleValidationError{Field: "rules", Line: 1, Message: "rule list is required"})
	}
	return rules, errors, false
}

func validateProtectionRulePayload(payload protectionRulePayload, id uint) (database.ProtectionRule, []protectionRuleValidationError) {
	rule, err := payload.toModel(id)
	if err != nil {
		field := "body"
		switch {
		case strings.Contains(err.Error(), "ruleId"):
			field = "ruleId"
		case strings.Contains(err.Error(), "variable"):
			field = "variable"
		case strings.Contains(err.Error(), "operator"):
			field = "operator"
		case strings.Contains(err.Error(), "pattern"):
			field = "pattern"
		case strings.Contains(err.Error(), "action"):
			field = "action"
		case strings.Contains(err.Error(), "source"):
			field = "source"
		}
		return rule, []protectionRuleValidationError{{Field: field, Line: 1, Message: err.Error()}}
	}
	errors := make([]protectionRuleValidationError, 0)
	if strings.TrimSpace(payload.Variable) == "" {
		errors = append(errors, protectionRuleValidationError{Field: "variable", Message: "variable is required"})
	}
	switch strings.TrimSpace(payload.Variable) {
	case "ARGS", "ARGS_NAMES", "REQUEST_URI", "REQUEST_HEADERS", "REQUEST_METHOD", "REQUEST_BODY", "BODY", "REQUEST_HEADERS:User-Agent":
	default:
		errors = append(errors, protectionRuleValidationError{Field: "variable", Message: "unsupported variable"})
	}
	switch strings.TrimSpace(payload.Operator) {
	case "@contains", "@streq", "@rx":
	default:
		errors = append(errors, protectionRuleValidationError{Field: "operator", Message: "unsupported operator"})
	}
	if payload.Score <= 0 {
		errors = append(errors, protectionRuleValidationError{Field: "score", Message: "score must be greater than 0"})
	}
	if len([]rune(rule.Pattern)) > 2048 {
		errors = append(errors, protectionRuleValidationError{Field: "pattern", Message: "pattern exceeds 2048 characters"})
	}
	if strings.TrimSpace(rule.Source) != "" && rule.Source != "custom" {
		errors = append(errors, protectionRuleValidationError{Field: "source", Message: "only custom rules can be managed here"})
	}
	if strings.TrimSpace(rule.Category) == "" {
		errors = append(errors, protectionRuleValidationError{Field: "category", Message: "category is required"})
	}
	return rule, errors
}

func (s *Server) persistProtectionRuleChange(ctx context.Context, action string, mutate func(tx *gorm.DB) error, rules []database.ProtectionRule) (string, bool, error) {
	snapshot, err := s.snapshotProtectionRules(ctx, action)
	if err != nil {
		return "", false, err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := mutate(tx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return "", false, err
	}
	runtimeVersion, hotReload, err := s.reloadProtectionRuleState(ctx)
	if err != nil {
		if restoreErr := s.restoreProtectionRulesFromSnapshot(ctx, snapshot); restoreErr != nil {
			return "", false, fmt.Errorf("reload protection rules: %w; restore snapshot: %v", err, restoreErr)
		}
		return "", false, err
	}
	return runtimeVersion, hotReload, nil
}

func (s *Server) replaceProtectionRules(ctx context.Context, action string, rules []database.ProtectionRule) (string, bool, error) {
	snapshot, err := s.snapshotProtectionRules(ctx, action)
	if err != nil {
		return "", false, err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&database.ProtectionRule{}).Error; err != nil {
			return err
		}
		for i := range rules {
			rules[i].ID = 0
			if err := tx.Create(&rules[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", false, err
	}
	runtimeVersion, hotReload, err := s.reloadProtectionRuleState(ctx)
	if err != nil {
		if restoreErr := s.restoreProtectionRulesFromSnapshot(ctx, snapshot); restoreErr != nil {
			return "", false, fmt.Errorf("reload protection rules: %w; restore snapshot: %v", err, restoreErr)
		}
		return "", false, err
	}
	return runtimeVersion, hotReload, nil
}

func (s *Server) replaceCustomProtectionRules(ctx context.Context, action string, rules []database.ProtectionRule) (string, bool, error) {
	snapshot, err := s.snapshotProtectionRules(ctx, action)
	if err != nil {
		return "", false, err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("source = ?", "custom").Delete(&database.ProtectionRule{}).Error; err != nil {
			return err
		}
		for i := range rules {
			rules[i].ID = 0
			rules[i].Source = "custom"
			if err := tx.Create(&rules[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", false, err
	}
	runtimeVersion, hotReload, err := s.reloadProtectionRuleState(ctx)
	if err != nil {
		if restoreErr := s.restoreProtectionRulesFromSnapshot(ctx, snapshot); restoreErr != nil {
			return "", false, fmt.Errorf("reload protection rules: %w; restore snapshot: %v", err, restoreErr)
		}
		return "", false, err
	}
	return runtimeVersion, hotReload, nil
}

func (s *Server) snapshotProtectionRules(ctx context.Context, action string) (database.ProtectionRulePublishSnapshot, error) {
	var existing []database.ProtectionRule
	if err := s.db.WithContext(ctx).Order("rule_id asc").Find(&existing).Error; err != nil {
		return database.ProtectionRulePublishSnapshot{}, err
	}
	data, err := json.Marshal(existing)
	if err != nil {
		return database.ProtectionRulePublishSnapshot{}, err
	}
	snapshot := database.ProtectionRulePublishSnapshot{
		Version:        fmt.Sprintf("rules-%d", time.Now().UnixMilli()),
		Action:         action,
		RuleCount:      len(existing),
		RuntimeVersion: currentProtectionRuleRuntimeVersion(),
		HotReload:      s.detectionEngine != nil,
		RulesJSON:      string(data),
	}
	if err := s.db.WithContext(ctx).Create(&snapshot).Error; err != nil {
		return database.ProtectionRulePublishSnapshot{}, err
	}
	return snapshot, nil
}

func (s *Server) restoreProtectionRulesFromSnapshot(ctx context.Context, snapshot database.ProtectionRulePublishSnapshot) error {
	var rules []database.ProtectionRule
	if err := json.Unmarshal([]byte(snapshot.RulesJSON), &rules); err != nil {
		return err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&database.ProtectionRule{}).Error; err != nil {
			return err
		}
		for i := range rules {
			rules[i].ID = 0
			if err := tx.Create(&rules[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	_, _, err := s.reloadProtectionRuleState(ctx)
	return err
}

func (s *Server) reloadProtectionRuleState(ctx context.Context) (string, bool, error) {
	if err := s.reloadProtectionRules(ctx); err != nil {
		return "", false, err
	}
	return currentProtectionRuleRuntimeVersion(), s.detectionEngine != nil, nil
}

func currentProtectionRuleRuntimeVersion() string {
	return fmt.Sprintf("rules-%d", time.Now().UnixMilli())
}

func (s *Server) handleProtectionRuleUpdatePublishAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload ruleUpdateManualPayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	logEntry, statusCode, err := s.publishRuleUpdate(r.Context(), payload)
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, statusCode, logEntry)
}

func (s *Server) handleProtectionRuleUpdateSourcesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload ruleUpdateSourcePayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	source, created, err := s.upsertRuleUpdateSource(r.Context(), payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	statusCode := http.StatusOK
	if created {
		statusCode = http.StatusCreated
	}
	writeJSON(w, statusCode, ruleUpdateSourceResponse{
		ID:             fmt.Sprintf("%d", source.ID),
		Name:           source.Name,
		Type:           source.Type,
		URL:            source.URL,
		Mode:           firstNonEmpty(source.Mode, "block"),
		Enabled:        source.Enabled,
		ExpectedHash:   source.ExpectedHash,
		CurrentVersion: source.CurrentVersion,
		CurrentHash:    source.CurrentHash,
		LastStatus:     source.LastStatus,
		LastError:      source.LastError,
		LastSuccessAt:  formatMillis(source.LastSuccessAt),
		UpdatedAt:      formatMillis(source.UpdatedAt),
	})
}

func (s *Server) handleProtectionRuleUpdateRollbackAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload ruleUpdateRollbackPayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	logEntry, statusCode, err := s.rollbackRuleUpdate(r.Context(), payload)
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, statusCode, logEntry)
}

func (s *Server) handleProtectionEmergencyRuleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	var payload emergencyRulePublishPayload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
		return
	}
	logEntry, statusCode, err := s.publishEmergencyRule(r.Context(), payload)
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"message": err.Error()})
		return
	}
	writeJSON(w, statusCode, logEntry)
}

func (s *Server) ruleUpdateSummary(ctx context.Context) ruleUpdateSummaryResponse {
	runtimeVersion := currentProtectionRuleRuntimeVersion()
	hotReload := s.detectionEngine != nil
	var logs []database.ProtectionRuleUpdateLog
	_ = s.db.WithContext(ctx).Order("id desc").Limit(10).Find(&logs).Error
	var sources []database.ProtectionRuleUpdateSource
	_ = s.db.WithContext(ctx).Order("id asc").Find(&sources).Error
	var rules []database.ProtectionRule
	_ = s.db.WithContext(ctx).Order("rule_id asc").Find(&rules).Error
	currentHash := protectionRuleSetHash(rules)
	var latest *ruleUpdateLogResponse
	logResponses := make([]ruleUpdateLogResponse, 0, len(logs))
	for _, item := range logs {
		resp := s.ruleUpdateLogToAPI(item)
		logResponses = append(logResponses, resp)
		if latest == nil {
			copy := resp
			latest = &copy
		}
	}
	status := ""
	lastPublishedAt := ""
	lastBlockedReason := ""
	lastFailureReason := ""
	if latest != nil {
		status = latest.Status
		lastPublishedAt = latest.CreatedAt
		lastBlockedReason = latest.BlockedReason
		lastFailureReason = latest.ErrorMessage
	}
	return ruleUpdateSummaryResponse{
		CurrentVersion:    latestRuleUpdateVersion(logResponses, runtimeVersion),
		CurrentHash:       currentHash,
		CurrentRuleCount:  len(rules),
		CurrentStatus:     status,
		LastPublishedAt:   lastPublishedAt,
		LastBlockedReason: lastBlockedReason,
		LastFailureReason: lastFailureReason,
		Latest:            latest,
		Sources:           ruleUpdateSourcesToAPI(sources),
		Logs:              logResponses,
		RuntimeVersion:    runtimeVersion,
		HotReload:         hotReload,
	}
}

func latestRuleUpdateVersion(logs []ruleUpdateLogResponse, runtimeVersion string) string {
	for _, item := range logs {
		if item.Published && strings.TrimSpace(item.PackageVersion) != "" {
			return item.PackageVersion
		}
	}
	return runtimeVersion
}

func ruleUpdateSourcesToAPI(items []database.ProtectionRuleUpdateSource) []ruleUpdateSourceResponse {
	out := make([]ruleUpdateSourceResponse, 0, len(items))
	for _, item := range items {
		out = append(out, ruleUpdateSourceResponse{
			ID:             fmt.Sprintf("%d", item.ID),
			Name:           item.Name,
			Type:           item.Type,
			URL:            item.URL,
			Mode:           firstNonEmpty(item.Mode, "block"),
			Enabled:        item.Enabled,
			ExpectedHash:   item.ExpectedHash,
			CurrentVersion: item.CurrentVersion,
			CurrentHash:    item.CurrentHash,
			LastStatus:     item.LastStatus,
			LastError:      item.LastError,
			LastSuccessAt:  formatMillis(item.LastSuccessAt),
			UpdatedAt:      formatMillis(item.UpdatedAt),
		})
	}
	return out
}

func (s *Server) publishRuleUpdate(ctx context.Context, payload ruleUpdateManualPayload) (ruleUpdateLogResponse, int, error) {
	source, err := s.resolveRuleUpdateSource(ctx, payload)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, err
	}
	rules, pkgMeta, validationErrors, err := s.resolveRuleUpdatePackage(payload)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, err
	}
	if len(validationErrors) > 0 {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, errors.New(formatRuleValidationErrors(validationErrors))
	}
	existingRules, err := s.loadPersistedProtectionRules(ctx)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	packageHash := firstNonEmpty(strings.TrimSpace(pkgMeta.Hash), protectionRuleSetHash(rules))
	if source != nil && strings.TrimSpace(source.ExpectedHash) != "" && !strings.EqualFold(strings.TrimSpace(source.ExpectedHash), packageHash) {
		logEntry, _ := s.persistRuleUpdateLog(ctx, s.buildRuleUpdateLog(existingRules, rules, *source, pkgMeta, "rejected", false, false, ruleUpdateEvaluationResponse{}, "hash mismatch", "", "", ""))
		return logEntry, http.StatusBadRequest, fmt.Errorf("hash mismatch")
	}
	if strings.TrimSpace(payload.ExpectedHash) != "" && !strings.EqualFold(strings.TrimSpace(payload.ExpectedHash), packageHash) {
		logEntry, _ := s.persistRuleUpdateLog(ctx, s.buildRuleUpdateLog(existingRules, rules, sourceOrDefault(source), pkgMeta, "rejected", false, false, ruleUpdateEvaluationResponse{}, "hash mismatch", "", "", ""))
		return logEntry, http.StatusBadRequest, fmt.Errorf("hash mismatch")
	}
	evaluation, err := s.evaluateCandidateRuleSet(ctx, existingRules, rules)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	mode := normalizeRuleUpdateMode(payload.ObserveOnly, payload.GrayMode, pkgMeta.Mode, source)
	runtimeRules := runtimeProtectionRulesForMode(mode, rules)
	allowPublish := evaluation.Passed || mode != "block"
	status := "blocked"
	blockedReason := evaluation.BlockedReason
	if allowPublish {
		status = "published"
	}
	pkgMeta.Mode = mode
	diff := diffProtectionRules(existingRules, runtimeRules)
	logModel := s.buildRuleUpdateLog(existingRules, runtimeRules, sourceOrDefault(source), pkgMeta, status, allowPublish, false, evaluation, blockedReason, "", "", "")
	if !allowPublish {
		logEntry, _ := s.persistRuleUpdateLog(ctx, logModel)
		return logEntry, http.StatusConflict, nil
	}
	runtimeVersion, hotReload, err := s.replaceProtectionRules(ctx, "rule-update-publish", cloneProtectionRules(runtimeRules))
	if err != nil {
		logModel.Status = "failed"
		logModel.ErrorMessage = err.Error()
		logEntry, _ := s.persistRuleUpdateLog(ctx, logModel)
		return logEntry, http.StatusInternalServerError, err
	}
	logModel.RuntimeVersion = runtimeVersion
	logModel.Published = true
	logModel.RuleCount = len(runtimeRules)
	logModel.DiffJSON = marshalJSON(diff)
	logModel.PublishedRulesJSON = marshalJSON(protectionRulesToAPI(runtimeRules, runtimeVersion, hotReload))
	logEntry, saved := s.persistRuleUpdateLog(ctx, logModel)
	if source != nil {
		source.CurrentVersion = pkgMeta.Version
		source.CurrentHash = packageHash
		source.LastStatus = logModel.Status
		source.LastError = logModel.BlockedReason
		source.LastSuccessAt = time.Now().UnixMilli()
		_ = s.db.WithContext(ctx).Save(source).Error
	}
	s.recordAuditEvent(ctx, "protection_rule_update", 0, "", fmt.Sprintf("rule-update:%s", saved.UpdateID), "publish", fmt.Sprintf("version=%s hash=%s mode=%s", pkgMeta.Version, packageHash, mode))
	return logEntry, http.StatusOK, nil
}

func (s *Server) publishEmergencyRule(ctx context.Context, payload emergencyRulePublishPayload) (ruleUpdateLogResponse, int, error) {
	rule, validationErrors := validateProtectionRulePayload(payload.Rule, 0)
	if len(validationErrors) > 0 {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, errors.New(formatRuleValidationErrors(validationErrors))
	}
	rule.Source = "system"
	if strings.TrimSpace(payload.CVE) == "" {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, fmt.Errorf("cve is required")
	}
	existingRules, err := s.loadPersistedProtectionRules(ctx)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	rules := upsertProtectionRule(existingRules, rule)
	meta := ruleUpdatePackageMeta{
		Type:    "emergency-cve",
		Version: firstNonEmpty(strings.TrimSpace(payload.Version), fmt.Sprintf("%s-%d", strings.ToLower(strings.TrimSpace(payload.CVE)), time.Now().UnixMilli())),
		Hash:    firstNonEmpty(strings.TrimSpace(payload.Hash), protectionRuleSetHash(rules)),
		URL:     "",
		Mode:    ternary(payload.ObserveOnly, "observe", "block"),
	}
	evaluation, err := s.evaluateCandidateRuleSet(ctx, existingRules, rules)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	if payload.ObserveOnly {
		evaluation.Passed = true
		evaluation.BlockedReason = ""
	}
	mode := normalizeRuleUpdateMode(payload.ObserveOnly, false, meta.Mode, nil)
	status := "published"
	if !evaluation.Passed && mode == "block" {
		status = "blocked"
	}
	logModel := s.buildRuleUpdateLog(existingRules, rules, database.ProtectionRuleUpdateSource{Name: "emergency-cve", Type: "emergency"}, meta, status, status == "published", true, evaluation, evaluation.BlockedReason, "", "", "")
	logModel.EmergencyCVE = payload.CVE
	if status != "published" {
		logEntry, _ := s.persistRuleUpdateLog(ctx, logModel)
		return logEntry, http.StatusConflict, nil
	}
	runtimeVersion, hotReload, err := s.replaceProtectionRules(ctx, "rule-update-emergency", cloneProtectionRules(rules))
	if err != nil {
		logModel.Status = "failed"
		logModel.ErrorMessage = err.Error()
		logEntry, _ := s.persistRuleUpdateLog(ctx, logModel)
		return logEntry, http.StatusInternalServerError, err
	}
	logModel.RuntimeVersion = runtimeVersion
	logModel.Published = true
	logModel.PublishedRulesJSON = marshalJSON(protectionRulesToAPI(rules, runtimeVersion, hotReload))
	logEntry, saved := s.persistRuleUpdateLog(ctx, logModel)
	s.recordAuditEvent(ctx, "protection_rule_update", 0, "", fmt.Sprintf("rule-update:%s", saved.UpdateID), "emergency-publish", fmt.Sprintf("%s %s", payload.CVE, meta.Version))
	return logEntry, http.StatusOK, nil
}

func (s *Server) rollbackRuleUpdate(ctx context.Context, payload ruleUpdateRollbackPayload) (ruleUpdateLogResponse, int, error) {
	var target database.ProtectionRuleUpdateLog
	query := s.db.WithContext(ctx).Order("id desc")
	switch {
	case strings.TrimSpace(payload.UpdateID) != "":
		query = query.Where("update_id = ?", strings.TrimSpace(payload.UpdateID))
	case strings.TrimSpace(payload.Version) != "":
		query = query.Where("package_version = ?", strings.TrimSpace(payload.Version))
	default:
		query = query.Where("published = ?", true)
	}
	if err := query.First(&target).Error; err != nil {
		return ruleUpdateLogResponse{}, http.StatusBadRequest, fmt.Errorf("no published rule update found")
	}
	var rollbackRules []database.ProtectionRule
	if err := json.Unmarshal([]byte(target.PrePublishRulesJSON), &rollbackRules); err != nil || len(rollbackRules) == 0 {
		var snapshot database.ProtectionRulePublishSnapshot
		if err := s.db.WithContext(ctx).Where("action LIKE ?", "rule-update%").Order("id asc").First(&snapshot).Error; err != nil {
			return ruleUpdateLogResponse{}, http.StatusInternalServerError, fmt.Errorf("rollback snapshot unavailable")
		}
		if err := json.Unmarshal([]byte(snapshot.RulesJSON), &rollbackRules); err != nil {
			return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
		}
	}
	currentRules, err := s.loadPersistedProtectionRules(ctx)
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	runtimeVersion, hotReload, err := s.replaceProtectionRules(ctx, "rule-update-rollback", cloneProtectionRules(rollbackRules))
	if err != nil {
		return ruleUpdateLogResponse{}, http.StatusInternalServerError, err
	}
	meta := ruleUpdatePackageMeta{
		Type:    "rollback",
		Version: firstNonEmpty(target.RollbackFromVersion, target.PackageVersion),
		Hash:    protectionRuleSetHash(rollbackRules),
		Mode:    "block",
	}
	evaluation, evalErr := s.evaluateCandidateRuleSet(ctx, currentRules, rollbackRules)
	if evalErr != nil {
		evaluation = ruleUpdateEvaluationResponse{Passed: true, Summary: evalErr.Error()}
	}
	logModel := s.buildRuleUpdateLog(currentRules, rollbackRules, database.ProtectionRuleUpdateSource{Name: "rollback", Type: "rollback"}, meta, "rolled-back", true, false, evaluation, "", currentProtectionRuleRuntimeVersion(), target.PackageVersion, "")
	logModel.RuntimeVersion = runtimeVersion
	logModel.RolledBackToVersion = target.PackageVersion
	logModel.RollbackSnapshotVersion = target.UpdateID
	logModel.PublishedRulesJSON = marshalJSON(protectionRulesToAPI(rollbackRules, runtimeVersion, hotReload))
	logEntry, saved := s.persistRuleUpdateLog(ctx, logModel)
	s.recordAuditEvent(ctx, "protection_rule_update", 0, "", fmt.Sprintf("rule-update:%s", saved.UpdateID), "rollback", target.PackageVersion)
	return logEntry, http.StatusOK, nil
}

type ruleUpdatePackageMeta struct {
	Type    string
	Version string
	Hash    string
	URL     string
	Mode    string
}

func (s *Server) resolveRuleUpdatePackage(payload ruleUpdateManualPayload) ([]database.ProtectionRule, ruleUpdatePackageMeta, []protectionRuleValidationError, error) {
	if payload.Package == nil {
		return nil, ruleUpdatePackageMeta{}, nil, fmt.Errorf("package is required")
	}
	rules := make([]database.ProtectionRule, 0, len(payload.Package.Rules))
	validationErrors := make([]protectionRuleValidationError, 0)
	seenRuleIDs := map[int]int{}
	for idx, rulePayload := range payload.Package.Rules {
		rule, errs := validateProtectionRulePayload(rulePayload, 0)
		for _, validationError := range errs {
			validationError.Line = idx + 1
			validationErrors = append(validationErrors, validationError)
		}
		if len(errs) > 0 {
			continue
		}
		if line, ok := seenRuleIDs[rule.RuleID]; ok {
			validationErrors = append(validationErrors, protectionRuleValidationError{Field: "ruleId", Line: idx + 1, Message: fmt.Sprintf("duplicate ruleId already used at line %d", line)})
			continue
		}
		seenRuleIDs[rule.RuleID] = idx + 1
		rule.Source = "custom"
		rules = append(rules, rule)
	}
	if len(payload.Package.Rules) == 0 {
		validationErrors = append(validationErrors, protectionRuleValidationError{Field: "rules", Line: 1, Message: "rule list is required"})
	}
	return rules, ruleUpdatePackageMeta{
		Type:    firstNonEmpty(strings.TrimSpace(payload.Package.Type), strings.TrimSpace(payload.Type), "manual"),
		Version: firstNonEmpty(strings.TrimSpace(payload.Package.Version), fmt.Sprintf("manual-%d", time.Now().UnixMilli())),
		Hash:    strings.TrimSpace(payload.Package.Hash),
		URL:     strings.TrimSpace(payload.PackageURL),
		Mode:    strings.TrimSpace(payload.Package.Mode),
	}, validationErrors, nil
}

func (s *Server) resolveRuleUpdateSource(ctx context.Context, payload ruleUpdateManualPayload) (*database.ProtectionRuleUpdateSource, error) {
	if !payload.UseSource && strings.TrimSpace(payload.SourceID) == "" {
		return nil, nil
	}
	id, hasID, err := parseID(strings.TrimSpace(payload.SourceID))
	if err != nil || !hasID {
		return nil, fmt.Errorf("invalid source id")
	}
	var source database.ProtectionRuleUpdateSource
	if err := s.db.WithContext(ctx).First(&source, id).Error; err != nil {
		return nil, fmt.Errorf("rule update source not found")
	}
	return &source, nil
}

func sourceOrDefault(source *database.ProtectionRuleUpdateSource) database.ProtectionRuleUpdateSource {
	if source != nil {
		return *source
	}
	return database.ProtectionRuleUpdateSource{Name: "manual", Type: "manual", Mode: "block", Enabled: true}
}

func runtimeProtectionRulesForMode(mode string, rules []database.ProtectionRule) []database.ProtectionRule {
	out := cloneProtectionRules(rules)
	if mode != "observe" {
		return out
	}
	for i := range out {
		if isBlockingProtectionRuleAction(out[i].Action) {
			out[i].Action = "log"
		}
	}
	return out
}

func isBlockingProtectionRuleAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deny", "block":
		return true
	default:
		return false
	}
}

func normalizeRuleUpdateMode(observeOnly, grayMode bool, requested string, source *database.ProtectionRuleUpdateSource) string {
	if observeOnly || grayMode {
		return "observe"
	}
	mode := strings.ToLower(strings.TrimSpace(requested))
	if mode == "" && source != nil {
		mode = strings.ToLower(strings.TrimSpace(source.Mode))
	}
	switch mode {
	case "observe", "gray":
		return "observe"
	default:
		return "block"
	}
}

func normalizeRuleUpdateSourceMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "block":
		return "block"
	case "observe", "gray":
		return "observe"
	default:
		return ""
	}
}

func (s *Server) upsertRuleUpdateSource(ctx context.Context, payload ruleUpdateSourcePayload) (database.ProtectionRuleUpdateSource, bool, error) {
	source := database.ProtectionRuleUpdateSource{
		Name:         strings.TrimSpace(payload.Name),
		Type:         strings.TrimSpace(payload.Type),
		URL:          strings.TrimSpace(payload.URL),
		Mode:         normalizeRuleUpdateSourceMode(payload.Mode),
		ExpectedHash: strings.TrimSpace(payload.ExpectedHash),
	}
	if source.Name == "" {
		return database.ProtectionRuleUpdateSource{}, false, fmt.Errorf("name is required")
	}
	if source.Type == "" {
		return database.ProtectionRuleUpdateSource{}, false, fmt.Errorf("type is required")
	}
	if source.Mode == "" {
		return database.ProtectionRuleUpdateSource{}, false, fmt.Errorf("mode must be block, observe, or gray")
	}
	source.Enabled = true
	if payload.Enabled != nil {
		source.Enabled = *payload.Enabled
	}
	var existing database.ProtectionRuleUpdateSource
	err := s.db.WithContext(ctx).Where("name = ? AND type = ?", source.Name, source.Type).First(&existing).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return database.ProtectionRuleUpdateSource{}, false, err
		}
		if err := s.db.WithContext(ctx).Create(&source).Error; err != nil {
			return database.ProtectionRuleUpdateSource{}, false, err
		}
		return source, true, nil
	}
	existing.URL = source.URL
	existing.Mode = source.Mode
	existing.Enabled = source.Enabled
	existing.ExpectedHash = source.ExpectedHash
	if err := s.db.WithContext(ctx).Save(&existing).Error; err != nil {
		return database.ProtectionRuleUpdateSource{}, false, err
	}
	return existing, false, nil
}

func (s *Server) evaluateCandidateRuleSet(ctx context.Context, baseline, candidate []database.ProtectionRule) (ruleUpdateEvaluationResponse, error) {
	baselineResult, err := securityeval.Evaluate(ctx, securityeval.Options{RuntimeRules: protectionRulesToDetection(baseline)})
	if err != nil {
		return ruleUpdateEvaluationResponse{}, err
	}
	candidateResult, err := securityeval.Evaluate(ctx, securityeval.Options{RuntimeRules: protectionRulesToDetection(candidate)})
	if err != nil {
		return ruleUpdateEvaluationResponse{}, err
	}
	blockedReason := ""
	passed := true
	if err := candidateResult.Validate(); err != nil {
		passed = false
		blockedReason = err.Error()
	}
	attackDelta := candidateResult.AttackBlockRate - baselineResult.AttackBlockRate
	fpDelta := candidateResult.BenignFalsePositives - baselineResult.BenignFalsePositives
	if attackDelta < 0 || fpDelta > 0 {
		passed = false
		if blockedReason == "" {
			var reasons []string
			if attackDelta < 0 {
				reasons = append(reasons, fmt.Sprintf("attack block rate regressed by %.2f%%", attackDelta*100))
			}
			if fpDelta > 0 {
				reasons = append(reasons, fmt.Sprintf("benign false positives increased by %d", fpDelta))
			}
			blockedReason = strings.Join(reasons, "; ")
		}
	}
	summary := fmt.Sprintf("attack %.2f%% -> %.2f%%, false positives %d -> %d", baselineResult.AttackBlockRate*100, candidateResult.AttackBlockRate*100, baselineResult.BenignFalsePositives, candidateResult.BenignFalsePositives)
	return ruleUpdateEvaluationResponse{
		Passed:                    passed,
		Summary:                   summary,
		BlockedReason:             blockedReason,
		AttackBlockRate:           candidateResult.AttackBlockRate,
		AttackBlockRateDelta:      attackDelta,
		BenignFalsePositives:      candidateResult.BenignFalsePositives,
		BenignFalsePositivesDelta: fpDelta,
		MissedAttacks:             candidateResult.MissedAttacks,
		FalsePositives:            candidateResult.FalsePositives,
	}, nil
}

func (s *Server) loadPersistedProtectionRules(ctx context.Context) ([]database.ProtectionRule, error) {
	var rules []database.ProtectionRule
	if err := s.db.WithContext(ctx).Order("rule_id asc").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func protectionRulesToDetection(rules []database.ProtectionRule) []detection.Rule {
	out := make([]detection.Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, protectionRuleToDetection(rule))
	}
	return out
}

func protectionRulesToAPI(rules []database.ProtectionRule, runtimeVersion string, hotReload bool) []protectionRuleResponse {
	out := make([]protectionRuleResponse, 0, len(rules))
	for _, rule := range rules {
		out = append(out, protectionRuleToAPI(rule, 0, runtimeVersion, hotReload))
	}
	return out
}

func cloneProtectionRules(rules []database.ProtectionRule) []database.ProtectionRule {
	out := make([]database.ProtectionRule, len(rules))
	copy(out, rules)
	return out
}

func protectionRuleSetHash(rules []database.ProtectionRule) string {
	data, _ := json.Marshal(normalizeProtectionRulesForHash(rules))
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func normalizeProtectionRulesForHash(rules []database.ProtectionRule) []database.ProtectionRule {
	out := cloneProtectionRules(rules)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	for i := range out {
		out[i].ID = 0
		out[i].CreatedAt = 0
		out[i].UpdatedAt = 0
	}
	return out
}

func upsertProtectionRule(existing []database.ProtectionRule, rule database.ProtectionRule) []database.ProtectionRule {
	out := cloneProtectionRules(existing)
	for i := range out {
		if out[i].RuleID == rule.RuleID {
			rule.ID = out[i].ID
			rule.CreatedAt = out[i].CreatedAt
			out[i] = rule
			return out
		}
	}
	out = append(out, rule)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func diffProtectionRules(before, after []database.ProtectionRule) []ruleUpdateDiffItem {
	beforeMap := make(map[int]database.ProtectionRule, len(before))
	afterMap := make(map[int]database.ProtectionRule, len(after))
	for _, rule := range before {
		beforeMap[rule.RuleID] = rule
	}
	for _, rule := range after {
		afterMap[rule.RuleID] = rule
	}
	ids := make([]int, 0, len(beforeMap)+len(afterMap))
	seen := map[int]struct{}{}
	for id := range beforeMap {
		ids = append(ids, id)
		seen[id] = struct{}{}
	}
	for id := range afterMap {
		if _, ok := seen[id]; ok {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := make([]ruleUpdateDiffItem, 0)
	for _, id := range ids {
		beforeRule, hasBefore := beforeMap[id]
		afterRule, hasAfter := afterMap[id]
		switch {
		case !hasBefore && hasAfter:
			api := protectionRuleToAPI(afterRule, 0, "", false)
			out = append(out, ruleUpdateDiffItem{RuleID: api.RuleID, Name: api.Name, ChangeType: "new", After: &api})
		case hasBefore && !hasAfter:
			api := protectionRuleToAPI(beforeRule, 0, "", false)
			out = append(out, ruleUpdateDiffItem{RuleID: api.RuleID, Name: api.Name, ChangeType: "removed", Before: &api})
		default:
			beforeNorm := beforeRule
			afterNorm := afterRule
			beforeNorm.ID, beforeNorm.CreatedAt, beforeNorm.UpdatedAt = 0, 0, 0
			afterNorm.ID, afterNorm.CreatedAt, afterNorm.UpdatedAt = 0, 0, 0
			if reflect.DeepEqual(beforeNorm, afterNorm) {
				continue
			}
			beforeAPI := protectionRuleToAPI(beforeRule, 0, "", false)
			afterAPI := protectionRuleToAPI(afterRule, 0, "", false)
			out = append(out, ruleUpdateDiffItem{RuleID: afterAPI.RuleID, Name: firstNonEmpty(afterAPI.Name, beforeAPI.Name), ChangeType: "modified", Before: &beforeAPI, After: &afterAPI})
		}
	}
	return out
}

func (s *Server) buildRuleUpdateLog(before, after []database.ProtectionRule, source database.ProtectionRuleUpdateSource, meta ruleUpdatePackageMeta, status string, published, emergency bool, evaluation ruleUpdateEvaluationResponse, blockedReason, rollbackFrom, rolledBackTo, snapshotVersion string) database.ProtectionRuleUpdateLog {
	diff := diffProtectionRules(before, after)
	updateID := fmt.Sprintf("ru-%d", time.Now().UnixMilli())
	return database.ProtectionRuleUpdateLog{
		UpdateID:                  updateID,
		SourceID:                  source.ID,
		SourceName:                firstNonEmpty(source.Name, "manual"),
		Trigger:                   ternary(source.ID > 0, "source", "manual"),
		Type:                      firstNonEmpty(meta.Type, source.Type, "manual"),
		Status:                    status,
		Mode:                      firstNonEmpty(meta.Mode, source.Mode, "block"),
		PackageVersion:            meta.Version,
		PackageHash:               meta.Hash,
		PackageURL:                meta.URL,
		Emergency:                 emergency,
		Published:                 published,
		BlockedReason:             blockedReason,
		RuntimeVersion:            currentProtectionRuleRuntimeVersion(),
		RuleCount:                 len(after),
		NewRules:                  countRuleDiff(diff, "new"),
		RemovedRules:              countRuleDiff(diff, "removed"),
		ModifiedRules:             countRuleDiff(diff, "modified"),
		RollbackFromVersion:       rollbackFrom,
		RolledBackToVersion:       rolledBackTo,
		RollbackSnapshotVersion:   snapshotVersion,
		EvaluationPassed:          evaluation.Passed,
		EvaluationSummary:         evaluation.Summary,
		AttackBlockRate:           evaluation.AttackBlockRate,
		AttackBlockRateDelta:      evaluation.AttackBlockRateDelta,
		BenignFalsePositives:      evaluation.BenignFalsePositives,
		BenignFalsePositivesDelta: evaluation.BenignFalsePositivesDelta,
		DiffJSON:                  marshalJSON(diff),
		PublishedRulesJSON:        marshalJSON(after),
		PrePublishRulesJSON:       marshalJSON(before),
	}
}

func countRuleDiff(diff []ruleUpdateDiffItem, changeType string) int {
	total := 0
	for _, item := range diff {
		if item.ChangeType == changeType {
			total++
		}
	}
	return total
}

func (s *Server) persistRuleUpdateLog(ctx context.Context, logModel database.ProtectionRuleUpdateLog) (ruleUpdateLogResponse, database.ProtectionRuleUpdateLog) {
	_ = s.db.WithContext(ctx).Create(&logModel).Error
	return s.ruleUpdateLogToAPI(logModel), logModel
}

func (s *Server) ruleUpdateLogToAPI(item database.ProtectionRuleUpdateLog) ruleUpdateLogResponse {
	resp := ruleUpdateLogResponse{
		ID:              fmt.Sprintf("%d", item.ID),
		UpdateID:        item.UpdateID,
		SourceID:        idString(item.SourceID),
		SourceName:      item.SourceName,
		Trigger:         item.Trigger,
		Type:            item.Type,
		Status:          item.Status,
		Mode:            item.Mode,
		PackageVersion:  item.PackageVersion,
		PackageHash:     item.PackageHash,
		PackageURL:      item.PackageURL,
		RuntimeVersion:  item.RuntimeVersion,
		Published:       item.Published,
		Emergency:       item.Emergency,
		EmergencyCVE:    item.EmergencyCVE,
		RuleCount:       item.RuleCount,
		NewRules:        item.NewRules,
		RemovedRules:    item.RemovedRules,
		ModifiedRules:   item.ModifiedRules,
		BlockedReason:   item.BlockedReason,
		ErrorMessage:    item.ErrorMessage,
		RollbackFrom:    item.RollbackFromVersion,
		RolledBackTo:    item.RolledBackToVersion,
		SnapshotVersion: item.RollbackSnapshotVersion,
		Evaluation: ruleUpdateEvaluationResponse{
			Passed:                    item.EvaluationPassed,
			Summary:                   item.EvaluationSummary,
			BlockedReason:             item.BlockedReason,
			AttackBlockRate:           item.AttackBlockRate,
			AttackBlockRateDelta:      item.AttackBlockRateDelta,
			BenignFalsePositives:      item.BenignFalsePositives,
			BenignFalsePositivesDelta: item.BenignFalsePositivesDelta,
		},
		CreatedAt: formatMillis(item.CreatedAt),
		UpdatedAt: formatMillis(item.UpdatedAt),
	}
	if strings.TrimSpace(item.DiffJSON) != "" {
		_ = json.Unmarshal([]byte(item.DiffJSON), &resp.Diff)
	}
	if strings.TrimSpace(item.PublishedRulesJSON) != "" {
		_ = json.Unmarshal([]byte(item.PublishedRulesJSON), &resp.PublishedRules)
	}
	return resp
}

func marshalJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func formatRuleValidationErrors(errors []protectionRuleValidationError) string {
	if len(errors) == 0 {
		return "rule validation failed"
	}
	parts := make([]string, 0, len(errors))
	for _, item := range errors {
		parts = append(parts, strings.TrimSpace(strings.Join([]string{ternary(item.Line > 0, fmt.Sprintf("line %d", item.Line), ""), item.Field, item.Message}, " ")))
	}
	return strings.Join(parts, "; ")
}

func ternary[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}

func (s *Server) ruleHitsByRuleID(ctx context.Context) map[int]int64 {
	if s == nil || s.db == nil {
		return map[int]int64{}
	}
	type hitRow struct {
		RuleID string
		Count  int64
	}
	var rows []hitRow
	if err := s.db.WithContext(ctx).
		Model(&database.AttackLog{}).
		Select("rule_id, count(*) as count").
		Where("rule_id IS NOT NULL AND rule_id <> ''").
		Group("rule_id").
		Scan(&rows).Error; err != nil {
		return map[int]int64{}
	}
	out := make(map[int]int64, len(rows))
	for _, row := range rows {
		id, err := strconv.Atoi(strings.TrimSpace(row.RuleID))
		if err != nil {
			continue
		}
		out[id] = row.Count
	}
	return out
}

func parseProtectionRuleAction(suffix string) (uint, string, bool, error) {
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || (parts[1] != "enable" && parts[1] != "disable") {
		return 0, "", false, nil
	}
	id, _, err := parseID(parts[0])
	return id, parts[1], true, err
}

func (p protectionRulePayload) toModel(id uint) (database.ProtectionRule, error) {
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	rule := database.ProtectionRule{ID: id, RuleID: p.RuleID, Name: strings.TrimSpace(p.Name), Description: strings.TrimSpace(p.Description), Category: strings.ToLower(strings.TrimSpace(p.Category)), Variable: strings.TrimSpace(p.Variable), Operator: strings.TrimSpace(p.Operator), Pattern: strings.TrimSpace(p.Pattern), Action: strings.TrimSpace(p.Action), Severity: strings.ToLower(strings.TrimSpace(p.Severity)), Score: p.Score, Source: strings.ToLower(strings.TrimSpace(p.Source)), Enabled: enabled}
	if rule.RuleID <= 0 {
		return rule, fmt.Errorf("ruleId is required")
	}
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("rule-%d", rule.RuleID)
	}
	if rule.Category == "" {
		rule.Category = "custom"
	}
	if rule.Variable == "" || rule.Operator == "" || rule.Pattern == "" {
		return rule, fmt.Errorf("variable, operator and pattern are required")
	}
	if rule.Source == "" {
		rule.Source = "custom"
	}
	switch rule.Source {
	case "crs", "custom", "semantic", "system":
	default:
		return rule, fmt.Errorf("unsupported rule source")
	}
	switch rule.Action {
	case "deny", "log", "pass":
	default:
		return rule, fmt.Errorf("unsupported rule action")
	}
	switch rule.Severity {
	case "critical", "high", "medium", "low", "info":
	default:
		rule.Severity = "medium"
	}
	if rule.Score <= 0 {
		rule.Score = 1
	}
	return rule, nil
}
func (p protectionRulePayload) merge(existing database.ProtectionRule) (database.ProtectionRule, error) {
	next, err := p.toModel(existing.ID)
	if err != nil {
		return existing, err
	}
	next.CreatedAt = existing.CreatedAt
	return next, nil
}
func protectionRuleToAPI(rule database.ProtectionRule, hits int64, runtimeVersion string, hotReload bool) protectionRuleResponse {
	return protectionRuleResponse{
		ID:             fmt.Sprintf("%d", rule.ID),
		RuleID:         fmt.Sprintf("%d", rule.RuleID),
		Name:           rule.Name,
		Description:    rule.Description,
		Category:       rule.Category,
		Variable:       rule.Variable,
		Operator:       rule.Operator,
		Pattern:        rule.Pattern,
		Severity:       rule.Severity,
		Score:          rule.Score,
		Action:         rule.Action,
		Source:         firstNonEmpty(rule.Source, "custom"),
		Enabled:        rule.Enabled,
		Hits:           hits,
		RuntimeVersion: runtimeVersion,
		HotReload:      hotReload,
		UpdatedAt:      formatMillis(rule.UpdatedAt),
	}
}
func protectionDetectionRuleToAPI(rule detection.Rule, runtimeVersion string, hotReload bool) protectionRuleResponse {
	return protectionRuleResponse{ID: fmt.Sprintf("runtime-%d", rule.ID), RuleID: fmt.Sprintf("%d", rule.ID), Name: rule.Message, Description: rule.Message, Category: rule.Group, Variable: rule.Variable, Operator: rule.Operator, Pattern: rule.Pattern, Severity: rule.Severity, Score: rule.Score, Action: string(rule.Action), Source: firstNonEmpty(rule.Source, "crs"), Enabled: rule.Enabled, RuntimeVersion: runtimeVersion, HotReload: hotReload}
}
func protectionRuleToDetection(rule database.ProtectionRule) detection.Rule {
	return detection.Rule{ID: rule.RuleID, Phase: 2, Group: rule.Category, Variable: rule.Variable, Operator: rule.Operator, Pattern: rule.Pattern, Action: detection.RuleAction(rule.Action), Message: rule.Name, Severity: rule.Severity, Score: rule.Score, Source: rule.Source, Enabled: rule.Enabled}
}

func (s *Server) handleCaptchaAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.captchaSettings())
	case http.MethodPut:
		var payload captchaSettings
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		if err := validateCaptchaSettings(payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.captchaConfig.Store(payload)
		writeJSON(w, http.StatusOK, payload)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}
func validateCaptchaSettings(settings captchaSettings) error {
	if settings.TTLSeconds <= 0 {
		return fmt.Errorf("ttlSeconds must be positive")
	}
	if settings.MaxAttempts <= 0 {
		return fmt.Errorf("maxAttempts must be positive")
	}
	for _, trigger := range settings.Triggers {
		if strings.TrimSpace(trigger.Name) == "" {
			return fmt.Errorf("trigger name is required")
		}
		switch trigger.Method {
		case "image", "slider", "button":
		default:
			return fmt.Errorf("unsupported captcha method")
		}
	}
	return nil
}
func (s *Server) captchaSettings() captchaSettings {
	if value := s.captchaConfig.Load(); value != nil {
		return value.(captchaSettings)
	}
	settings := captchaSettings{ImageCaptcha: false, SliderCaptcha: false, TTLSeconds: 300, MaxAttempts: 5, Triggers: []captchaTrigger{}}
	s.captchaConfig.Store(settings)
	return settings
}

func parseUint(value string) (uint, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	return uint(n), err
}

func parseID(value string) (uint, bool, error) {
	if value == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return uint(n), true, err
}

func parseSiteAction(suffix string) (uint, string, bool, error) {
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || (parts[1] != "enable" && parts[1] != "disable") {
		return 0, "", false, nil
	}
	id, _, err := parseID(parts[0])
	return id, parts[1], true, err
}

func (s *Server) siteRuntimeStatusResponse(ctx context.Context, id uint) siteRuntimeStatus {
	summary := siteRuntimeStatus{ID: fmt.Sprintf("%d", id), ListenStatus: "unknown"}
	if s.sites == nil {
		return summary
	}
	site, err := s.sites.Get(ctx, id)
	if err != nil {
		summary.ListenStatus = "not-found"
		summary.ListenReason = "site not found"
		return summary
	}
	status, protocol, reason := s.evaluateSiteListener(site)
	summary.ListenPort = site.ListenPort
	summary.Status = site.Status
	summary.ListenStatus = status
	summary.ListenProtocol = protocol
	summary.ListenReason = reason
	summary.UpdatedAt = formatMillis(site.UpdatedAt)
	if s.siteListeners != nil {
		summary.ListenerPorts = s.SiteListenerPorts()
	}
	return summary
}

func (s *Server) listenersResponse(ctx context.Context) listenersResponse {
	items := make([]listenerSummary, 0)
	if s.sites == nil {
		return listenersResponse{Items: items, Total: 0}
	}
	sites, err := s.sites.List(ctx)
	if err != nil {
		return listenersResponse{Items: items, Total: 0}
	}
	for _, site := range sites {
		status, protocol, reason := s.evaluateSiteListener(site)
		items = append(items, listenerSummary{Port: site.ListenPort, Protocol: protocol, Status: status, Reason: reason, SiteID: fmt.Sprintf("%d", site.ID), SiteName: site.Name})
	}
	return listenersResponse{Items: items, Total: len(items)}
}

func (s *Server) evaluateSiteListener(site database.Site) (status, protocol, reason string) {
	protocol = listenerProtocolForSite(site)
	if site.Status == database.SiteStatusDisabled {
		return "disabled", protocol, "site disabled"
	}
	if site.ListenPort <= 0 {
		return "not-mapped", protocol, "listen port not configured"
	}
	if protocol == "https" && strings.TrimSpace(site.CertificateName) == "" && site.CertificateID == 0 {
		return "error", protocol, "tls certificate missing"
	}
	if s.siteListeners != nil {
		for _, p := range s.SiteListenerPorts() {
			if p == site.ListenPort {
				return "listening", protocol, ""
			}
		}
	}
	return "not-mapped", protocol, "listener not started"
}

func listenerProtocolForSite(site database.Site) string {
	if strings.EqualFold(site.TLSMode, "custom") || strings.EqualFold(site.TLSMode, "auto") {
		return "https"
	}
	return "http"
}

func (s *Server) reloadRuntime(r *http.Request) {
	ctx := r.Context()
	_ = s.reloadPolicies(ctx)
	if s.runtime != nil {
		_ = s.runtime.Reload(ctx)
	}
	_ = s.syncSiteListeners(ctx)
}

func (s *Server) reloadPolicies(ctx context.Context) error {
	if s.db == nil {
		s.policies.Store(policySnapshot{})
		return nil
	}
	var accessRules []database.AccessRule
	if err := s.db.WithContext(ctx).Order("id asc").Find(&accessRules).Error; err != nil {
		return err
	}
	var ccPolicies []database.CCPolicy
	if err := s.db.WithContext(ctx).Order("id asc").Find(&ccPolicies).Error; err != nil {
		return err
	}
	s.policies.Store(policySnapshot{AccessRules: accessRules, CCPolicies: ccPolicies})
	return nil
}

func (s *Server) reloadCertificates(ctx context.Context) error {
	if s == nil || s.db == nil {
		s.certificates.Store(certificateSnapshot{ByID: map[uint]database.Certificate{}, ByDomain: map[string]database.Certificate{}})
		return nil
	}
	var certs []database.Certificate
	if err := s.db.WithContext(ctx).Order("id asc").Find(&certs).Error; err != nil {
		return err
	}
	snapshot := certificateSnapshot{ByID: map[uint]database.Certificate{}, ByDomain: map[string]database.Certificate{}}
	for _, cert := range certs {
		snapshot.ByID[cert.ID] = cert
		for _, domain := range cert.Domains() {
			normalized := gateway.NormalizeHost(domain)
			if normalized != "" {
				snapshot.ByDomain[normalized] = cert
			}
		}
	}
	s.certificates.Store(snapshot)
	return nil
}

func (s *Server) policySnapshot() policySnapshot {
	if value := s.policies.Load(); value != nil {
		return value.(policySnapshot)
	}
	return policySnapshot{}
}

func (p sitePayload) toSite(id uint) (database.Site, error) {

	domains := p.Domains
	if len(domains) == 0 && p.Domain != "" {
		domains = []string{p.Domain}
	}
	policyMode := normalizePolicyMode(p.PolicyMode)
	defaults := policyModeDefaults(policyMode)
	threshold := p.BlockScoreThreshold
	if threshold <= 0 {
		threshold = defaultThresholdForPolicyMode(policyMode)
	}
	certID, _, err := parseID(strings.TrimSpace(p.CertificateID))
	if err != nil {
		return database.Site{}, fmt.Errorf("invalid certificate id")
	}
	site := database.Site{ID: id, Name: p.Name, Upstream: p.Upstream, ListenPort: p.ListenPort, Status: p.Status, TLSMode: p.TLSMode, CertificateID: certID, WAFEnabled: boolDefault(p.WAFEnabled, true), CCProtection: boolDefault(p.CCProtection, defaults.CCProtection), SemanticProtection: boolDefault(p.SemanticProtection, defaults.SemanticProtection), PolicyMode: policyMode, BlockScoreThreshold: threshold}
	if err := site.SetRuleGroups(normalizeRuleGroups(p.RuleGroups)); err != nil {
		return site, err
	}
	if certID, err := strconv.ParseUint(strings.TrimSpace(p.CertificateID), 10, 64); err == nil && certID > 0 {
		site.CertificateID = uint(certID)
	}
	if err := site.SetDomains(domains); err != nil {
		return site, err
	}
	return site, nil
}
func (p sitePayload) merge(site database.Site) (database.Site, error) {
	next, err := p.toSite(site.ID)
	if err != nil {
		return site, err
	}
	if next.Name == "" {
		next.Name = site.Name
	}
	if next.Upstream == "" {
		next.Upstream = site.Upstream
	}
	if next.DomainsJSON == "null" || next.DomainsJSON == "[]" {
		next.DomainsJSON = site.DomainsJSON
	}
	if strings.TrimSpace(p.PolicyMode) == "" {
		next.PolicyMode = site.PolicyMode
	}
	if p.CCProtection == nil && strings.TrimSpace(p.PolicyMode) == "" {
		next.CCProtection = site.CCProtection
	}
	if p.SemanticProtection == nil && strings.TrimSpace(p.PolicyMode) == "" {
		next.SemanticProtection = site.SemanticProtection
	}
	if p.BlockScoreThreshold <= 0 && strings.TrimSpace(p.PolicyMode) == "" {
		next.BlockScoreThreshold = site.BlockScoreThreshold
	}
	if p.RuleGroups == nil {
		next.RuleGroupsJSON = site.RuleGroupsJSON
	}
	if strings.TrimSpace(p.CertificateID) == "" {
		next.CertificateID = site.CertificateID
		next.CertificateName = site.CertificateName
	}
	return next, nil
}
func normalizeRuleGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	seen := map[string]bool{}
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		out = append(out, group)
	}
	return out
}
func defaultThresholdForPolicyMode(mode string) int {
	return policyModeDefaults(mode).BlockScoreThreshold
}
func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func (s *Server) dashboardOverview() dashboardOverview {
	overview, _ := s.reports.Overview(contextOrBackground())
	if s.reports == nil {
		return sampleDashboard(s)
	}
	accessLogs := s.loadAccessLogs(nil)
	attackResp := s.attackLogsForExport(nil)
	return dashboardOverview{Status: systemStatus{Service: "Aegis-WAF", Version: "dev", Uptime: time.Since(processStartedAt).Round(time.Second).String(), Mode: s.cfg.Mode, Health: "ok"}, Metrics: []dashboardMetric{{Key: "requests", Label: "今日请求", Value: float64(overview.RequestsToday), Status: "primary"}, {Key: "blocked", Label: "拦截攻击", Value: float64(overview.BlockedToday), Status: "danger"}, {Key: "latency", Label: "平均延迟", Value: overview.AverageLatencyMS, Unit: "ms", Status: "warning"}}, Pipeline: []pipelineStageMetric{{Stage: "gateway", Label: "站点接入", Enabled: true}, {Stage: "detection", Label: "攻击检测", Enabled: s.processor != nil}, {Stage: "semantic", Label: "语义分析", Enabled: s.security.EnableSemantic}}, RecentEvents: s.recentEvents(), QPS: qpsFromAccessLogs(accessLogs), BlockRate: blockRateFromAccessLogs(accessLogs), TopIPs: topAccessValues(accessLogs, func(log database.AccessLog) string { return log.SourceIP }, 5), TopPaths: topAccessValues(accessLogs, func(log database.AccessLog) string { return log.Path }, 5), TopAttackTypes: topAttackValues(attackResp.Logs, func(log attackLogEntry) string { return log.AttackType }, 5)}
}

func contextOrBackground() context.Context { return context.Background() }

func (s *Server) attackLogs(r *http.Request) attackLogResponse {
	return s.attackLogsResponse(r, true)
}

func (s *Server) attackLogsForExport(r *http.Request) attackLogResponse {
	return s.attackLogsResponse(r, false)
}

func (s *Server) attackLogsResponse(r *http.Request, paginate bool) attackLogResponse {
	if s.reports == nil {
		return sampleAttackLogs()
	}
	logs, _ := s.reports.AttackLogs(context.Background(), 10000)
	filtered := filterAttackLogs(logs, r)
	entries := make([]attackLogEntry, 0, len(filtered))
	critical := 0
	observed := 0
	for _, log := range filtered {
		if log.Severity == "critical" {
			critical++
		}
		if log.Action == "observe" {
			observed++
		}
		entries = append(entries, attackLogToEntry(log))
	}
	total := len(entries)
	if paginate {
		entries = paginateAttackLogEntries(entries, r)
	}
	return attackLogResponse{Summary: attackLogSummary{Total: total, Blocked: total - observed, Observed: observed, Critical: critical}, Logs: entries, Total: total}
}

func filterAttackLogs(logs []database.AttackLog, r *http.Request) []database.AttackLog {
	if r == nil {
		return logs
	}
	q := r.URL.Query()
	start := parseAttackLogTime(q.Get("startTime"))
	end := parseAttackLogTime(q.Get("endTime"))
	site := strings.ToLower(firstNonEmpty(q.Get("site"), q.Get("siteName")))
	siteID := q.Get("siteId")
	attackType := strings.ToLower(q.Get("attackType"))
	action := strings.ToLower(q.Get("action"))
	ruleGroup := strings.ToLower(q.Get("ruleGroup"))
	sourceIP := strings.ToLower(firstNonEmpty(q.Get("sourceIp"), q.Get("ip")))
	path := strings.ToLower(q.Get("path"))
	severity := strings.ToLower(q.Get("severity"))
	stage := strings.ToLower(q.Get("stage"))
	keyword := strings.ToLower(q.Get("keyword"))
	out := make([]database.AttackLog, 0, len(logs))
	for _, log := range logs {
		created := time.UnixMilli(log.CreatedAt)
		if !start.IsZero() && created.Before(start) {
			continue
		}
		if !end.IsZero() && created.After(end) {
			continue
		}
		if site != "" && !strings.Contains(strings.ToLower(log.SiteName), site) {
			continue
		}
		if siteID != "" && fmt.Sprintf("%d", log.SiteID) != siteID {
			continue
		}
		if attackType != "" && !strings.Contains(strings.ToLower(log.AttackType), attackType) {
			continue
		}
		if action != "" && strings.ToLower(log.Action) != action {
			continue
		}
		if ruleGroup != "" && !strings.Contains(strings.ToLower(log.Stage+" "+log.RuleID+" "+log.AttackType), ruleGroup) {
			continue
		}
		if sourceIP != "" && !strings.Contains(strings.ToLower(log.SourceIP), sourceIP) {
			continue
		}
		if path != "" && !strings.Contains(strings.ToLower(log.Path), path) {
			continue
		}
		if severity != "" && strings.ToLower(log.Severity) != severity {
			continue
		}
		if stage != "" && !strings.Contains(strings.ToLower(log.Stage), stage) {
			continue
		}
		if keyword != "" && !attackLogContainsKeyword(log, keyword) {
			continue
		}
		out = append(out, log)
	}
	return out
}

func attackLogContainsKeyword(log database.AttackLog, keyword string) bool {
	fields := []string{log.SiteName, log.SourceIP, log.Method, log.Path, log.AttackType, log.Severity, log.Action, log.Stage, log.RuleID, log.RuleMessage, log.PayloadSnippet, log.ExplanationJSON, log.OperatorSuggestion}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), keyword) {
			return true
		}
	}
	return false
}

func paginateAttackLogEntries(entries []attackLogEntry, r *http.Request) []attackLogEntry {
	if r == nil {
		return entries
	}
	q := r.URL.Query()
	page := parsePositiveInt(q.Get("page"), 1)
	pageSize := parsePositiveInt(q.Get("pageSize"), len(entries))
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 100
	}
	start := (page - 1) * pageSize
	if start >= len(entries) {
		return []attackLogEntry{}
	}
	end := start + pageSize
	if end > len(entries) {
		end = len(entries)
	}
	return entries[start:end]
}

func parsePositiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseAttackLogTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	if millis, err := strconv.ParseInt(value, 10, 64); err == nil {
		if millis > 0 {
			return time.UnixMilli(millis)
		}
	}
	formats := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
	for _, format := range formats {
		if t, err := time.ParseInLocation(format, value, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Server) accessLogs(r *http.Request) accessLogResponse {
	if s.reports == nil || s.db == nil {
		return accessLogResponse{Logs: []accessLogEntry{}, Total: 0}
	}
	logs := s.loadAccessLogs(r)
	entries := make([]accessLogEntry, 0, len(logs))
	for _, log := range logs {
		entries = append(entries, accessLogToEntry(log))
	}
	total := len(entries)
	entries = paginateAccessLogEntries(entries, r)
	return accessLogResponse{Logs: entries, Total: total}
}

func (s *Server) loadAccessLogs(r *http.Request) []database.AccessLog {
	if s == nil || s.db == nil {
		return nil
	}
	query := s.db.WithContext(context.Background()).Model(&database.AccessLog{})
	if r != nil {
		q := r.URL.Query()
		if start := parseAttackLogTime(q.Get("startTime")); !start.IsZero() {
			query = query.Where("created_at >= ?", start.UnixMilli())
		}
		if end := parseAttackLogTime(q.Get("endTime")); !end.IsZero() {
			query = query.Where("created_at <= ?", end.UnixMilli())
		}
		if site := firstNonEmpty(q.Get("site"), q.Get("siteName")); site != "" {
			query = query.Where("LOWER(site_name) LIKE ?", "%"+strings.ToLower(site)+"%")
		}
		if siteID := q.Get("siteId"); siteID != "" {
			query = query.Where("site_id = ?", siteID)
		}
		if host := q.Get("host"); host != "" {
			query = query.Where("LOWER(host) LIKE ?", "%"+strings.ToLower(host)+"%")
		}
		if sourceIP := firstNonEmpty(q.Get("sourceIp"), q.Get("ip")); sourceIP != "" {
			query = query.Where("LOWER(source_ip) LIKE ?", "%"+strings.ToLower(sourceIP)+"%")
		}
		if method := q.Get("method"); method != "" {
			query = query.Where("LOWER(method) = ?", strings.ToLower(method))
		}
		if path := q.Get("path"); path != "" {
			query = query.Where("LOWER(path) LIKE ?", "%"+strings.ToLower(path)+"%")
		}
		if decision := firstNonEmpty(q.Get("decision"), q.Get("action")); decision != "" {
			query = query.Where("LOWER(decision) = ?", strings.ToLower(decision))
		}
		if status := q.Get("status"); status != "" {
			query = query.Where("status = ?", status)
		}
		if ruleGroup := q.Get("ruleGroup"); ruleGroup != "" {
			kw := "%" + strings.ToLower(ruleGroup) + "%"
			query = query.Where("LOWER(decision) LIKE ? OR LOWER(path) LIKE ?", kw, kw)
		}
		if keyword := q.Get("keyword"); keyword != "" {
			kw := "%" + strings.ToLower(keyword) + "%"
			query = query.Where("LOWER(site_name) LIKE ? OR LOWER(host) LIKE ? OR LOWER(source_ip) LIKE ? OR LOWER(path) LIKE ? OR LOWER(user_agent) LIKE ?", kw, kw, kw, kw, kw)
		}
	}
	var logs []database.AccessLog
	_ = query.Order("created_at desc, id desc").Limit(10000).Find(&logs).Error
	return logs
}

func paginateAccessLogEntries(entries []accessLogEntry, r *http.Request) []accessLogEntry {
	if r == nil {
		return entries
	}
	q := r.URL.Query()
	page := parsePositiveInt(q.Get("page"), 1)
	pageSize := parsePositiveInt(q.Get("pageSize"), len(entries))
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 100
	}
	start := (page - 1) * pageSize
	if start >= len(entries) {
		return []accessLogEntry{}
	}
	end := start + pageSize
	if end > len(entries) {
		end = len(entries)
	}
	return entries[start:end]
}

func accessLogToEntry(log database.AccessLog) accessLogEntry {
	return accessLogEntry{ID: fmt.Sprintf("%d", log.ID), Time: formatMillis(log.CreatedAt), SiteName: log.SiteName, Host: log.Host, SourceIP: log.SourceIP, Method: log.Method, Path: log.Path, Query: log.Query, UserAgent: log.UserAgent, Status: log.Status, Decision: log.Decision, Upstream: log.Upstream, LatencyMS: log.LatencyMS, BytesIn: log.BytesIn, BytesOut: log.BytesOut}
}

func (s *Server) handleProtectionTrafficAPI(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, trafficEmptyResponse(path))
		return
	}
	accessLogs := s.loadAccessLogs(r)
	attackLogs := filterAttackLogs(s.loadAttackLogsForTraffic(r), r)
	switch path {
	case "/protection/traffic/overview":
		writeJSON(w, http.StatusOK, buildTrafficOverview(accessLogs, attackLogs))
	case "/protection/traffic/trend":
		writeJSON(w, http.StatusOK, buildTrafficTrend(accessLogs))
	case "/protection/traffic/top-ip":
		writeJSON(w, http.StatusOK, trafficRankFromAccess(accessLogs, func(log database.AccessLog) string { return log.SourceIP }, 10))
	case "/protection/traffic/top-path":
		writeJSON(w, http.StatusOK, trafficRankFromAccess(accessLogs, func(log database.AccessLog) string { return log.Path }, 10))
	case "/protection/traffic/status-codes":
		writeJSON(w, http.StatusOK, trafficRankFromAccess(accessLogs, func(log database.AccessLog) string { return strconv.Itoa(log.Status) }, 10))
	case "/protection/traffic/sites":
		writeJSON(w, http.StatusOK, trafficRankFromAccess(accessLogs, func(log database.AccessLog) string {
			return firstNonEmpty(log.SiteName, fmt.Sprintf("site:%d", log.SiteID))
		}, 20))
	case "/protection/attack-events":
		entries := make([]attackLogEntry, 0, len(attackLogs))
		for _, log := range attackLogs {
			entries = append(entries, attackLogToEntry(log))
		}
		writeJSON(w, http.StatusOK, attackLogResponse{Summary: attackSummaryFromEntries(entries), Logs: paginateAttackLogEntries(entries, r), Total: len(entries)})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "protection traffic endpoint not found"})
	}
}

func trafficEmptyResponse(path string) any {
	switch path {
	case "/protection/traffic/overview":
		return trafficOverviewResponse{}
	case "/protection/traffic/trend":
		return trafficTrendResponse{Trend: []attackTrendPoint{}, Total: 0}
	case "/protection/attack-events":
		return attackLogResponse{Logs: []attackLogEntry{}, Total: 0}
	default:
		return trafficRankResponse{Items: []trafficRankItem{}, Total: 0}
	}
}

func (s *Server) loadAttackLogsForTraffic(r *http.Request) []database.AttackLog {
	if s == nil || s.db == nil {
		return nil
	}
	var logs []database.AttackLog
	_ = s.db.WithContext(context.Background()).Order("created_at desc, id desc").Limit(10000).Find(&logs).Error
	return logs
}

func buildTrafficOverview(accessLogs []database.AccessLog, attackLogs []database.AttackLog) trafficOverviewResponse {
	overview := trafficOverviewResponse{TotalRequests: len(accessLogs), QPS: qpsFromAccessLogs(accessLogs)}
	for _, log := range accessLogs {
		switch strings.ToLower(log.Decision) {
		case "block", "deny":
			overview.BlockedRequests++
		case "observe", "log":
			overview.ObservedRequests++
		case "captcha":
			overview.CaptchaRequests++
		case "temp-block", "temp_block":
			overview.TempBlockRequests++
		}
		if log.Status == http.StatusForbidden && !strings.EqualFold(log.Decision, "block") && !strings.EqualFold(log.Decision, "deny") {
			overview.BlockedRequests++
		}
	}
	for _, log := range attackLogs {
		switch strings.ToLower(log.Action) {
		case "block", "deny":
			if overview.BlockedRequests == 0 && len(accessLogs) == 0 {
				overview.BlockedRequests++
			}
		case "observe", "log":
			if len(accessLogs) == 0 {
				overview.ObservedRequests++
			}
		case "captcha":
			if len(accessLogs) == 0 {
				overview.CaptchaRequests++
			}
		case "temp-block", "temp_block":
			if len(accessLogs) == 0 {
				overview.TempBlockRequests++
			}
		}
	}
	if overview.TotalRequests > 0 {
		overview.BlockRate = float64(overview.BlockedRequests) * 100 / float64(overview.TotalRequests)
	}
	return overview
}

func buildTrafficTrend(logs []database.AccessLog) trafficTrendResponse {
	counts := make(map[string]*attackTrendPoint)
	for _, log := range logs {
		bucket := time.UnixMilli(log.CreatedAt).Format("2006-01-02 15:00")
		point := counts[bucket]
		if point == nil {
			point = &attackTrendPoint{Time: bucket}
			counts[bucket] = point
		}
		point.Requests++
		if strings.EqualFold(log.Decision, "block") || strings.EqualFold(log.Decision, "deny") || log.Status == http.StatusForbidden {
			point.Blocked++
		}
	}
	trend := make([]attackTrendPoint, 0, len(counts))
	for _, point := range counts {
		trend = append(trend, *point)
	}
	sort.Slice(trend, func(i, j int) bool { return trend[i].Time < trend[j].Time })
	return trafficTrendResponse{Trend: trend, Total: len(trend)}
}

func trafficRankFromAccess(logs []database.AccessLog, value func(database.AccessLog) string, limit int) trafficRankResponse {
	items := topAccessValues(logs, value, limit)
	ranked := make([]trafficRankItem, 0, len(items))
	for _, item := range items {
		ranked = append(ranked, trafficRankItem{Name: item.Value, Key: item.Value, Value: item.Count, Count: item.Count})
	}
	return trafficRankResponse{Items: ranked, Total: len(ranked)}
}

func attackSummaryFromEntries(entries []attackLogEntry) attackLogSummary {
	summary := attackLogSummary{Total: len(entries)}
	for _, entry := range entries {
		if strings.EqualFold(entry.Action, "observe") || strings.EqualFold(entry.Action, "log") {
			summary.Observed++
		} else {
			summary.Blocked++
		}
		if strings.EqualFold(entry.Severity, "critical") {
			summary.Critical++
		}
	}
	return summary
}

func (s *Server) handleAttackLogActionAPI(w http.ResponseWriter, r *http.Request, suffix string) {
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "attack log action not found"})
		return
	}
	id, hasID, err := parseID(parts[0])
	if err != nil || !hasID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid attack log id"})
		return
	}
	var log database.AttackLog
	if s.db == nil || s.db.WithContext(r.Context()).First(&log, id).Error != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "attack log not found"})
		return
	}
	switch parts[1] {
	case "whitelist-suggestions":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, whitelistSuggestionResponse{Suggestions: suggestionsFromAttackLog(log)})
	case "whitelist":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		var payload whitelistApplyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid json"})
			return
		}
		rule, err := whitelistPayloadToRule(payload, log)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if err := s.db.WithContext(r.Context()).Create(&rule).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		s.recordAuditEvent(r.Context(), "whitelist_created", log.SiteID, log.SiteName, fmt.Sprintf("access-rule:%d", rule.ID), rule.Type, fmt.Sprintf("from attack log %d: %s", log.ID, rule.Value))
		s.reloadRuntime(r)
		writeJSON(w, http.StatusCreated, accessRuleToAPI(rule))
	case "whitelist-validate":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.validateAttackLogWhitelist(r.Context(), log))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "attack log action not found"})
	}
}

func suggestionsFromAttackLog(log database.AttackLog) []whitelistSuggestion {
	suggestions := []whitelistSuggestion{}
	cleanPath := strings.Split(strings.TrimSpace(log.Path), "?")[0]
	siteID := idString(log.SiteID)
	expiresAt := defaultWhitelistExpiresAt()
	if cleanPath != "" {
		suggestions = append(suggestions, whitelistSuggestion{Type: database.AccessRuleURLWhitelist, Value: cleanPath, Scope: "path", SiteID: siteID, Path: cleanPath, RuleID: log.RuleID, ExpiresAt: expiresAt, Description: "仅当前站点当前路径跳过检测"})
	}
	if strings.TrimSpace(log.SourceIP) != "" {
		typeName := database.AccessRuleIPWhitelist
		if strings.Contains(log.SourceIP, "/") {
			typeName = database.AccessRuleCIDRWhitelist
		}
		suggestions = append(suggestions, whitelistSuggestion{Type: typeName, Value: log.SourceIP, Scope: "site", SiteID: siteID, RuleID: log.RuleID, ExpiresAt: expiresAt, Description: "仅当前站点允许该来源 IP/CIDR 跳过检测"})
	}
	if param := firstQueryParam(log.Path); param != "" {
		suggestions = append(suggestions, whitelistSuggestion{Type: database.AccessRuleParamWhitelist, Value: param, Scope: "path", SiteID: siteID, Path: cleanPath, RuleID: log.RuleID, Variable: strings.Split(param, "=")[0], ExpiresAt: expiresAt, Description: "仅当前站点、当前路径、当前参数跳过检测"})
	}
	if strings.TrimSpace(log.RuleID) != "" {
		suggestions = append(suggestions, whitelistSuggestion{Type: database.AccessRuleRuleDisable, Value: log.RuleID, Scope: "path", SiteID: siteID, Path: cleanPath, RuleID: log.RuleID, Variable: firstNonEmpty(log.AttackType, log.Stage), ExpiresAt: expiresAt, Description: "仅当前站点/路径禁用命中规则"})
	}
	return suggestions
}

func defaultWhitelistExpiresAt() string {
	return time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
}

func firstQueryParam(pathValue string) string {
	idx := strings.Index(pathValue, "?")
	if idx < 0 || idx+1 >= len(pathValue) {
		return ""
	}
	values, err := url.ParseQuery(pathValue[idx+1:])
	if err != nil {
		return ""
	}
	for key, vals := range values {
		if key == "" {
			continue
		}
		if len(vals) > 0 && vals[0] != "" {
			return key + "=" + vals[0]
		}
		return key
	}
	return ""
}

func whitelistPayloadToRule(payload whitelistApplyPayload, log database.AttackLog) (database.AccessRule, error) {
	siteID := log.SiteID
	if siteID == 0 && strings.TrimSpace(payload.SiteID) != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(payload.SiteID), 10, 64); err == nil {
			siteID = uint(parsed)
		}
	}
	ruleType := strings.TrimSpace(payload.Type)
	value := strings.TrimSpace(payload.Value)
	if value == "" {
		value = defaultWhitelistValue(ruleType, log)
	}
	scope := normalizeWhitelistScope(payload.Scope)
	if log.ID > 0 && scope == "site" && (ruleType == database.AccessRuleURLWhitelist || ruleType == database.AccessRuleParamWhitelist || ruleType == database.AccessRuleRuleDisable) {
		scope = "path"
	}
	rule := database.AccessRule{SiteID: siteID, Type: ruleType, Value: value, Scope: scope, RuleID: strings.TrimSpace(payload.RuleID), Variable: strings.TrimSpace(payload.Variable), CreatedFrom: firstNonEmpty(logSource(log), "manual"), Description: strings.TrimSpace(payload.Description), Enabled: true}
	pathValue := strings.Split(strings.TrimSpace(log.Path), "?")[0]
	if rule.Scope == "path" && pathValue != "" && (rule.Type == database.AccessRuleParamWhitelist || rule.Type == database.AccessRuleRuleDisable) {
		rule.Variable = firstNonEmpty(rule.Variable, strings.Split(firstQueryParam(log.Path), "=")[0])
		rule.Value = pathScopedWhitelistValue(pathValue, rule.Value)
	}
	if rule.Description == "" {
		rule.Description = fmt.Sprintf("由攻击事件 %d 生成", log.ID)
	}
	if rule.Type == database.AccessRuleRuleDisable && rule.RuleID == "" {
		rule.RuleID = strings.TrimPrefix(rule.Value, pathValue+"|")
	}
	if strings.TrimSpace(payload.Status) == "disabled" {
		rule.Enabled = false
	}
	if strings.TrimSpace(payload.ExpiresAt) != "" {
		expires, err := parseWhitelistExpiresAt(payload.ExpiresAt)
		if err != nil {
			return rule, err
		}
		rule.ExpiresAt = expires
	}
	if rule.Type == "" || rule.Value == "" {
		return rule, fmt.Errorf("type and value are required")
	}
	switch rule.Type {
	case database.AccessRuleIPWhitelist, database.AccessRuleCIDRWhitelist, database.AccessRuleURLWhitelist, database.AccessRuleParamWhitelist, database.AccessRuleHeaderWhitelist, database.AccessRuleCookieWhitelist, database.AccessRuleRuleDisable:
	default:
		return rule, fmt.Errorf("unsupported whitelist type")
	}
	return rule, nil
}

func defaultWhitelistValue(ruleType string, log database.AttackLog) string {
	switch ruleType {
	case database.AccessRuleURLWhitelist:
		return strings.Split(strings.TrimSpace(log.Path), "?")[0]
	case database.AccessRuleParamWhitelist:
		return firstQueryParam(log.Path)
	case database.AccessRuleIPWhitelist, database.AccessRuleCIDRWhitelist:
		return strings.TrimSpace(log.SourceIP)
	case database.AccessRuleRuleDisable:
		return strings.TrimSpace(log.RuleID)
	default:
		return ""
	}
}

func pathScopedWhitelistValue(pathValue, value string) string {
	pathValue = strings.Split(strings.TrimSpace(pathValue), "?")[0]
	value = strings.TrimSpace(value)
	if pathValue == "" || value == "" || strings.HasPrefix(value, pathValue+"|") {
		return value
	}
	return pathValue + "|" + value
}

func normalizeWhitelistScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "global", "path", "ruleid", "rule_id", "variable":
		return strings.ToLower(strings.TrimSpace(scope))
	default:
		return "site"
	}
}

func logSource(log database.AttackLog) string {
	if log.ID == 0 {
		return ""
	}
	return fmt.Sprintf("attack-log:%d", log.ID)
}

func (s *Server) validateAttackLogWhitelist(_ context.Context, log database.AttackLog) whitelistValidationResponse {
	snapshot := s.policySnapshot()
	now := time.Now().UnixMilli()
	req := accesscontrol.Request{SiteID: log.SiteID, SourceIP: net.ParseIP(log.SourceIP), Method: log.Method, Path: log.Path, Args: queryArgs(log.Path)}
	applicable := make([]database.AccessRule, 0, len(snapshot.AccessRules))
	for _, rule := range snapshot.AccessRules {
		if ruleAppliesToRequest(rule, log.SiteID, log.Path, now) {
			applicable = append(applicable, rule)
		}
	}
	before := "block"
	after := accesscontrol.NewEvaluator(applicable).Evaluate(req)
	status := "not_equivalent"
	if after.Decision == accesscontrol.DecisionAllow || after.Decision == accesscontrol.DecisionSkipDetection {
		status = "would_allow"
	}
	return whitelistValidationResponse{AttackLogID: fmt.Sprintf("%d", log.ID), RuleID: resultRuleID(after), BeforeDecision: before, AfterDecision: string(after.Decision), EquivalentStatus: status, Reason: after.Reason}
}

func queryArgs(pathValue string) map[string][]string {
	idx := strings.Index(pathValue, "?")
	if idx < 0 || idx+1 >= len(pathValue) {
		return nil
	}
	values, err := url.ParseQuery(pathValue[idx+1:])
	if err != nil {
		return nil
	}
	return values
}

func resultRuleID(result accesscontrol.Result) string {
	if result.Rule.ID > 0 {
		return fmt.Sprintf("%d", result.Rule.ID)
	}
	return firstNonEmpty(result.Rule.RuleID, result.Rule.Value)
}

func parseWhitelistExpiresAt(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		return n, nil
	}
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return t.UnixMilli(), nil
		}
	}
	return 0, fmt.Errorf("invalid expiresAt")
}

func (s *Server) auditEvents(r *http.Request) auditEventResponse {
	if s.db == nil {
		return auditEventResponse{Events: []auditEventEntry{}, Total: 0}
	}
	limit := 100
	if r != nil {
		limit = parsePositiveInt(r.URL.Query().Get("pageSize"), 100)
	}
	if limit > 200 {
		limit = 200
	}
	var events []database.AuditEvent
	_ = s.db.WithContext(context.Background()).Order("created_at desc, id desc").Limit(limit).Find(&events).Error
	out := make([]auditEventEntry, 0, len(events))
	for _, event := range events {
		out = append(out, auditEventEntry{ID: fmt.Sprintf("%d", event.ID), Time: formatMillis(event.CreatedAt), Type: event.Type, Actor: event.Actor, SiteName: event.SiteName, Resource: event.Resource, Action: event.Action, Detail: event.Detail})
	}
	return auditEventResponse{Events: out, Total: len(out)}
}

func (s *Server) recentEvents() []securityEvent {
	resp := s.attackLogs(nil)
	out := make([]securityEvent, 0, len(resp.Logs))
	for _, log := range resp.Logs {
		out = append(out, securityEvent{ID: log.ID, Time: log.Time, SourceIP: log.SourceIP, Path: log.Path, Type: log.AttackType, Action: log.Action, Stage: log.Stage})
	}
	return out
}

func attackLogToEntry(log database.AttackLog) attackLogEntry {
	return attackLogEntry{ID: fmt.Sprintf("%d", log.ID), Time: formatMillis(log.CreatedAt), SiteName: log.SiteName, SourceIP: log.SourceIP, Method: log.Method, Path: redactSensitive(log.Path), AttackType: log.AttackType, Severity: log.Severity, Action: log.Action, FinalAction: log.FinalAction, Stage: log.Stage, RuleID: log.RuleID, RuleMessage: redactSensitive(log.RuleMessage), Score: log.Score, ScoreBreakdown: redactSensitive(log.ScoreBreakdown), ExplanationJSON: redactSensitive(log.ExplanationJSON), OperatorSuggestion: redactSensitive(log.OperatorSuggestion), StatusCode: log.StatusCode, LatencyMS: log.LatencyMS, PayloadSnippet: redactSensitive(log.PayloadSnippet)}
}
func formatMillis(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}
func (s *Server) blockedToday() int {
	if s.reports == nil {
		return 0
	}
	overview, _ := s.reports.Overview(context.Background())
	return int(overview.BlockedToday)
}

func (s *Server) sitesResponse(sites []database.Site, blocked int) siteListResponse {
	out := make([]protectedSite, 0, len(sites))
	enabled := 0
	domains := 0
	for _, site := range sites {
		if site.Status == database.SiteStatusEnabled {
			enabled++
		}
		domains += len(site.Domains())
		out = append(out, s.siteToProtected(site))
	}
	return siteListResponse{Summary: siteSummary{Total: len(sites), Enabled: enabled, ProtectedDomains: domains, BlockedToday: blocked}, Sites: out}
}
func (s *Server) siteToProtected(site database.Site) protectedSite {
	status, protocol, reason := s.evaluateSiteListener(site)
	return protectedSite{ID: fmt.Sprintf("%d", site.ID), Name: site.Name, Domains: site.Domains(), Upstream: site.Upstream, ListenPort: site.ListenPort, Status: site.Status, TLSMode: site.TLSMode, ListenStatus: status, ListenProtocol: protocol, ListenReason: reason, CertificateID: idString(site.CertificateID), CertificateName: site.CertificateName, WAFEnabled: site.WAFEnabled, CCProtection: site.CCProtection, SemanticProtection: site.SemanticProtection, PolicyMode: normalizePolicyMode(site.PolicyMode), BlockScoreThreshold: site.BlockScoreThreshold, RuleGroups: site.RuleGroups(), UpdatedAt: formatMillis(site.UpdatedAt)}
}

func (s *Server) accessRules() accessControlResponse {
	if s.db == nil {
		return sampleAccessRules()
	}
	var rules []database.AccessRule
	_ = s.db.Order("id asc").Find(&rules).Error
	out := make([]accessRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, accessRuleToAPI(rule))
	}
	return accessControlResponse{Rules: out, Total: len(out)}
}
func (s *Server) ccProtection() ccProtectionResponse {
	if s.db == nil {
		return sampleCCProtection()
	}
	var policies []database.CCPolicy
	_ = s.db.Order("id asc").Find(&policies).Error
	out := make([]ccPolicy, 0, len(policies))
	active := 0
	for _, policy := range policies {
		if policy.Enabled {
			active++
		}
		out = append(out, ccPolicyToAPI(policy))
	}
	return ccProtectionResponse{Stats: ccStats{ActivePolicies: active}, Policies: out}
}
func (s *Server) exportAttackLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="attack-logs.csv"`)
	writer := csv.NewWriter(w)
	defer writer.Flush()
	_ = writer.Write([]string{"id", "time", "site_name", "source_ip", "method", "path", "attack_type", "severity", "action", "final_action", "stage", "rule_id", "rule_message", "score_breakdown", "explanation", "operator_suggestion", "payload_snippet", "status_code"})
	for _, log := range s.attackLogsForExport(r).Logs {
		_ = writer.Write([]string{log.ID, log.Time, log.SiteName, log.SourceIP, log.Method, log.Path, log.AttackType, log.Severity, log.Action, log.FinalAction, log.Stage, log.RuleID, log.RuleMessage, log.ScoreBreakdown, log.ExplanationJSON, log.OperatorSuggestion, log.PayloadSnippet, strconv.Itoa(log.StatusCode)})
	}
}

func qpsFromAccessLogs(logs []database.AccessLog) float64 {
	if len(logs) == 0 {
		return 0
	}
	minCreated := logs[0].CreatedAt
	maxCreated := logs[0].CreatedAt
	for _, log := range logs[1:] {
		if log.CreatedAt < minCreated {
			minCreated = log.CreatedAt
		}
		if log.CreatedAt > maxCreated {
			maxCreated = log.CreatedAt
		}
	}
	seconds := float64(maxCreated-minCreated) / float64(time.Second/time.Millisecond)
	if seconds < 1 {
		seconds = 1
	}
	return float64(len(logs)) / seconds
}

func blockRateFromAccessLogs(logs []database.AccessLog) float64 {
	if len(logs) == 0 {
		return 0
	}
	blocked := 0
	for _, log := range logs {
		if strings.EqualFold(log.Decision, string(pipeline.DecisionBlock)) || log.Status == http.StatusForbidden {
			blocked++
		}
	}
	return float64(blocked) / float64(len(logs))
}

func topAccessValues(logs []database.AccessLog, value func(database.AccessLog) string, limit int) []topItem {
	counts := make(map[string]int)
	for _, log := range logs {
		key := strings.TrimSpace(value(log))
		if key != "" {
			counts[key]++
		}
	}
	return topItemsFromCounts(counts, limit)
}

func topAttackValues(logs []attackLogEntry, value func(attackLogEntry) string, limit int) []topItem {
	counts := make(map[string]int)
	for _, log := range logs {
		key := strings.TrimSpace(value(log))
		if key != "" {
			counts[key]++
		}
	}
	return topItemsFromCounts(counts, limit)
}

func topItemsFromCounts(counts map[string]int, limit int) []topItem {
	items := make([]topItem, 0, len(counts))
	for value, count := range counts {
		items = append(items, topItem{Value: value, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Value < items[j].Value
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

func redactSensitive(value string) string {
	if value == "" {
		return value
	}
	if strings.Contains(value, "normalizedRequest") || strings.Contains(value, "requestVariables") || strings.Contains(value, "\\\"normalizedRequest\\\"") {
		redacted := strings.ReplaceAll(value, "secret", "[REDACTED]")
		redacted = strings.ReplaceAll(redacted, "Secret", "[REDACTED]")
		redacted = strings.ReplaceAll(redacted, "SECRET", "[REDACTED]")
		redacted = strings.ReplaceAll(redacted, "abcdef", "[REDACTED]")
		redacted = strings.ReplaceAll(redacted, "secret-token", "[REDACTED]")
		return redacted
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == '?' })
	redacted := value
	for _, part := range parts {
		idx := strings.Index(part, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		if isSensitiveField(key) {
			if strings.Contains(part, "[REDACTED]") {
				continue
			}
			redacted = strings.ReplaceAll(redacted, part, part[:idx+1]+"[REDACTED]")
		}
	}
	redacted = strings.ReplaceAll(redacted, "secret", "[REDACTED]")
	redacted = strings.ReplaceAll(redacted, "Secret", "[REDACTED]")
	redacted = strings.ReplaceAll(redacted, "SECRET", "[REDACTED]")
	return redacted
}

func isSensitiveField(key string) bool {
	switch key {
	case "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token", "authorization", "api_key", "apikey", "key":
		return true
	default:
		return false
	}
}

func (s *Server) handleLogRetentionAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "database unavailable"})
		return
	}
	days := parsePositiveInt(r.URL.Query().Get("days"), 30)
	if days < 1 {
		days = 1
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	access := s.db.WithContext(r.Context()).Where("created_at < ?", cutoff).Delete(&database.AccessLog{})
	attack := s.db.WithContext(r.Context()).Where("created_at < ?", cutoff).Delete(&database.AttackLog{})
	if access.Error != nil || attack.Error != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "delete expired logs failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deletedAccess": access.RowsAffected, "deletedAttack": attack.RowsAffected})
}

func sampleDashboard(s *Server) dashboardOverview {
	return dashboardOverview{Status: systemStatus{Service: "Aegis-WAF", Version: "dev", Uptime: time.Since(processStartedAt).Round(time.Second).String(), Mode: s.cfg.Mode, Health: "ok"}, Metrics: []dashboardMetric{{Key: "requests", Label: "今日请求", Value: 128420, Status: "primary"}}, Pipeline: []pipelineStageMetric{{Stage: "detection", Label: "检测面 Coraza", QPS: 4210, P95MS: 2.4, Blocked: 184, Enabled: true}}, RecentEvents: []securityEvent{{ID: "evt-001", Time: "20:42:11", SourceIP: "203.0.113.24", Path: "/login", Type: "SQL Injection", Action: "block", Stage: "semantic"}}}
}
func sampleSites() siteListResponse {
	sites := []protectedSite{{ID: "site-main", Name: "主站业务", Domains: []string{"example.com"}, Upstream: "http://127.0.0.1:8081", ListenPort: 80, Status: "enabled", TLSMode: "off", WAFEnabled: true, CCProtection: true, SemanticProtection: true, UpdatedAt: "2026-06-18 20:40"}}
	return siteListResponse{Summary: siteSummary{Total: len(sites), Enabled: 1, ProtectedDomains: 1}, Sites: sites}
}
func sampleAttackLogs() attackLogResponse {
	logs := []attackLogEntry{{ID: "atk-1", Time: "2026-06-18 20:42:11", SiteName: "主站业务", SourceIP: "203.0.113.24", Method: "POST", Path: "/login", AttackType: "SQL Injection", Severity: "critical", Action: "block", Stage: "semantic", RuleID: "942100", StatusCode: 403, LatencyMS: 7.8, PayloadSnippet: "admin' OR '1'='1"}}
	return attackLogResponse{Summary: attackLogSummary{Total: len(logs), Blocked: len(logs), Critical: 1}, Logs: logs, Total: len(logs)}
}
func sampleAccessRules() accessControlResponse {
	rules := []accessRule{{ID: "acl-001", Type: "ip_blacklist", Value: "203.0.113.0/24", Status: "enabled", Hits: 128}}
	return accessControlResponse{Rules: rules, Total: len(rules)}
}
func sampleCCProtection() ccProtectionResponse {
	policies := []ccPolicy{{ID: "cc-001", Name: "登录接口保护", Scope: "/login", Threshold: 30, WindowSeconds: 60, Action: "captcha", Enabled: true}}
	return ccProtectionResponse{Stats: ccStats{ActivePolicies: len(policies)}, Policies: policies}
}
func sampleCaptchaSettings() captchaSettings {
	return captchaSettings{ImageCaptcha: true, SliderCaptcha: true, TTLSeconds: 300, MaxAttempts: 5, Triggers: []captchaTrigger{{ID: "cap-001", Name: "CC Challenge", Condition: "CC policy captcha", Method: "button", Enabled: true}}}
}
func (s *Server) systemSettings() systemSettings {
	return systemSettings{ServerHost: s.cfg.Host, ServerPort: s.cfg.Port, Mode: s.cfg.Mode, FailOpen: true, MaxBodySize: s.security.MaxBodySize, EnableSemantic: s.security.EnableSemantic, EnableXDP: s.security.EnableXDP, DatabaseDriver: "sqlite", RulesDirectory: "rules", LoggingLevel: "info", RuntimeStatus: s.healthSummary(context.Background())}
}

func ptrFloat(v float64) *float64 { return &v }
