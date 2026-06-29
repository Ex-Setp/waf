package database

import "encoding/json"

const (
	SiteStatusEnabled  = "enabled"
	SiteStatusDisabled = "disabled"

	SemanticFingerprintStatusObserving = "observing"
	SemanticFingerprintStatusActive    = "active"
	SemanticFingerprintStatusRollback  = "rollback"

	AccessRuleIPBlacklist     = "ip_blacklist"
	AccessRuleIPWhitelist     = "ip_whitelist"
	AccessRuleCIDRWhitelist   = "cidr_whitelist"
	AccessRuleURLWhitelist    = "url_whitelist"
	AccessRuleParamWhitelist  = "param_whitelist"
	AccessRuleHeaderWhitelist = "header_whitelist"
	AccessRuleCookieWhitelist = "cookie_whitelist"
	AccessRuleRuleDisable     = "rule_disable"
	AccessRuleUABlacklist     = "ua_blacklist"
	AccessRuleMethodBlock     = "method_block"

	CCActionObserve   = "observe"
	CCActionBlock     = "block"
	CCActionCaptcha   = "captcha"
	CCActionTempBlock = "temp-block"
	CCActionLongBlock = "long-block"

	PolicyModeObserve  = "observe"
	PolicyModeLoose    = "loose"
	PolicyModeStandard = "standard"
	PolicyModeStrict   = "strict"
	PolicyModeCustom   = "custom"
)

type Site struct {
	ID                  uint   `gorm:"primaryKey" json:"id"`
	Name                string `gorm:"size:128;not null" json:"name"`
	DomainsJSON         string `gorm:"type:text;not null" json:"-"`
	Upstream            string `gorm:"size:512;not null" json:"upstream"`
	ListenPort          int    `gorm:"not null;default:80" json:"listenPort"`
	Status              string `gorm:"size:32;not null;default:enabled;index" json:"status"`
	TLSMode             string `gorm:"size:32;not null;default:off" json:"tlsMode"`
	CertificateID       uint   `gorm:"index;default:0" json:"certificateId"`
	CertificateName     string `gorm:"size:128" json:"certificateName"`
	WAFEnabled          bool   `gorm:"not null" json:"wafEnabled"`
	CCProtection        bool   `gorm:"not null" json:"ccProtection"`
	SemanticProtection  bool   `gorm:"not null" json:"semanticProtection"`
	PolicyMode          string `gorm:"size:32;not null;default:standard;index" json:"policyMode"`
	BlockScoreThreshold int    `gorm:"not null;default:5" json:"blockScoreThreshold"`
	RuleGroupsJSON      string `gorm:"type:text" json:"-"`
	CreatedAt           int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt           int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

func (s Site) Domains() []string {
	var domains []string
	if err := json.Unmarshal([]byte(s.DomainsJSON), &domains); err != nil {
		return nil
	}
	return domains
}

func (s *Site) SetDomains(domains []string) error {
	data, err := json.Marshal(domains)
	if err != nil {
		return err
	}
	s.DomainsJSON = string(data)
	return nil
}

func (s Site) RuleGroups() []string {
	var groups []string
	if err := json.Unmarshal([]byte(s.RuleGroupsJSON), &groups); err != nil {
		return nil
	}
	return groups
}

func (s *Site) SetRuleGroups(groups []string) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	s.RuleGroupsJSON = string(data)
	return nil
}

type Certificate struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"size:128;not null" json:"name"`
	DomainsJSON string `gorm:"type:text;not null" json:"-"`
	CertPEM     string `gorm:"type:text;not null" json:"-"`
	KeyPEM      string `gorm:"type:text" json:"-"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

func (c Certificate) Domains() []string {
	var domains []string
	if err := json.Unmarshal([]byte(c.DomainsJSON), &domains); err != nil {
		return nil
	}
	return domains
}
func (c *Certificate) SetDomains(domains []string) error {
	data, err := json.Marshal(domains)
	if err != nil {
		return err
	}
	c.DomainsJSON = string(data)
	return nil
}

type SemanticFingerprint struct {
	ID                uint    `gorm:"primaryKey" json:"id"`
	Hash              string  `gorm:"size:128;uniqueIndex;not null" json:"hash"`
	Language          string  `gorm:"size:32;index" json:"language"`
	Skeleton          string  `gorm:"type:text" json:"skeleton"`
	NodeTypesJSON     string  `gorm:"type:text" json:"-"`
	SamplePayload     string  `gorm:"type:text" json:"samplePayload"`
	Action            string  `gorm:"size:32;index;not null;default:log" json:"action"`
	Status            string  `gorm:"size:32;index;not null;default:observing" json:"status"`
	RuleID            int     `gorm:"index;default:0" json:"ruleId"`
	GeneratedRule     string  `gorm:"type:text" json:"generatedRule"`
	Hits              int64   `gorm:"not null;default:0" json:"hits"`
	FalsePositiveRate float64 `gorm:"not null;default:0" json:"falsePositiveRate"`
	Source            string  `gorm:"size:128;index" json:"source"`
	XDPSyncStatus     string  `gorm:"size:255" json:"xdpSyncStatus"`
	SiteID            uint    `gorm:"index;default:0" json:"siteId"`
	SiteName          string  `gorm:"size:128" json:"siteName"`
	LastSeenAt        int64   `gorm:"index" json:"lastSeenAt"`
	CreatedAt         int64   `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt         int64   `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

type AccessLog struct {
	ID        uint    `gorm:"primaryKey" json:"id"`
	RequestID string  `gorm:"size:64;index" json:"requestId"`
	SiteID    uint    `gorm:"index" json:"siteId"`
	SiteName  string  `gorm:"size:128" json:"siteName"`
	Host      string  `gorm:"size:255;index" json:"host"`
	SourceIP  string  `gorm:"size:64;index" json:"sourceIp"`
	Method    string  `gorm:"size:16;not null" json:"method"`
	Path      string  `gorm:"size:2048;not null" json:"path"`
	Query     string  `gorm:"type:text" json:"query"`
	UserAgent string  `gorm:"size:512" json:"userAgent"`
	Status    int     `gorm:"index;not null" json:"status"`
	Decision  string  `gorm:"size:32;index" json:"decision"`
	Upstream  string  `gorm:"size:512" json:"upstream"`
	LatencyMS float64 `gorm:"not null;default:0" json:"latencyMs"`
	BytesIn   int64   `gorm:"not null;default:0" json:"bytesIn"`
	BytesOut  int64   `gorm:"not null;default:0" json:"bytesOut"`
	CreatedAt int64   `gorm:"autoCreateTime:milli;index" json:"createdAt"`
}

type AttackLog struct {
	ID                 uint    `gorm:"primaryKey" json:"id"`
	RequestID          string  `gorm:"size:64;index" json:"requestId"`
	SiteID             uint    `gorm:"index" json:"siteId"`
	SiteName           string  `gorm:"size:128" json:"siteName"`
	SourceIP           string  `gorm:"size:64;index" json:"sourceIp"`
	Method             string  `gorm:"size:16" json:"method"`
	Path               string  `gorm:"size:2048" json:"path"`
	AttackType         string  `gorm:"size:128;index" json:"attackType"`
	Severity           string  `gorm:"size:32;index" json:"severity"`
	Action             string  `gorm:"size:32;index" json:"action"`
	FinalAction        string  `gorm:"size:32;index" json:"finalAction"`
	Stage              string  `gorm:"size:64;index" json:"stage"`
	RuleID             string  `gorm:"size:128;index" json:"ruleId"`
	RuleMessage        string  `gorm:"size:512" json:"ruleMessage"`
	Score              int     `gorm:"index;default:0" json:"score"`
	ScoreBreakdown     string  `gorm:"type:text" json:"scoreBreakdown"`
	ExplanationJSON    string  `gorm:"type:text" json:"explanationJson"`
	OperatorSuggestion string  `gorm:"type:text" json:"operatorSuggestion"`
	StatusCode         int     `gorm:"index" json:"statusCode"`
	LatencyMS          float64 `gorm:"not null;default:0" json:"latencyMs"`
	PayloadSnippet     string  `gorm:"type:text" json:"payloadSnippet"`
	CreatedAt          int64   `gorm:"autoCreateTime:milli;index" json:"createdAt"`
}

type AccessRule struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	SiteID      uint   `gorm:"index;default:0" json:"siteId"`
	Type        string `gorm:"size:32;index" json:"type"`
	Value       string `gorm:"size:512;not null" json:"value"`
	Scope       string `gorm:"size:32;index;not null;default:site" json:"scope"`
	RuleID      string `gorm:"size:64;index" json:"ruleId"`
	Variable    string `gorm:"size:128;index" json:"variable"`
	ExpiresAt   int64  `gorm:"index;default:0" json:"expiresAt"`
	CreatedFrom string `gorm:"size:128" json:"createdFrom"`
	Description string `gorm:"size:512" json:"description"`
	Enabled     bool   `gorm:"not null;default:true" json:"enabled"`
	Hits        int64  `gorm:"not null;default:0" json:"hits"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

type CCPolicy struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	SiteID        uint   `gorm:"index;default:0" json:"siteId"`
	Name          string `gorm:"size:128;not null" json:"name"`
	Scope         string `gorm:"size:512;not null" json:"scope"`
	Threshold     int    `gorm:"not null" json:"threshold"`
	WindowSeconds int    `gorm:"not null" json:"windowSeconds"`
	Action        string `gorm:"size:32;not null" json:"action"`
	Priority      int    `gorm:"not null;default:100;index" json:"priority"`
	Enabled       bool   `gorm:"not null;default:true" json:"enabled"`
	Hits          int64  `gorm:"not null;default:0" json:"hits"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

type ProtectionRule struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	RuleID      int    `gorm:"uniqueIndex;not null" json:"ruleId"`
	Name        string `gorm:"size:256;not null" json:"name"`
	Description string `gorm:"size:512" json:"description"`
	Category    string `gorm:"size:128;index" json:"category"`
	Variable    string `gorm:"size:128;not null" json:"variable"`
	Operator    string `gorm:"size:32;not null" json:"operator"`
	Pattern     string `gorm:"type:text;not null" json:"pattern"`
	Action      string `gorm:"size:32;not null" json:"action"`
	Severity    string `gorm:"size:32;not null" json:"severity"`
	Score       int    `gorm:"not null;default:1" json:"score"`
	Source      string `gorm:"size:32;index;not null;default:custom" json:"source"`
	Enabled     bool   `gorm:"not null;default:true" json:"enabled"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

type SiteProtectionPolicy struct {
	ID                    uint   `gorm:"primaryKey" json:"id"`
	SiteID                uint   `gorm:"uniqueIndex;not null" json:"siteId"`
	SiteName              string `gorm:"size:128" json:"siteName"`
	Mode                  string `gorm:"size:32;not null;default:standard;index" json:"mode"`
	EnabledRuleGroupsJSON string `gorm:"type:text" json:"-"`
	CRSParanoiaLevel      int    `gorm:"not null;default:1" json:"crsParanoiaLevel"`
	InboundThreshold      int    `gorm:"not null;default:7" json:"inboundThreshold"`
	OutboundThreshold     int    `gorm:"not null;default:7" json:"outboundThreshold"`
	DefaultAction         string `gorm:"size:32;not null;default:block" json:"defaultAction"`
	RuntimeVersion        string `gorm:"size:64" json:"runtimeVersion"`
	PublishedAt           int64  `gorm:"index" json:"publishedAt"`
	CreatedAt             int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt             int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}

func (p SiteProtectionPolicy) EnabledRuleGroups() []string {
	var groups []string
	if err := json.Unmarshal([]byte(p.EnabledRuleGroupsJSON), &groups); err != nil {
		return nil
	}
	return groups
}

func (p *SiteProtectionPolicy) SetEnabledRuleGroups(groups []string) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	p.EnabledRuleGroupsJSON = string(data)
	return nil
}

type PolicyVersion struct {
	ID                    uint   `gorm:"primaryKey" json:"id"`
	SiteID                uint   `gorm:"index;not null" json:"siteId"`
	Version               string `gorm:"size:64;index;not null" json:"version"`
	Mode                  string `gorm:"size:32;not null" json:"mode"`
	EnabledRuleGroupsJSON string `gorm:"type:text" json:"-"`
	CRSParanoiaLevel      int    `gorm:"not null;default:1" json:"crsParanoiaLevel"`
	InboundThreshold      int    `gorm:"not null;default:7" json:"inboundThreshold"`
	OutboundThreshold     int    `gorm:"not null;default:7" json:"outboundThreshold"`
	DefaultAction         string `gorm:"size:32;not null;default:block" json:"defaultAction"`
	CreatedAt             int64  `gorm:"autoCreateTime:milli;index" json:"createdAt"`
}

func (v PolicyVersion) EnabledRuleGroups() []string {
	var groups []string
	if err := json.Unmarshal([]byte(v.EnabledRuleGroupsJSON), &groups); err != nil {
		return nil
	}
	return groups
}

func (v *PolicyVersion) SetEnabledRuleGroups(groups []string) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	v.EnabledRuleGroupsJSON = string(data)
	return nil
}

type PolicyAudit struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	SiteID    uint   `gorm:"index;not null" json:"siteId"`
	SiteName  string `gorm:"size:128" json:"siteName"`
	Version   string `gorm:"size:64;index" json:"version"`
	Action    string `gorm:"size:64;index;not null" json:"action"`
	Detail    string `gorm:"type:text" json:"detail"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;index" json:"createdAt"`
}

type AuditEvent struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Type      string `gorm:"size:64;index;not null" json:"type"`
	Actor     string `gorm:"size:128" json:"actor"`
	SiteID    uint   `gorm:"index;default:0" json:"siteId"`
	SiteName  string `gorm:"size:128" json:"siteName"`
	Resource  string `gorm:"size:128" json:"resource"`
	Action    string `gorm:"size:64" json:"action"`
	Detail    string `gorm:"type:text" json:"detail"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;index" json:"createdAt"`
}
