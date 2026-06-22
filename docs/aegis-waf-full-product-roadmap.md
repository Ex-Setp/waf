# Aegis-WAF 完整产品化后续开发文档

> **For Hermes:** 后续执行时使用 `software-development/staged-project-development`，严格按本文任务编号推进；一次只做一个任务，完成后测试、更新状态、再进入下一项。

**目标：** 基于现有四层架构骨架，把 Aegis-WAF 补成可真实接入站点、可转发流量、可拦截攻击、可管理规则、可统计报表、可对标雷池个人版核心功能的完整 WAF 产品。

**架构：** 保留现有四层防护流水线：数据面 XDP/eBPF、检测面规则引擎、语义分析、特征闭环。新增“站点接入层”和“控制台管理层”，让前端新增站点能够真正影响后端请求路由、防护策略、日志和统计。

**技术栈：** Go + net/http + httputil.ReverseProxy + GORM + SQLite/PostgreSQL + Viper + Zap + Vue3 + TypeScript + Element Plus + ECharts。后期可替换检测面为 Coraza/v3 + OWASP CRS v4，XDP 在 Linux 环境专项落地。

---

## 0. 当前真实状态校准

当前项目不是完整 WAF 产品，只是骨架和样例控制台。

### 已有能力

- HTTP 服务入口：`internal/httpserver/server.go`
- 四层流水线编排：`internal/pipeline/pipeline.go`
- 规则加载、热重载、启停用内存方法：`internal/detection/manager.go`
- 规则文件目录：`rules/`
- SQL / JS AST 与语义模块骨架：`internal/semantic/`
- 特征闭环骨架：`internal/featureloop/`
- 数据面 XDP/eBPF 适配骨架：`internal/dataplane/`
- 前端控制台页面：`web/src/views/`
- 样例 API 清单：`docs/backend-api-list.md`

### 关键缺口

- 站点新增、编辑、删除 API 缺失。
- 站点数据模型过简，只有单个 `Domain`，没有 upstream、端口、TLS、防护开关。
- HTTP 请求没有按 Host 匹配站点。
- 放行后没有反向代理到源站，只返回 JSON 决策结果。
- 访问日志、攻击日志没有在真实请求中写入数据库。
- 统计报表没有真实聚合接口。
- 前端多数页面依赖 Mock / fallback。
- 规则管理没有 API 持久化，启停用只在内存里。
- CC、人机验证、访问控制、证书管理都只是样例页面或未实现。

### 产品闭环定义

一个站点能算“真正被 WAF 防护”，必须满足：

1. 控制台新增站点成功写入数据库。
2. 请求带 `Host` 命中该站点域名。
3. 请求进入防护流水线。
4. 命中 deny 规则时返回 403，并写攻击日志。
5. 未命中规则时转发到该站点 upstream，并返回源站响应。
6. 每次请求写访问日志。
7. 控制台统计和日志能看到真实数据。

---

## 1. 目标产品功能矩阵

### 1.1 雷池核心能力对标

| 模块 | 最小可用目标 | 完整目标 |
| --- | --- | --- |
| 站点管理 | 新增/编辑/删除站点，按 Host 转发 | 多域名、泛域名、端口、TLS、负载均衡 upstream |
| 反向代理 | HTTP upstream 转发 | HTTPS upstream、超时、重试、健康检查 |
| WAF 规则 | 全局规则拦截 | 站点级规则组、白名单、规则启停、CRS 导入 |
| 访问控制 | IP 黑白名单、URL 白名单 | 地区封锁、UA 限制、Bot 策略 |
| CC 防护 | IP+URI 滑动窗口限速 | 站点级策略、验证码联动、Redis 集群计数 |
| 人机验证 | 简单挑战页 / token | 图形验证码、滑块、触发策略、白名单绕过 |
| 日志审计 | 访问日志、攻击日志 | 搜索、筛选、导出、保留策略、脱敏 |
| 统计报表 | 8 卡片 + 趋势 | 地图、Top 国家、PV/UV/IP、错误率、实时 QPS |
| 系统管理 | 配置读取、健康检查 | 备份恢复、版本检查、证书管理、运行状态 |
| 高性能 | Go 反代 + 规则检测 | WorkerPool、对象池、XDP 快速拦截、Prometheus |
| 0day | AST/语义模块可调用 | 语义评分、指纹生成、灰度、自动回滚 |

### 1.2 四层架构落地边界

```text
入口监听 HTTP/HTTPS
  ↓
站点接入层：Host/SNI → Site → upstream/policy
  ↓
第一层 数据面：XDP/eBPF 快速 IP/指纹拦截（Linux 可选）
  ↓
第二层 检测面：规则引擎 / CRS / 自定义规则 / ACL / CC
  ↓
第三层 语义分析：SQL/JS AST、污点追踪、熵值、0day 评分
  ↓
第四层 特征闭环：攻击聚类、生成指纹、灰度验证、规则下发
  ↓
放行：ReverseProxy 转发 upstream
拦截：返回拦截页 / JSON，并写攻击日志
  ↓
异步日志/指标：访问日志、攻击日志、统计聚合
```

---

## 2. 后端目标目录结构

新增或重构后建议结构：

```text
internal/
  accesscontrol/       # IP/URL/地区/UA 访问控制
  captcha/             # 人机验证 challenge/token
  cc/                  # CC 滑动窗口限速
  certs/               # TLS 证书管理
  console/             # 控制台 API handlers，可从 httpserver 拆出
  database/            # models/repositories/migrations
  gateway/             # 站点匹配、反向代理、请求上下文
  metrics/             # QPS、PV、UV、错误率、Prometheus
  proxy/               # reverse proxy、upstream、health check
  reports/             # 报表聚合查询
  rules/               # 规则 CRUD、规则组、CRS 导入
  auditlog/            # 访问日志、攻击日志、异步写入
```

短期不必一次性重构目录；优先在现有 `httpserver`、`database` 中补功能，稳定后再拆包。

---

## 3. 数据库模型设计

### 3.1 Site

替换现有 `Site` 简化模型。

```go
type Site struct {
    ID                 uint   `gorm:"primaryKey" json:"id"`
    Name               string `gorm:"size:128;not null" json:"name"`
    DomainsJSON        string `gorm:"type:text;not null" json:"-"`
    Upstream           string `gorm:"size:512;not null" json:"upstream"`
    ListenPort         int    `gorm:"not null;default:80" json:"listenPort"`
    Status             string `gorm:"size:32;not null;default:enabled;index" json:"status"`
    TLSMode            string `gorm:"size:32;not null;default:off" json:"tlsMode"`
    WAFEnabled         bool   `gorm:"not null;default:true" json:"wafEnabled"`
    CCProtection       bool   `gorm:"not null;default:false" json:"ccProtection"`
    SemanticProtection bool   `gorm:"not null;default:true" json:"semanticProtection"`
    CreatedAt          int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
    UpdatedAt          int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}
```

### 3.2 SiteDomain

建议单独建表，避免 JSON 查询困难。

```go
type SiteDomain struct {
    ID        uint   `gorm:"primaryKey"`
    SiteID    uint   `gorm:"index;not null"`
    Domain    string `gorm:"size:255;not null;uniqueIndex"`
    IsWildcard bool  `gorm:"not null;default:false"`
    CreatedAt int64  `gorm:"autoCreateTime:milli"`
}
```

### 3.3 AccessLog

```go
type AccessLog struct {
    ID           uint    `gorm:"primaryKey"`
    RequestID    string  `gorm:"size:64;index"`
    SiteID       uint    `gorm:"index"`
    SiteName     string  `gorm:"size:128"`
    Host         string  `gorm:"size:255;index"`
    SourceIP     string  `gorm:"size:64;index"`
    Country      string  `gorm:"size:64;index"`
    Region       string  `gorm:"size:64;index"`
    Method       string  `gorm:"size:16;not null"`
    Path         string  `gorm:"size:2048;not null"`
    Query        string  `gorm:"type:text"`
    UserAgent    string  `gorm:"size:512"`
    Referer      string  `gorm:"size:512"`
    Status       int     `gorm:"index;not null"`
    Decision     string  `gorm:"size:32;index"`
    Upstream     string  `gorm:"size:512"`
    LatencyMS    float64 `gorm:"not null;default:0"`
    BytesIn      int64   `gorm:"not null;default:0"`
    BytesOut     int64   `gorm:"not null;default:0"`
    CreatedAt    int64   `gorm:"autoCreateTime:milli;index"`
}
```

### 3.4 AttackLog

```go
type AttackLog struct {
    ID             uint    `gorm:"primaryKey"`
    RequestID      string  `gorm:"size:64;index"`
    SiteID         uint    `gorm:"index"`
    SiteName       string  `gorm:"size:128"`
    SourceIP       string  `gorm:"size:64;index"`
    Method         string  `gorm:"size:16"`
    Path           string  `gorm:"size:2048"`
    AttackType     string  `gorm:"size:128;index"`
    Severity       string  `gorm:"size:32;index"`
    Action         string  `gorm:"size:32;index"`
    Stage          string  `gorm:"size:64;index"`
    RuleID         string  `gorm:"size:128;index"`
    RuleMessage    string  `gorm:"size:512"`
    StatusCode     int     `gorm:"index"`
    LatencyMS      float64 `gorm:"not null;default:0"`
    PayloadSnippet string  `gorm:"type:text"`
    CreatedAt      int64   `gorm:"autoCreateTime:milli;index"`
}
```

### 3.5 RuleEntity

```go
type RuleEntity struct {
    ID          uint   `gorm:"primaryKey"`
    RuleID      int    `gorm:"uniqueIndex;not null"`
    Name        string `gorm:"size:255;not null"`
    Content     string `gorm:"type:text;not null"`
    Category    string `gorm:"size:64;index"`
    Severity    string `gorm:"size:32;index"`
    Action      string `gorm:"size:32;not null"`
    Enabled     bool   `gorm:"not null;default:true"`
    Source      string `gorm:"size:64;index"`
    SiteID      uint   `gorm:"index;default:0"` // 0 means global
    CreatedAt   int64  `gorm:"autoCreateTime:milli"`
    UpdatedAt   int64  `gorm:"autoUpdateTime:milli"`
}
```

### 3.6 AccessRule

```go
type AccessRule struct {
    ID          uint   `gorm:"primaryKey"`
    SiteID      uint   `gorm:"index;default:0"`
    Type        string `gorm:"size:32;index"` // ip_blacklist/ip_whitelist/url_whitelist/ua_block/region_block
    Value       string `gorm:"size:512;not null"`
    Description string `gorm:"size:512"`
    Enabled     bool   `gorm:"not null;default:true"`
    Hits        int64  `gorm:"not null;default:0"`
    CreatedAt   int64  `gorm:"autoCreateTime:milli"`
    UpdatedAt   int64  `gorm:"autoUpdateTime:milli"`
}
```

### 3.7 CCPolicy

```go
type CCPolicy struct {
    ID            uint   `gorm:"primaryKey"`
    SiteID        uint   `gorm:"index;default:0"`
    Name          string `gorm:"size:128;not null"`
    Scope         string `gorm:"size:512;not null"`
    Threshold     int    `gorm:"not null"`
    WindowSeconds int    `gorm:"not null"`
    Action        string `gorm:"size:32;not null"` // block/captcha/log
    Enabled       bool   `gorm:"not null;default:true"`
    CreatedAt     int64  `gorm:"autoCreateTime:milli"`
    UpdatedAt     int64  `gorm:"autoUpdateTime:milli"`
}
```

---

## 4. API 目标清单

### 4.1 站点管理

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/sites` | 站点列表 |
| POST | `/api/sites` | 新增站点 |
| GET | `/api/sites/{id}` | 站点详情 |
| PUT | `/api/sites/{id}` | 更新站点 |
| PATCH | `/api/sites/{id}/status` | 启用/禁用站点 |
| DELETE | `/api/sites/{id}` | 删除站点 |
| POST | `/api/sites/{id}/test-upstream` | 测试源站连通性 |

### 4.2 规则管理

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/rules` | 规则列表 |
| POST | `/api/rules` | 新增自定义规则 |
| PUT | `/api/rules/{id}` | 更新规则 |
| PATCH | `/api/rules/{id}/status` | 启用/禁用规则 |
| DELETE | `/api/rules/{id}` | 删除规则 |
| POST | `/api/rules/reload` | 规则热重载 |
| POST | `/api/rules/import-crs` | 导入 CRS 规则包 |

### 4.3 访问控制

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/access-rules` | 访问控制列表 |
| POST | `/api/access-rules` | 新增访问控制规则 |
| PUT | `/api/access-rules/{id}` | 更新规则 |
| PATCH | `/api/access-rules/{id}/status` | 启用/禁用 |
| DELETE | `/api/access-rules/{id}` | 删除 |

### 4.4 CC 防护

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/cc-protection` | CC 策略与统计 |
| POST | `/api/cc-protection/policies` | 新增策略 |
| PUT | `/api/cc-protection/policies/{id}` | 更新策略 |
| DELETE | `/api/cc-protection/policies/{id}` | 删除策略 |

### 4.5 日志审计

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/access-logs` | 访问日志列表 |
| GET | `/api/access-logs/export` | 访问日志导出 |
| GET | `/api/attack-logs` | 攻击日志列表 |
| GET | `/api/attack-logs/export` | 攻击日志导出 |

### 4.6 统计报表

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/dashboard/overview` | 首页概览 |
| GET | `/api/reports/overview?range=24h|7d|30d` | 统计报表完整数据 |
| GET | `/api/reports/geo?range=24h&scope=world|china` | 地理热力数据 |
| GET | `/api/reports/trend?range=24h|7d|30d` | 趋势数据 |

---

## 5. 实施路线总览

必须先完成 P0-P2，项目才算“能防护真实站点”。P3-P6 是雷池级体验和高级能力。

| 阶段 | 目标 | 验收 |
| --- | --- | --- |
| P0 | 清理状态、测试基线、API 文档同步 | `go test ./...`、`npm run build` 通过 |
| P1 | 站点 CRUD + 数据库持久化 | 前端新增站点成功，数据库可见 |
| P2 | Host 匹配 + 反向代理 + 防护闭环 | 新增站点可转发源站，攻击请求 403 |
| P3 | 访问/攻击日志 + 统计报表 | 8 张统计卡片来自真实日志 |
| P4 | 规则/ACL/CC 控制台真实化 | 页面 CRUD 生效，策略影响请求 |
| P5 | TLS/证书/验证码/运维能力 | HTTPS 站点可接入，人机验证可触发 |
| P6 | 高性能/XDP/语义闭环强化 | Linux 压测达标，语义指纹可下刷 |

---

# P0：状态校准与工程基线

## T100：更新 README 当前状态

**目标：** 修正 README 中“已完成”的夸大描述，明确当前是骨架，防止后续误判。

**文件：**
- 修改：`README.md`

**步骤：**
1. 把“当前状态”改为“已完成骨架 / 未完成产品闭环”。
2. 列出真实已实现能力。
3. 列出 P1-P6 后续路线。
4. 运行：`go test ./...`
5. 验收：README 与真实代码一致。

## T101：建立后续任务状态文件

**目标：** 创建可维护的任务状态清单。

**文件：**
- 创建：`docs/full-product-progress.md`

**内容要求：**
- P0-P6 阶段列表。
- 当前任务指针。
- 每项状态：pending / in_progress / done / blocked。
- 每次完成任务后更新。

## T102：补 API 清单缺口标记

**目标：** 在现有 API 文档中明确哪些接口是 Mock，哪些是待实现。

**文件：**
- 修改：`docs/backend-api-list.md`

**验收：**
- 每个接口都有状态：real / mock / planned。

---

# P1：站点管理真实化

## T110：扩展数据库 Site 模型

**目标：** 支持多域名、upstream、端口、TLS、防护开关。

**文件：**
- 修改：`internal/database/models.go`
- 修改：`internal/database/database.go`
- 修改：`internal/database/database_test.go`

**实现要求：**
- 新增 `SiteDomain`。
- 扩展 `Site` 字段。
- AutoMigrate 包含新表。
- 保留兼容性：测试使用内存 SQLite。

**验收：**
- `go test ./internal/database -v` 通过。

## T111：新增站点 Repository

**目标：** 封装站点 CRUD，避免 handler 直接写 GORM。

**文件：**
- 创建：`internal/database/site_repository.go`
- 创建：`internal/database/site_repository_test.go`

**接口：**

```go
type SiteRepository struct { db *gorm.DB }
func NewSiteRepository(db *gorm.DB) *SiteRepository
func (r *SiteRepository) List(ctx context.Context) ([]SiteWithDomains, error)
func (r *SiteRepository) Get(ctx context.Context, id uint) (SiteWithDomains, error)
func (r *SiteRepository) Create(ctx context.Context, input SiteInput) (SiteWithDomains, error)
func (r *SiteRepository) Update(ctx context.Context, id uint, input SiteInput) (SiteWithDomains, error)
func (r *SiteRepository) SetStatus(ctx context.Context, id uint, status string) error
func (r *SiteRepository) Delete(ctx context.Context, id uint) error
func (r *SiteRepository) FindByHost(ctx context.Context, host string) (SiteWithDomains, error)
```

**验收：**
- 创建站点后能按域名查到。
- 泛域名 `*.example.com` 能匹配 `api.example.com`。
- 删除站点同步删除 domains。

## T112：HTTP Server 注入数据库依赖

**目标：** 让控制台 API 和 WAF 请求处理能访问站点数据。

**文件：**
- 修改：`internal/httpserver/server.go`
- 修改：`cmd/aegis-waf/main.go`
- 修改：相关测试构造函数

**设计：**
- 不要直接把 GORM 暴露给所有 handler。
- 给 `httpserver.Server` 增加 repositories 或 service 层。

**建议：**

```go
type Dependencies struct {
    Sites *database.SiteRepository
    Logs  *database.LogRepository
}
func New(cfg config.ServerConfig, security config.SecurityConfig, processor Processor, deps Dependencies) *Server
```

**验收：**
- 原有测试全部改造并通过。

## T113：实现站点 CRUD API

**目标：** 前端新增/编辑/启停/删除站点真实可用。

**文件：**
- 修改：`internal/httpserver/console_api.go`
- 创建：`internal/httpserver/sites_api_test.go`

**接口：**
- `GET /api/sites`
- `POST /api/sites`
- `GET /api/sites/{id}`
- `PUT /api/sites/{id}`
- `PATCH /api/sites/{id}/status`
- `DELETE /api/sites/{id}`

**请求示例：**

```json
{
  "name": "主站业务",
  "domains": ["example.com", "www.example.com"],
  "upstream": "http://127.0.0.1:18080",
  "listenPort": 8080,
  "tlsMode": "off",
  "wafEnabled": true,
  "ccProtection": true,
  "semanticProtection": true
}
```

**验收：**
- `POST /api/sites` 返回 201。
- `GET /api/sites` 返回刚创建的站点。
- 重复域名返回 409。
- 非法 upstream 返回 400。

## T114：前端站点页面接真实 API

**目标：** 移除保存失败提示，新增站点后表格刷新显示真实数据。

**文件：**
- 修改：`web/src/api/sites.ts`
- 修改：`web/src/stores/sites.ts`
- 修改：`web/src/views/SitesView.vue`

**验收：**
- `npm run build` 通过。
- 新增、编辑、启停、删除按钮与后端 API 对齐。

---

# P2：真实站点防护闭环

## T120：实现 Host 到 Site 匹配

**目标：** 每个请求根据 Host 找到站点。

**文件：**
- 创建：`internal/gateway/site_matcher.go`
- 创建：`internal/gateway/site_matcher_test.go`
- 修改：`internal/httpserver/server.go`

**规则：**
- 精确域名优先。
- 泛域名次之。
- 禁用站点不匹配。
- Host 带端口时剥离端口。

**验收：**
- `example.com:8080` 匹配 `example.com`。
- `api.example.com` 匹配 `*.example.com`。
- 未配置站点返回 404 或默认站点策略。

## T121：扩展 Pipeline Request 上下文

**目标：** 流水线知道当前站点和防护开关。

**文件：**
- 修改：`internal/pipeline/pipeline.go`
- 修改：相关测试

**新增字段：**

```go
type SiteContext struct {
    ID uint
    Name string
    Domains []string
    Upstream string
    WAFEnabled bool
    CCProtection bool
    SemanticProtection bool
}
```

**验收：**
- `WAFEnabled=false` 时跳过规则检测。
- `SemanticProtection=false` 时跳过语义检测。

## T122：实现 ReverseProxy 放行转发

**目标：** 未被拦截的请求真实转发到 upstream。

**文件：**
- 创建：`internal/proxy/reverse_proxy.go`
- 创建：`internal/proxy/reverse_proxy_test.go`
- 修改：`internal/httpserver/server.go`

**实现要求：**
- 使用 `net/http/httputil.ReverseProxy`。
- 支持 upstream URL 校验。
- 设置 `X-Forwarded-For`、`X-Forwarded-Host`、`X-Request-ID`。
- upstream 错误返回 502。
- 保留原始 path/query。

**验收：**
- httptest 源站返回内容，WAF 放行后能拿到源站内容。
- 攻击请求不访问源站，直接 403。

## T123：实现拦截响应页

**目标：** 拦截时返回用户友好的 403 页面，API 请求可返回 JSON。

**文件：**
- 创建：`internal/httpserver/block_response.go`
- 创建：`internal/httpserver/block_response_test.go`

**规则：**
- `Accept: application/json` 返回 JSON。
- 普通浏览器返回 HTML 拦截页。
- 响应包含 request ID，不暴露敏感 payload。

## T124：端到端站点防护测试

**目标：** 证明新增站点能防护。

**文件：**
- 创建：`internal/httpserver/site_proxy_e2e_test.go`

**测试流程：**
1. 启动 httptest upstream。
2. 创建站点：domain=`protected.test`，upstream=httptest URL。
3. 请求 `Host: protected.test`，正常 path 返回 upstream 内容。
4. 请求 `/?q=union select` 返回 403。
5. 验证 upstream 未收到攻击请求。

**验收：**
- `go test ./internal/httpserver -run TestSiteProxyProtection -v` 通过。

---

# P3：日志与统计报表真实化

## T130：实现异步日志写入器

**目标：** 防护请求写访问日志和攻击日志，不阻塞主路径。

**文件：**
- 创建：`internal/auditlog/writer.go`
- 创建：`internal/auditlog/writer_test.go`
- 修改：`internal/database/models.go`
- 修改：`internal/database/database.go`

**要求：**
- channel 缓冲。
- 写入失败计数。
- shutdown flush。
- 测试可同步 flush。

## T131：请求处理写访问日志

**目标：** 每个站点请求写 AccessLog。

**文件：**
- 修改：`internal/httpserver/server.go`
- 修改：`internal/httpserver/site_proxy_e2e_test.go`

**字段：**
- siteID、host、sourceIP、method、path、status、decision、latency、bytesOut。

**验收：**
- 正常请求产生 AccessLog。
- upstream 502 也产生 AccessLog。

## T132：拦截请求写攻击日志

**目标：** 命中规则后写 AttackLog。

**文件：**
- 修改：`internal/httpserver/server.go`
- 修改：`internal/pipeline/pipeline.go`
- 修改：`internal/httpserver/site_proxy_e2e_test.go`

**要求：**
- Pipeline Result 暴露 matched rules。
- AttackLog 记录 ruleID、message、stage、payload snippet。

## T133：实现日志查询 API

**目标：** 攻击日志和访问日志页面读真实数据库。

**文件：**
- 创建：`internal/database/log_repository.go`
- 创建：`internal/httpserver/logs_api.go`
- 创建：`internal/httpserver/logs_api_test.go`
- 修改：`internal/httpserver/console_api.go`

**接口：**
- `GET /api/access-logs?page=1&pageSize=20&siteId=&ip=&status=&from=&to=`
- `GET /api/attack-logs?page=1&pageSize=20&siteId=&ip=&type=&severity=&from=&to=`
- `GET /api/access-logs/export`
- `GET /api/attack-logs/export`

## T134：实现统计聚合 Repository

**目标：** 从 AccessLog / AttackLog 聚合统计报表。

**文件：**
- 创建：`internal/reports/repository.go`
- 创建：`internal/reports/repository_test.go`

**聚合项：**
- 请求次数：AccessLog count。
- PV：AccessLog count。
- UV：初期用 distinct `sourceIP + userAgent`，后续可 Cookie。
- 独立 IP：distinct sourceIP。
- 拦截次数：AttackLog count 或 AccessLog decision=block。
- 攻击 IP：AttackLog distinct sourceIP。
- QPS：最近 60 秒 AccessLog / 60。
- 4xx/5xx：status between 400 and 599。
- 趋势：按小时/天 bucket 聚合。

## T135：实现 `/api/reports/overview`

**目标：** 统计报表页面 8 卡片、趋势、Top5 读真实数据。

**文件：**
- 创建：`internal/httpserver/reports_api.go`
- 创建：`internal/httpserver/reports_api_test.go`

**验收：**
- 测试插入日志后，接口返回正确聚合。
- `range=24h|7d|30d` 均可用。

## T136：前端统计报表接真实 API

**目标：** `DashboardView.vue` 或统计报表页移除硬编码 Mock。

**文件：**
- 创建：`web/src/api/reports.ts`
- 创建：`web/src/stores/reports.ts`
- 修改：`web/src/views/DashboardView.vue`

**验收：**
- `npm run build` 通过。
- 后端无数据时显示 0 和空状态，不使用假数据。

---

# P4：策略能力真实化

## T140：规则管理持久化

**目标：** 控制台规则 CRUD 真正影响检测引擎。

**文件：**
- 创建：`internal/rules/service.go`
- 创建：`internal/rules/service_test.go`
- 修改：`internal/detection/manager.go`
- 修改：`internal/httpserver/console_api.go`

**设计：**
- DB 存自定义规则。
- 文件规则仍从 `rules/` 读取。
- Reload 时合并文件规则和 DB 规则。
- 禁用规则持久化到 DB 或 config 表。

## T141：接入 OWASP CRS 子集

**目标：** 从种子规则升级到 CRS 可用子集。

**文件：**
- 创建：`rules/crs/`
- 创建：`internal/detection/crs_import.go`

**注意：**
- 当前解析器只支持简化 `SecRule`，短期先导入可解析子集。
- 完整对标建议引入 Coraza/v3，而不是自研解析全部 ModSecurity。

## T142：访问控制规则生效

**目标：** IP 黑白名单、URL 白名单、UA 限制参与请求决策。

**文件：**
- 创建：`internal/accesscontrol/engine.go`
- 创建：`internal/accesscontrol/engine_test.go`
- 修改：`internal/pipeline/pipeline.go`

**优先级：**
1. IP 白名单：直接 allow 并跳过检测。
2. URL 白名单：跳过检测但仍转发和记录访问日志。
3. IP 黑名单 / UA 限制 / 地区封锁：block。

## T143：访问控制 API 真实化

**目标：** 前端访问控制页面可 CRUD。

**文件：**
- 修改：`internal/httpserver/console_api.go`
- 创建：`internal/httpserver/access_rules_api_test.go`
- 修改：`web/src/api/accessControl.ts`

## T144：CC 防护引擎

**目标：** 基于 IP + site + scope 的滑动窗口限速。

**文件：**
- 创建：`internal/cc/engine.go`
- 创建：`internal/cc/engine_test.go`
- 修改：`internal/pipeline/pipeline.go`

**算法：**
- 初期内存 map + ring buckets。
- key=`siteID:sourceIP:scope`。
- 超阈值 action=`block|captcha|log`。
- 后期 Redis 可选。

## T145：CC 策略 API 真实化

**目标：** 前端 CC 页面保存策略后生效。

**文件：**
- 修改：`internal/httpserver/console_api.go`
- 创建：`internal/httpserver/cc_api_test.go`
- 修改：`web/src/api/ccProtection.ts`

---

# P5：证书、人机验证、运维

## T150：证书模型与 API

**目标：** 支持上传证书并绑定站点。

**文件：**
- 修改：`internal/database/models.go`
- 创建：`internal/certs/service.go`
- 创建：`internal/httpserver/certs_api.go`

**接口：**
- `GET /api/certificates`
- `POST /api/certificates`
- `DELETE /api/certificates/{id}`
- `POST /api/sites/{id}/certificate`

## T151：HTTPS 监听与 SNI 匹配

**目标：** HTTPS 请求按 SNI/Host 命中站点。

**文件：**
- 修改：`internal/httpserver/server.go`
- 创建：`internal/httpserver/tls_config.go`

**注意：**
- Windows 本地先用自签证书测试。
- 生产需支持证书热加载。

## T152：验证码 Challenge 最小实现

**目标：** CC action=captcha 时返回 challenge 页面，验证通过后短期放行。

**文件：**
- 创建：`internal/captcha/service.go`
- 创建：`internal/captcha/service_test.go`
- 修改：`internal/httpserver/server.go`

**最小策略：**
- token 存内存，TTL 5 分钟。
- Challenge path：`/_aegis_challenge`。
- 初期可用简单图形/算术验证码，后续接滑块。

## T153：系统备份恢复

**目标：** 导出/导入站点、规则、策略配置。

**接口：**
- `GET /api/system/backup`
- `POST /api/system/restore`

---

# P6：高性能与高级语义闭环

## T160：请求对象池和 Body 限制优化

**目标：** 降低高并发 GC 压力。

**文件：**
- 修改：`internal/httpserver/server.go`
- 修改：`internal/pipeline/pipeline.go`

**要求：**
- 大 body 只截取 snippet 写日志。
- 检测 body 读取受配置控制。
- sync.Pool 管理临时 buffer。

## T161：WorkerPool 检测模式

**目标：** 对规则/语义检测引入可配置 worker pool。

**文件：**
- 创建：`internal/pipeline/worker_pool.go`
- 创建：`internal/pipeline/worker_pool_test.go`

**配置：**
- `pipeline.workerCount`
- `pipeline.queueSize`
- `pipeline.timeoutMs`

## T162：Prometheus 指标

**目标：** 暴露 QPS、延迟、拦截数、错误数。

**接口：**
- `GET /metrics`

**指标：**
- `aegis_requests_total`
- `aegis_blocked_total`
- `aegis_request_duration_seconds`
- `aegis_upstream_errors_total`

## T163：Linux XDP 真实验收

**目标：** 在 Linux 环境验证 eBPF/XDP 挂载和 map 下刷。

**要求：**
- 不在 Windows 上伪造 XDP 结果。
- Linux 机器：root/CAP_BPF/CAP_NET_ADMIN、clang/llvm、bpftool。
- 压测命令见 `docs/performance-t061.md`。

## T164：语义分析决策接入

**目标：** 让 AST/污点/熵值结果真正影响请求决策。

**文件：**
- 修改：`internal/detection/semantic.go`
- 修改：`internal/pipeline/pipeline.go`

**策略：**
- 高置信度：block。
- 中置信度：log / captcha。
- 低置信度：allow + featureloop observe。

## T165：特征闭环真实化

**目标：** 从攻击日志聚类生成候选规则，灰度验证后启用。

**文件：**
- 修改：`internal/featureloop/featureloop.go`
- 创建：`internal/featureloop/scheduler.go`

**流程：**
1. 读取攻击日志和语义结果。
2. AST 骨架提取。
3. 聚类。
4. 生成候选规则。
5. 灰度启用。
6. 误报率超阈值自动回滚。

---

## 6. 前端页面验收标准

### 6.1 站点页面

- 新增站点会调用 `POST /api/sites`。
- 编辑站点会调用 `PUT /api/sites/{id}`。
- 启停站点会调用 `PATCH /api/sites/{id}/status`。
- 删除站点会调用 `DELETE /api/sites/{id}`。
- 不再使用 fallback 假站点掩盖接口失败。

### 6.2 攻击日志页面

- 支持分页。
- 支持站点、IP、攻击类型、动作、时间筛选。
- 导出 CSV 来自后端真实数据。

### 6.3 统计报表页面

- 8 个卡片全部来自 `/api/reports/overview`。
- 地图数据无 IP 库时显示“未配置地理库”，不能造假。
- 趋势图无数据时显示空状态。

### 6.4 规则页面

- 规则启停后立即 reload 检测引擎。
- 新增自定义规则必须校验语法。
- 删除规则需要二次确认。

---

## 7. 测试策略

### 7.1 后端测试

每个任务至少有单元或集成测试：

```bash
go test ./internal/database -v
go test ./internal/gateway -v
go test ./internal/proxy -v
go test ./internal/httpserver -v
go test ./internal/reports -v
go test ./...
```

### 7.2 前端测试

```bash
cd web
npm run build
npm run lint
```

如项目未配置 lint，则只跑 build，不新增格式化体系。

### 7.3 端到端验收

本地最小验收脚本：

1. 启动 fake upstream：`python -m http.server 18080` 或 httptest。
2. 启动 WAF：`AEGIS_WAF_SERVER_PORT=9090 go run ./cmd/aegis-waf`。
3. 创建站点：Host=`protected.test`，upstream=`http://127.0.0.1:18080`。
4. 正常请求：`curl -H 'Host: protected.test' http://127.0.0.1:9090/`，应返回 upstream 内容。
5. 攻击请求：`curl -H 'Host: protected.test' 'http://127.0.0.1:9090/?q=union%20select'`，应返回 403。
6. 查询攻击日志：`GET /api/attack-logs` 能看到记录。
7. 查询报表：`GET /api/reports/overview?range=24h` 计数增加。

---

## 8. 执行纪律

- 每次只执行一个任务编号。
- 每个任务必须有测试或构建验证。
- 不允许用 Mock 掩盖真实接口失败。
- 不允许在 Windows 声称 XDP 真实性能达标。
- 站点防护闭环优先级高于美化前端。
- 完成每个任务后更新 `docs/full-product-progress.md`。
- 任何 destructive 操作先说明范围。

---

## 9. 首批推荐执行顺序

如果目标是最快从骨架变成“能用的 WAF”，按下面顺序执行：

1. T100：更新 README 当前状态。
2. T101：建立后续任务状态文件。
3. T110：扩展数据库 Site 模型。
4. T111：新增站点 Repository。
5. T112：HTTP Server 注入数据库依赖。
6. T113：实现站点 CRUD API。
7. T114：前端站点页面接真实 API。
8. T120：实现 Host 到 Site 匹配。
9. T122：实现 ReverseProxy 放行转发。
10. T124：端到端站点防护测试。

完成到 T124 后，项目才可以对外说：新增站点后能进行基础 WAF 防护。

---

## 10. 阶段性验收口径

### P1 完成口径

- 前端新增站点成功。
- 站点写入数据库。
- 重启服务后站点仍存在。
- 站点启停状态可保存。

### P2 完成口径

- Host 命中站点。
- 正常请求转发 upstream。
- 攻击请求被规则拦截。
- 拦截不会访问 upstream。
- `go test ./...` 通过。

### P3 完成口径

- 访问日志真实写入。
- 攻击日志真实写入。
- 统计报表 8 项来自数据库。
- 前端无 Mock 数据兜底。

### P4 完成口径

- 规则、访问控制、CC 策略 CRUD 生效。
- 控制台改动能影响下一次请求。

### P5 完成口径

- HTTPS 站点可接入。
- 证书可管理。
- CC 可触发验证码。

### P6 完成口径

- Linux 环境完成 XDP 挂载和压测。
- 语义分析能影响决策。
- 特征闭环能生成候选规则并灰度。

---

## 11. 风险和取舍

### 11.1 Coraza / CRS 风险

当前自研规则解析器只能解析极简 `SecRule`，完整 CRS 语法很复杂。若要真正对标雷池，建议 P4 直接引入 Coraza/v3，而不是继续扩展简易解析器。

### 11.2 HTTPS / SNI 风险

HTTP 反代闭环应先完成。HTTPS 接入涉及证书、SNI、多端口监听、热加载，放到 P5。

### 11.3 XDP 风险

XDP 只能在 Linux + 权限 + 网卡环境验收。Windows 下只能测 mock 数据面和 Go HTTP 路径。

### 11.4 统计准确性风险

UV 没有 Cookie 或 JS SDK 时只能近似。第一版用 IP+UA，后续加访问标识 Cookie。

### 11.5 性能风险

真实 WAF 的主要耗时在规则检测、body 读取、日志写入和 upstream。先做正确闭环，再做 WorkerPool、对象池、异步日志和 XDP。

---

## 12. 给后续实现 Agent 的硬性要求

- 不要再写只返回样例数据的 API。
- 所有新增控制台 API 必须有后端测试。
- 前端 fallback 只能用于开发提示，不能伪装成真实数据。
- 每个 “保存” 按钮必须对应真实后端接口。
- 每个 “防护开关” 必须影响请求处理结果。
- 每个统计数字必须能追溯到日志或指标来源。
- 文档说完成前必须用 curl/测试证明。

## 13. 执行粒度约束

本文的 T100、T110 这类编号是“交付任务”，执行时如果单个任务超过 2 小时，必须拆成子任务，例如：

- T110-1：只改模型并 AutoMigrate。
- T110-2：只补数据库迁移测试。
- T110-3：只修受影响编译错误。

拆分后仍必须遵守：

1. 一次只执行一个子任务。
2. 子任务必须有明确验收命令。
3. 子任务完成后更新 `docs/full-product-progress.md`。
4. 不允许跳过失败测试继续后续任务。
5. 不允许为了通过测试删除真实验收逻辑。
