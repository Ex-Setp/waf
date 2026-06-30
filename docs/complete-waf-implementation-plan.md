# Aegis-WAF 完整 WAF 落地开发文档

> **For Hermes:** 后续执行时使用 `software-development/staged-project-development`。严格按本文任务编号推进，一次只做一个任务；每个任务必须实现、测试、更新状态后再进入下一项。

**目标：** 基于当前 Aegis-WAF 项目骨架，把系统补成一个可以真实接入多个网站、按站点防护、反向代理转发、拦截攻击、记录日志、统计报表，并在语义分析能力上替代/增强雷池个人版体验的完整 WAF。

**当前定位修正：** 现有项目已经有 HTTP 入口、规则检测、语义分析骨架、前端控制台和部分样例 API，但还不是完整 WAF。当前最大缺口不是语义分析，而是“站点接入 + Host 匹配 + upstream 反代 + 真实日志统计”这条地基链路。

**核心原则：** 功能形态对标雷池，检测核心使用 `Coraza/CRS + 自研语义分析 + 特征闭环`，性能路径使用 `内存快照 + 异步日志 + 按需语义分析 + 可选 XDP/eBPF 快速封禁`。

---

## 1. 当前项目真实状态

### 1.1 已有能力

- HTTP 服务入口：`internal/httpserver/server.go`
- 控制台 API 样例：`internal/httpserver/console_api.go`
- 四层流水线编排：`internal/pipeline/pipeline.go`
- 规则加载与匹配：`internal/detection/manager.go`
- 默认规则目录：`rules/`
- SQL / JS AST 与污点追踪骨架：`internal/semantic/`
- 特征闭环骨架：`internal/featureloop/`
- 数据面 XDP/eBPF 适配骨架：`internal/dataplane/`
- 数据库连接和迁移骨架：`internal/database/`
- Vue3 控制台页面：`web/src/`

### 1.2 关键缺口

- `/api/sites` 只返回样例数据，没有真实 CRUD。
- `Site` 模型只有 `Domain` 和 `Enabled`，无法表达完整站点配置。
- 请求没有按 `Host` 匹配站点。
- WAF 放行后不会转发到 upstream，只返回 JSON 决策。
- 攻击日志、访问日志没有在真实请求中落库。
- dashboard、站点列表、攻击日志、CC、人机验证大多是样例数据。
- CC 防护没有真实滑动窗口计数。
- 访问控制没有真实策略链路。
- 人机验证没有 challenge/token 闭环。
- 语义分析还没有和真实站点策略、规则评分、日志解释完整打通。

### 1.3 最小完整 WAF 闭环

一个站点算“真正被 WAF 防护”，必须满足：

```text
控制台新增站点
  -> 写入数据库
  -> 刷新内存 SiteRuntime 快照
  -> 请求进入 WAF
  -> 根据 Host 匹配站点
  -> 执行访问控制 / CC / 规则检测 / 语义检测
  -> block：返回 403 并写攻击日志
  -> allow：反向代理到 upstream 并写访问日志
  -> 控制台展示真实日志和统计
```

---

## 2. 目标架构

### 2.1 产品防护链路

```text
Client
  ↓
HTTP/HTTPS 入口
  ↓
站点接入层：Host/SNI -> SiteRuntime -> upstream/policy
  ↓
访问控制层：IP 黑白名单 / URL 白名单 / UA / 方法 / 地区
  ↓
行为防护层：CC 限速 / Bot / 人机验证 / 临时封禁
  ↓
攻击检测层：Coraza/CRS / 自定义规则 / SQL/XSS/命令注入/路径遍历
  ↓
语义增强层：AST / 污点追踪 / 语法熵 / 0day 泛化 / 特征闭环
  ↓
allow -> ReverseProxy -> Upstream
block -> 拦截响应
  ↓
异步日志与统计：access_logs / attack_logs / metrics
```

### 2.2 四层架构重新定义

当前文档里的四层偏技术实现。为了更像雷池，应改成用户可感知的四层防护：

| 层级 | 名称 | 职责 | 当前状态 |
| --- | --- | --- | --- |
| 第一层 | 站点接入层 | Host 匹配、upstream、反代、TLS、站点开关 | 缺失 |
| 第二层 | 访问控制层 | IP/URL/UA/地区/方法黑白名单 | 缺失 |
| 第三层 | 行为防护层 | CC、高频访问、Bot、人机验证 | 缺失 |
| 第四层 | 攻击检测层 | CRS 规则、语义分析、0day、特征闭环 | 部分已有 |

XDP/eBPF 不单独作为产品层，而是作为性能加速能力：用于 IP 黑名单、高频源、已确认恶意指纹的快速丢弃。

### 2.3 前端复刻原则

当前前端不能按普通后台模板继续自由发挥。产品目标是替代雷池个人版，所以控制台必须以 SafeLine / 雷池的交互和信息架构为基准，做近 1:1 功能复刻。

复刻范围：

- 左侧导航结构：总览、防护应用/站点、攻击事件、黑白名单、CC 防护、人机验证、防护配置、证书、系统设置。
- 页面布局：卡片数量、表格字段、筛选区、操作按钮、详情抽屉/弹窗位置尽量保持一致。
- 站点管理流程：新增站点、配置域名、配置源站、开启防护、查看状态的步骤要和雷池接近。
- 攻击事件页面：筛选、列表字段、攻击详情、命中规则、请求 payload、处理动作要完整。
- CC、人机验证、黑白名单页面：策略配置项、启停状态、命中次数、操作入口要对齐。
- 视觉风格：颜色、间距、表格密度、状态标签、危险操作提示要统一，不能混搭不同后台风格。

开发约束：

- 不允许把 Element Plus 示例页当成最终设计。
- 不允许为了“看起来高级”改成和雷池差异很大的信息架构。
- 不允许前端展示后端不存在的真实功能，除非明确标注为后续任务或隐藏入口。
- 新页面开发前必须先列出雷池对应页面的字段、操作、状态和空态。
- 后端未落地前，前端可以保留 skeleton/loading/empty，但不能用假数据冒充完成。

验收口径：

- 用户能按雷池的使用习惯找到同类功能。
- 站点、攻击事件、黑白名单、CC、人机验证的主要字段与雷池基本一致。
- 页面截图对比时，布局和操作路径应接近，而不是只是功能名字相同。
- 所有数据优先来自真实 API；Mock 只能用于开发态，不计入完成状态。

### 2.4 性能原则

热路径禁止做这些事:

- 每个请求查数据库。
- 每个请求同步写大量日志。
- 每个请求重新解析规则。
- 每个请求都跑完整 AST/语义分析。
- 每个请求新建 upstream 连接。

热路径必须做到：

- 站点和策略使用内存快照。
- Host 匹配使用 `map[string]*SiteRuntime`。
- 规则预编译或预加载。
- 日志先写队列，后台批量落库。
- 正常请求走轻路径，可疑请求才进入重语义分析。
- ReverseProxy 复用连接池和 keep-alive。

---

## 3. 后端模块规划

短期可以在现有目录内补功能，稳定后再拆包。目标结构如下：

```text
internal/
  gateway/          # Host 匹配、站点运行时快照、请求上下文
  proxy/            # ReverseProxy、upstream、超时、错误处理
  accesscontrol/    # IP/URL/UA/地区访问控制
  cc/               # 滑动窗口/令牌桶限速
  captcha/          # 人机验证 challenge/token
  auditlog/         # 访问日志、攻击日志、异步写入
  reports/          # dashboard、趋势、TopN 聚合
  rules/            # 规则 CRUD、规则组、CRS 导入
  database/         # GORM models/repositories/migrations
  httpserver/       # HTTP server 和 API 路由
```

---

## 4. 数据模型设计

### 4.1 Site

替换当前简化版 `Site`。

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

第一版可以用 `DomainsJSON` 存数组，后续再拆 `SiteDomain` 表。

### 4.2 AccessLog

```go
type AccessLog struct {
    ID        uint    `gorm:"primaryKey"`
    RequestID string  `gorm:"size:64;index"`
    SiteID    uint    `gorm:"index"`
    SiteName  string  `gorm:"size:128"`
    Host      string  `gorm:"size:255;index"`
    SourceIP  string  `gorm:"size:64;index"`
    Method    string  `gorm:"size:16;not null"`
    Path      string  `gorm:"size:2048;not null"`
    Query     string  `gorm:"type:text"`
    UserAgent string  `gorm:"size:512"`
    Status    int     `gorm:"index;not null"`
    Decision  string  `gorm:"size:32;index"`
    Upstream  string  `gorm:"size:512"`
    LatencyMS float64 `gorm:"not null;default:0"`
    BytesIn   int64   `gorm:"not null;default:0"`
    BytesOut  int64   `gorm:"not null;default:0"`
    CreatedAt int64   `gorm:"autoCreateTime:milli;index"`
}
```

### 4.3 AttackLog

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

### 4.4 AccessRule

```go
type AccessRule struct {
    ID          uint   `gorm:"primaryKey"`
    SiteID      uint   `gorm:"index;default:0"`
    Type        string `gorm:"size:32;index"` // ip_blacklist/ip_whitelist/url_whitelist/ua_block/method_block/region_block
    Value       string `gorm:"size:512;not null"`
    Description string `gorm:"size:512"`
    Enabled     bool   `gorm:"not null;default:true"`
    Hits        int64  `gorm:"not null;default:0"`
    CreatedAt   int64  `gorm:"autoCreateTime:milli"`
    UpdatedAt   int64  `gorm:"autoUpdateTime:milli"`
}
```

### 4.5 CCPolicy

```go
type CCPolicy struct {
    ID            uint   `gorm:"primaryKey"`
    SiteID        uint   `gorm:"index;default:0"`
    Name          string `gorm:"size:128;not null"`
    Scope         string `gorm:"size:512;not null"`
    Threshold     int    `gorm:"not null"`
    WindowSeconds int    `gorm:"not null"`
    Action        string `gorm:"size:32;not null"` // observe/block/captcha
    Enabled       bool   `gorm:"not null;default:true"`
    CreatedAt     int64  `gorm:"autoCreateTime:milli"`
    UpdatedAt     int64  `gorm:"autoUpdateTime:milli"`
}
```

---

## 5. 运行时快照设计

新增 `internal/gateway`。

### 5.1 SiteRuntime

```go
type SiteRuntime struct {
    ID                 uint
    Name               string
    Domains            []string
    Upstream           *url.URL
    UpstreamRaw        string
    Status             string
    WAFEnabled         bool
    CCProtection       bool
    SemanticProtection bool
    Proxy              *httputil.ReverseProxy
}
```

### 5.2 RuntimeSnapshot

```go
type RuntimeSnapshot struct {
    SitesByHost map[string]*SiteRuntime
    SitesByID   map[uint]*SiteRuntime
    LoadedAt    time.Time
}
```

请求链路只读 `RuntimeSnapshot`，不直接访问数据库。

### 5.3 RuntimeManager

职责：

- 启动时从数据库加载所有站点。
- 新增/编辑/删除站点后刷新快照。
- 支持精确域名匹配。
- 后续支持泛域名匹配。
- 使用 `atomic.Value` 或 `atomic.Pointer` 做无锁读。

接口建议：

```go
type RuntimeManager interface {
    Reload(ctx context.Context) error
    MatchSite(host string) (*SiteRuntime, bool)
    Snapshot() *RuntimeSnapshot
}
```

---

## 6. HTTP 请求主链路

修改 `internal/httpserver/server.go` 的 `handleWAF`。

目标流程：

```text
1. 解析 Host，去掉端口。
2. runtime.MatchSite(host)。
3. 未匹配：返回 404。
4. 站点 disabled：返回 503。
5. 站点 WAF 开启：进入 pipeline。
6. pipeline block：返回 403，写 attack_logs 和 access_logs。
7. pipeline allow：调用站点 ReverseProxy 转发 upstream。
8. upstream 完成后写 access_logs。
```

第一版可以保留当前 JSON 拦截响应；后续再做 HTML 拦截页。

---

## 7. 控制台 API 设计

### 7.1 站点 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/sites` | 站点列表，查数据库 |
| POST | `/api/sites` | 新增站点 |
| GET | `/api/sites/{id}` | 站点详情 |
| PUT | `/api/sites/{id}` | 更新站点 |
| DELETE | `/api/sites/{id}` | 删除站点 |
| POST | `/api/sites/{id}/enable` | 启用站点 |
| POST | `/api/sites/{id}/disable` | 禁用站点 |

新增/更新/删除成功后必须调用 `RuntimeManager.Reload()`。

### 7.2 日志 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/access-logs` | 访问日志列表，支持分页筛选 |
| GET | `/api/attack-logs` | 攻击日志列表，支持分页筛选 |
| GET | `/api/attack-logs/export` | 按筛选条件导出 CSV |

### 7.3 访问控制 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/access-rules` | 规则列表 |
| POST | `/api/access-rules` | 新增规则 |
| PUT | `/api/access-rules/{id}` | 更新规则 |
| DELETE | `/api/access-rules/{id}` | 删除规则 |
| POST | `/api/access-rules/{id}/enable` | 启用 |
| POST | `/api/access-rules/{id}/disable` | 禁用 |

### 7.4 CC API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/cc-protection` | 策略与统计 |
| POST | `/api/cc-policies` | 新增 CC 策略 |
| PUT | `/api/cc-policies/{id}` | 更新 CC 策略 |
| DELETE | `/api/cc-policies/{id}` | 删除 CC 策略 |

### 7.5 人机验证 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/captcha` | 配置 |
| PUT | `/api/captcha` | 更新配置 |
| GET | `/challenge` | 展示挑战页 |
| POST | `/challenge/verify` | 验证并写 token |

---

## 8. 分阶段任务计划

## 阶段 A：真实站点防护闭环

### T070：扩展数据库模型

**目标：** 扩展 `Site`、`AccessLog`、`AttackLog`，让数据库能保存真实 WAF 运行数据。

**文件：**

- 修改：`internal/database/models.go`
- 修改：`internal/database/database.go`
- 修改：`internal/database/database_test.go`

**验收：**

- `go test ./internal/database` 通过。
- SQLite AutoMigrate 能创建新字段。

### T071：实现站点 CRUD API

**目标：** `/api/sites` 从样例数据改成真实数据库 CRUD。

**文件：**

- 修改：`internal/httpserver/console_api.go`
- 新增：`internal/database/site_repository.go`
- 修改：`internal/httpserver/console_api_test.go`

**验收：**

- `POST /api/sites` 能新增站点。
- `GET /api/sites` 返回真实新增站点。
- `PUT /api/sites/{id}` 能修改 upstream/domain。
- `DELETE /api/sites/{id}` 能删除站点。

### T072：实现运行时站点快照

**目标：** 请求链路通过内存快照按 Host 匹配站点。

**文件：**

- 新增：`internal/gateway/runtime.go`
- 新增：`internal/gateway/runtime_test.go`
- 修改：`internal/httpserver/server.go`

**验收：**

- `test.local` 能匹配到对应站点。
- `test.local:9090` 能归一化为 `test.local`。
- 未配置 Host 返回未匹配。

### T073：实现 ReverseProxy 转发

**目标：** WAF 放行后转发请求到站点 upstream。

**文件：**

- 新增：`internal/proxy/reverse_proxy.go`
- 修改：`internal/gateway/runtime.go`
- 修改：`internal/httpserver/server.go`
- 修改：`internal/httpserver/server_test.go`

**验收：**

- 启动测试 upstream 后，`Host: test.local` 请求能返回源站内容。
- upstream 不可用时返回 `502`。
- `X-Forwarded-For` 正确追加客户端 IP。

### T074：打通 block/allow 日志

**目标：** WAF 真实请求写访问日志和攻击日志。

**文件：**

- 新增：`internal/auditlog/writer.go`
- 新增：`internal/auditlog/writer_test.go`
- 修改：`internal/httpserver/server.go`
- 修改：`internal/database/models.go`

**验收：**

- allow 请求写 `access_logs`。
- block 请求写 `access_logs` 和 `attack_logs`。
- 攻击日志包含站点、IP、路径、规则 ID、拦截阶段。

### T075：控制台日志和统计改真实数据

**目标：** dashboard、站点列表、攻击日志不再使用 sample 数据。

**文件：**

- 修改：`internal/httpserver/console_api.go`
- 新增：`internal/reports/dashboard.go`
- 新增：`internal/reports/dashboard_test.go`

**验收：**

- `/api/dashboard/overview` 今日请求数来自 `access_logs`。
- 今日拦截数来自 `attack_logs`。
- `/api/attack-logs` 返回真实攻击日志。

## 阶段 B：雷池基础策略能力

### T080：访问控制策略

**目标：** 实现站点级 IP/URL/UA/方法黑白名单。

**验收：**

- IP 黑名单直接 block。
- IP 白名单可跳过重检测。
- URL 白名单可直接放行或跳过语义分析。
- UA 黑名单可 block。

### T081：CC 防护

**目标：** 实现单机内存滑动窗口限速。

**验收：**

- 同 IP 同路径超过阈值触发 block。
- key 使用 `siteID + sourceIP + path`。
- 支持 `observe/block/captcha` 动作。
- 命中后写攻击日志或行为日志。

### T082：人机验证最小闭环

**目标：** 实现 challenge 页面、验证接口和 Cookie token。

**验收：**

- CC 策略动作为 captcha 时跳转/返回 challenge。
- 验证成功后写入 token。
- token 有效期内放行。
- token 过期后重新挑战。

## 阶段 C：检测引擎强化

### T090：请求规范化

**目标：** 在检测前统一解码和归一化请求。

**内容：**

- URL decode。
- HTML entity decode。
- Unicode escape decode。
- path normalize。
- SQL 注释和空白归一。
- Header/参数大小写策略。

**验收：**

- 编码后的 `<script>` 能被还原并检测。
- 编码后的 `union select` 能被还原并检测。

### T091：规则评分模式

**目标：** 从“一条 deny 就拦”升级为可配置评分阈值。

**验收：**

- 规则有 severity/score。
- 站点可配置拦截阈值。
- 低分命中可 observe，高分命中 block。

### T092：语义分析按需触发

**目标：** 语义分析只对可疑请求执行，避免拖慢全部流量。

**触发条件：**

- CRS 命中但未达到拦截阈值。
- 参数含 SQL/JS 高危 token。
- 高风险路径，例如 `/login`、`/search`、`/api/*`。
- 站点开启强语义模式。

**验收：**

- 静态资源不跑语义分析。
- 普通请求不跑语义分析。
- 可疑 SQL/XSS 请求触发语义分析。

## 阶段 D：性能与生产化

### T100：异步日志队列

**目标：** 请求线程不直接阻塞写数据库。

**验收：**

- 日志投递到 channel。
- 后台 worker 批量写库。
- 队列满时按策略丢弃 access log，但不能丢 attack log。

### T101：配置热加载

**目标：** 站点、访问控制、CC、规则变更后刷新内存快照。

**验收：**

- 新增站点无需重启生效。
- 修改 upstream 无需重启生效。
- 修改黑名单无需重启生效。

### T102：XDP/eBPF 快速封禁

**目标：** 把已确认恶意 IP/指纹下刷到 XDP map。

**验收：**

- 用户态识别高频恶意 IP。
- 下刷到 map。
- 后续请求在数据面快速 block/drop。
- Linux 环境专项测试通过。

## 阶段 E：前端 SafeLine / 雷池近 1:1 复刻

### T110：前端信息架构重整

**目标：** 按雷池个人版控制台重整导航、路由、页面层级，移除当前混乱的泛后台布局。

**文件：**

- 修改：`web/src/router/`
- 修改：`web/src/layouts/`
- 修改：`web/src/views/`
- 修改：`web/src/components/`

**验收：**

- 左侧导航与雷池核心功能分组基本一致。
- 总览、防护应用、攻击事件、黑白名单、CC 防护、人机验证、防护配置、证书、系统设置都有明确入口。
- 不存在命名重复、页面职责交叉、入口混乱的问题。

### T111：防护应用/站点页面复刻

**目标：** 站点列表、新增站点、编辑站点、启停防护流程接近雷池。

**验收：**

- 表格字段包括站点名、域名、源站、防护状态、证书状态、今日请求、今日拦截、操作。
- 新增站点流程至少包含域名、upstream、监听端口、防护开关。
- 保存后调用真实 `/api/sites`，不使用 Mock 数据。
- 页面空态、错误态、加载态完整。

### T112：攻击事件页面复刻

**目标：** 攻击日志页面接近雷池事件审计体验。

**验收：**

- 支持按时间、站点、攻击类型、动作、IP、路径筛选。
- 列表展示时间、站点、源 IP、路径、攻击类型、风险等级、动作、规则 ID。
- 详情抽屉展示请求头、参数、payload、命中规则、阶段、处理结果。
- 数据来自真实 `/api/attack-logs`。

### T113：访问控制、CC、人机验证页面复刻

**目标：** 黑白名单、CC 防护、人机验证页面按雷池操作模型重做。

**验收：**

- 黑白名单页面支持 IP、URL、UA、方法策略。
- CC 页面支持策略列表、阈值、窗口、动作、启停、命中数。
- 人机验证页面支持配置开关、触发条件、token 有效期、验证方式。
- 后端未实现的高级项必须隐藏或标注“后续支持”，不能展示假完成。

### T114：统一视觉和交互规范

**目标：** 统一 SafeLine 风格的间距、颜色、表格密度、状态标签、弹窗/抽屉、危险操作确认。

**验收：**

- 主要页面视觉风格一致。
- 状态颜色统一：启用/正常、禁用、拦截、观察、错误。
- 危险操作有二次确认。
- `npm run build` 通过。

---

## 9. 最小可用版本验收

完成阶段 A 后，项目应达到最小可用 WAF：

1. 启动测试源站：`127.0.0.1:8081`。
2. 控制台或 API 新增站点：`test.local -> http://127.0.0.1:8081`。
3. 请求：`curl -H "Host: test.local" http://127.0.0.1:9090/`。
4. 结果：返回 upstream 源站内容。
5. 请求：`curl -H "Host: test.local" "http://127.0.0.1:9090/?q=<script>"`。
6. 结果：返回 `403`。
7. `/api/access-logs` 能看到正常访问。
8. `/api/attack-logs` 能看到拦截记录。
9. `/api/dashboard/overview` 今日请求和拦截数变化。
10. 删除站点后，`Host: test.local` 不再转发。

---

## 10. 与雷池对标口径

### 10.1 必须对标的基础能力

- 多站点管理。
- 域名/端口/upstream 配置。
- HTTP/HTTPS 反代。
- 规则检测。
- IP 黑白名单。
- URL 白名单。
- CC 防护。
- 人机验证。
- 攻击日志。
- 访问日志。
- Dashboard 统计。
- 规则和策略热更新。

### 10.2 差异化卖点

- SQL/JS AST 解析。
- 污点追踪。
- 语法熵值。
- 0day payload 泛化识别。
- 攻击骨架聚类。
- 自动生成观察规则。
- 稳定后升级拦截规则。
- XDP/eBPF 快速封禁。

### 10.3 不应承诺的内容

在没有真实压测和样本验证前，不应承诺：

- 检测率超过雷池。
- 误报率低于雷池。
- QPS 一定超过雷池。
- Bot 防护效果等同商业版。
- 威胁情报能力等同长亭。

正确表述应为：

- 功能形态对标雷池个人版。
- 检测核心采用自研语义增强。
- 性能目标通过实际压测验证。
- 高级 Bot/威胁情报作为后续增强。

---

## 11. 开发纪律

- 每次只做一个任务编号。
- 每个任务必须有测试。
- 不允许用 sample 数据冒充真实实现。
- 不允许每请求查数据库。
- 不允许正常请求默认全量语义分析。
- 不允许同步重日志阻塞热路径。
- 前端页面只有在后端真实 API 存在后才标完成。
- 前端必须按 SafeLine / 雷池近 1:1 复刻验收，不能用普通后台模板或自由重设计替代。
- 前端新增页面前必须先确认对应雷池页面的信息架构、字段、操作、状态、空态。
- README 的完成状态必须和真实代码一致。

---

## 12. 基础闭环完成后的生产化完善路线

本章节假设阶段 A 已完成，即系统已经具备：站点 CRUD、Host 匹配、ReverseProxy、allow/block、访问日志、攻击日志和基础统计。

此时项目已经不是 Demo，但还不能直接宣称成熟 WAF。后续重点应从“功能能点”转为“实际能防、少误报、可观测、可回滚、可压测”。

### 12.1 实战验证

目标：确认真实攻击能拦，正常业务不误伤。

验证对象：

- 普通页面。
- 登录接口。
- 搜索接口。
- JSON API。
- 文件上传接口。
- 静态资源。

验证攻击：

- SQL 注入。
- XSS。
- 路径遍历。
- 命令注入。
- 恶意 User-Agent。
- 高频请求 / CC。
- 编码绕过 payload。

每条用例必须记录：

| 类型 | Payload | 预期 | 实际 | 是否误报 | 日志是否完整 | 后续动作 |
| --- | --- | --- | --- | --- | --- | --- |

### 12.2 默认防护策略

目标：开箱可用，不让用户从零配置。

必须内置三套策略：

- 宽松模式：适合刚接入，默认 observe，只 block 明确高危攻击。
- 标准模式：适合普通网站，常见 SQLi/XSS/扫描器直接 block。
- 严格模式：适合后台/API，高风险路径启用更强规则、CC、人机验证。

策略必须支持站点级切换。

### 12.3 误报处理

目标：让 WAF 能长期运行，不把业务拦坏。

必须支持：

- observe 模式。
- block 模式。
- URL 白名单。
- 参数白名单。
- IP 白名单。
- 站点级规则启停。
- 路径级规则例外。
- 攻击日志一键加入白名单。
- 白名单命中日志。

### 12.4 请求规范化增强

目标：提升检测效果，降低编码绕过。

必须完善：

- 多层 URL decode。
- HTML entity decode。
- Unicode escape decode。
- Base64 可疑片段识别。
- path normalize。
- SQL 注释归一。
- SQL 空白符归一。
- JSON body 参数提取。
- multipart/form-data 解析。
- gzip body 解压。

### 12.5 规则体系完善

目标：从简单规则匹配升级成可维护规则系统。

必须支持：

- CRS 规则导入。
- 自定义规则管理。
- 规则分类：SQLi、XSS、RCE、LFI、Scanner、Bot。
- 规则严重等级。
- 规则评分。
- 站点级规则组。
- 规则启停。
- 规则热更新。
- 规则命中解释。

推荐动作模型：

```text
低风险 -> observe
中风险 -> captcha / challenge
高风险 -> block
```

### 12.6 CC / Bot 增强

目标：防普通高频访问、扫描器和基础自动化。

必须支持：

- IP + site 限速。
- IP + path 限速。
- IP + UA 限速。
- 登录失败限速。
- 404 扫描限速。
- 无 Cookie 高频请求识别。
- UA 异常识别。
- Referer 异常识别。
- 临时封禁。
- 验证码联动。
- 等候室。

动作分级：

```text
observe -> captcha -> temporary block -> long block
```

### 12.7 日志和可观测性

目标：让管理员看得懂、查得到、能定位。

必须支持：

- 攻击事件详情。
- 原始请求片段。
- 命中规则。
- 命中阶段。
- 拦截原因。
- 处理动作。
- 源 IP。
- 站点。
- upstream 状态。
- latency。
- QPS。
- block rate。
- Top IP。
- Top path。
- Top attack type。
- 日志导出。
- 日志保留策略。
- 敏感字段脱敏。
- Prometheus 指标。

### 12.8 上线安全机制

目标：避免 WAF 自己造成业务故障。

必须支持：

- fail-open / fail-closed 可配置。
- upstream 健康检查。
- upstream 超时。
- upstream 重试。
- WAF 配置备份。
- 配置回滚。
- 规则更新回滚。
- 紧急旁路模式。
- 一键关闭某站点防护。
- 管理后台鉴权。

### 12.9 性能压测

目标：用真实链路证明能扛住业务。

必须压测：

- 纯反代 QPS。
- 开启规则检测 QPS。
- 开启 CC QPS。
- 开启语义分析 QPS。
- 大 body 请求。
- 高并发连接。
- upstream 慢响应。
- 日志高写入压力。

必须记录：

- QPS。
- P50 / P95 / P99 延迟。
- CPU。
- 内存。
- GC 压力。
- 日志队列积压。
- upstream 错误率。

### 12.10 语义增强

目标：形成自研差异化，而不是只靠规则库。

必须增强：

- SQL AST 结构检测。
- 布尔盲注识别。
- 时间盲注识别。
- UNION 变体识别。
- JS/XSS AST 检测。
- 污点追踪。
- 攻击骨架聚类。
- 相似 payload 识别。
- 自动生成观察规则。
- 稳定后升级拦截规则。

约束：语义分析必须按需触发，不能所有请求默认全量执行。

---

## 13. 生产化后续任务

### T120：实战攻击验证集

**目标：** 建立可重复运行的攻击验证集，覆盖常见 Web 攻击和正常业务请求。

**验收：**

- 有 SQLi、XSS、路径遍历、命令注入、恶意 UA、CC、编码绕过测试用例。
- 每个用例记录预期、实际、日志是否完整。
- 验证命令可一键运行。

### T121：默认防护策略

**目标：** 内置宽松、标准、严格三套策略。

**验收：**

- 站点可切换策略。
- 宽松模式默认 observe。
- 标准模式拦截常见高危攻击。
- 严格模式对后台/API 启用更强检测和 CC。

### T122：误报处理闭环

**目标：** 从攻击日志直接生成白名单或规则例外。

**验收：**

- 支持 URL 白名单、参数白名单、IP 白名单。
- 支持站点级禁用规则。
- 攻击日志详情可生成白名单建议。
- 白名单命中可记录审计日志。

### T123：请求规范化增强

**目标：** 提升编码绕过检测能力。

**验收：**

- 多层 URL 编码 payload 能还原。
- HTML entity payload 能还原。
- Unicode escape payload 能还原。
- JSON 和 multipart 参数能进入检测。

### T124：规则评分和规则组

**目标：** 从单规则 deny 升级为站点级规则评分和站点级规则组控制，让不同站点可以按风险阈值和防护类别决定 observe 或 block。

**功能目的：**

- 规则可解释：每条规则具备 `severity`、`score`、`group`，攻击日志能解释“为什么拦、属于哪类攻击、风险几分”。
- 站点可调强度：站点通过 `BlockScoreThreshold` 控制拦截阈值，宽松模式减少误报，严格模式提高拦截强度。
- 站点级规则组：站点通过 `ruleGroups` 选择启用 SQLi、XSS、Scanner、命令注入、路径遍历等检测类别；为空时默认启用全部规则，保持兼容。
- 为 SafeLine / 雷池风格“防护配置”铺后端基础：后续前端可把规则组展示为 SQL 注入防护、XSS 防护、扫描器防护、命令执行防护、文件包含/路径遍历防护、高危拦截/低危观察、站点级策略等配置项。

**规则组建议：**

```text
sqli                 SQL 注入防护
xss                  XSS 防护
scanner              扫描器 / 恶意 UA 防护
command-injection    命令执行 / RCE 防护
path-traversal       文件包含 / 路径遍历防护
default              未分类或通用规则
```

**运行时闭环：**

```text
站点配置 ruleGroups / BlockScoreThreshold
  -> 写入数据库 Site.RuleGroupsJSON / BlockScoreThreshold
  -> Runtime 快照 SiteRuntime.RuleGroups / BlockScoreThreshold
  -> HTTP 请求生成 pipeline.Request.EnabledRuleGroups / BlockScoreThreshold
  -> pipeline 透传给 detection.Request
  -> detection 只运行该站点启用的规则组
  -> 命中规则累计 score
  -> score < threshold：observe / allow，并写日志用于解释
  -> score >= threshold：block，并写攻击日志
```

**实现要求：**

- `detection.Rule` / `MatchedRule` 支持 `Group`。
- `detection.Request` / `pipeline.Request` 支持 `EnabledRuleGroups`。
- 规则 action 支持 `group:'sqli'` 这类解析。
- 未显式配置 group 时可按规则文件名推断：`942/sqli -> sqli`，`941/xss -> xss`，`930/lfi/rfi -> path-traversal`，`932/rce/command -> command-injection`，`913/scanner -> scanner`，其他为 `default`。
- `database.Site` 支持 `RuleGroupsJSON`，并提供 `RuleGroups()` / `SetRuleGroups()`。
- `gateway.SiteRuntime` 携带 `RuleGroups`。
- `/api/sites` payload 和 response 支持 `ruleGroups`。
- 创建/更新站点时持久化规则组；更新未传 `ruleGroups` 时保留原规则组。

**验收：**

- 规则有 severity 和 score。
- 站点可配置评分阈值。
- 低风险 observe，高风险 block。
- 支持站点级规则组。
- 空规则组配置时全部规则启用。
- 非空规则组配置时只运行站点启用的规则组。
- 规则组、评分阈值能从站点 API 持久化并进入真实 runtime 请求链路。
- 前端“防护配置”后续可直接基于该能力展示 SQLi/XSS/Scanner/RCE/LFI 等防护开关，而不是只做静态页面。

**建议测试：**

- `internal/detection`: `TestManagerFiltersRulesByEnabledRuleGroups`
- `internal/pipeline`: `TestPipelinePassesEnabledRuleGroupsToDetection`
- `internal/gateway`: `TestRuntimeCarriesSiteRuleGroups`
- `internal/httpserver`: 站点 `ruleGroups` 创建/更新/保留，以及真实请求进入 pipeline 的集成测试。

### T125：CC / Bot 增强

**目标：** 防高频访问、扫描器和基础自动化。

**验收：**

- 支持 IP+site、IP+path、IP+UA 多维限速。
- 支持登录失败和 404 扫描限速。
- 支持 observe/captcha/temp-block/long-block 动作链。

### T126：日志可观测性增强

**目标：** 攻击事件可解释、系统状态可观测。

**验收：**

- 攻击详情展示原始请求片段、命中规则、阶段、动作。
- Dashboard 展示 QPS、block rate、Top IP、Top path、Top attack type。
- 支持日志导出、保留策略、敏感字段脱敏。

### T127：上线安全机制

**目标：** 防止 WAF 故障影响业务。

**验收：**

- 支持 fail-open/fail-closed。
- 支持 upstream 健康检查、超时、重试。
- 支持配置备份、配置回滚、规则回滚。
- 支持紧急旁路和站点级一键关闭防护。

### T128：真实链路性能压测

**目标：** 验证不同防护开关下的吞吐和延迟。

**验收：**

- 输出纯反代、规则检测、CC、语义分析、大 body、高并发、慢 upstream 压测报告。
- 报告包含 QPS、P50/P95/P99、CPU、内存、GC、日志队列、upstream 错误率。

### T129：语义增强闭环

**目标：** 把自研语义分析变成稳定差异化能力。

**验收：**

- SQL/XSS AST 检测接入真实请求链路。
- 语义分析按需触发。
- 攻击骨架可聚类。
- 可生成观察规则。
- 观察稳定后可升级为拦截规则。

---

## 14. 防护配置页面完善开发文档

> **背景：** 当前控制台已经按 SafeLine / 雷池风格完成信息架构重组，`/protection-config` 仍是占位页，只提示“规则管理、语义指纹、访问统计”后续补齐。该页面不能继续展示规划中状态，也不能使用前端假数据；必须承接真实防护配置能力，并与后端运行时闭环打通。

### 14.1 页面定位

防护配置页是站点防护能力的统一配置入口，面向管理员提供：

```text
规则管理 / CRS
  -> 查看内置 CRS、自定义规则、语义规则和系统规则
  -> 配置启停、严重等级、分数、动作、规则组、paranoia level
  -> 管理 CRS rule exclusion、规则版本、热更新和回滚
  -> 写入数据库/规则仓库
  -> 热更新 Coraza/CRS、检测引擎和 SiteRuntime 策略
  -> 真实请求命中后写攻击日志/审计日志

站点策略
  -> 按站点配置防护模式、阈值、规则组、动作、CC/Bot、误报白名单
  -> 支持全局默认策略 + 站点覆盖策略
  -> 保存后刷新 SiteRuntime，下一次真实请求生效

误报白名单
  -> 从攻击事件一键加白 URL/参数/IP/规则例外
  -> 支持 rule exclusion、参数级忽略、路径级忽略、时间有效期
  -> 命中白名单必须写审计日志，避免静默绕过

请求解析 / 规范化
  -> 展示 raw/normalized payload、JSON、multipart、header、cookie、body 命中位置
  -> 支持编码绕过解释和解析失败原因展示
  -> 规则详情和攻击事件详情能解释为什么命中

CC / Bot 防护
  -> 配置 IP+site、IP+path、IP+UA、404、login-failure 多维策略
  -> 支持 observe/captcha/temp-block/long-block 动作链
  -> 与人机验证、封禁、访问统计、攻击日志闭环

语义指纹
  -> 展示语义分析生成的攻击骨架/指纹
  -> 支持观察、启用拦截、回滚
  -> 稳定观察后生成规则或升级动作
  -> 接入真实语义检测链路

访问统计 / 攻击日志解释
  -> 展示真实 access_logs / attack_logs / reports 聚合
  -> 支持按站点、时间、路径、状态码、来源 IP、规则组、动作筛选
  -> 展示规则命中链、评分组成、白名单跳过、CC/Bot 处置和 payload 解释
  -> 用于判断策略效果、误报、热点路径和异常流量
```

### 14.2 SafeLine 风格信息架构

防护配置页采用 SafeLine / 雷池近似结构，不能做成泛后台模板。

页面一级结构：

```text
防护配置
  ├─ 站点策略
  │   ├─ 防护模式：宽松 / 标准 / 严格 / 观察
  │   ├─ 站点级阈值、动作、规则组绑定
  │   ├─ CRS paranoia level / anomaly threshold
  │   ├─ CC/Bot 策略摘要
  │   └─ 策略版本、发布、回滚、审计
  ├─ 规则管理 / CRS
  │   ├─ CRS 规则集概览
  │   ├─ 规则列表
  │   ├─ 自定义规则
  │   ├─ 规则组
  │   ├─ Rule exclusion / 规则例外
  │   └─ 规则热更新/回滚
  ├─ 误报白名单
  │   ├─ URL 白名单
  │   ├─ 参数白名单
  │   ├─ IP / CIDR 白名单
  │   ├─ 规则例外
  │   └─ 从攻击日志一键加白
  ├─ 请求解析
  │   ├─ raw request
  │   ├─ normalized request
  │   ├─ JSON / multipart / cookie / header / body 字段树
  │   └─ 解析失败和编码绕过解释
  ├─ CC / Bot 防护
  │   ├─ 策略列表
  │   ├─ 多维限速 site/path/ua/404/login-failure
  │   ├─ captcha 联动
  │   ├─ temp-block / long-block
  │   └─ 最近命中和封禁状态
  ├─ 语义指纹
  │   ├─ 指纹概览
  │   ├─ 观察中指纹
  │   ├─ 已拦截指纹
  │   ├─ 回滚记录
  │   └─ 升级为规则
  └─ 访问统计 / 攻击日志解释
      ├─ 请求趋势
      ├─ Top IP
      ├─ Top Path
      ├─ Top Host / Site
      ├─ 状态码分布
      ├─ 拦截率 / 误报辅助指标
      ├─ 攻击事件列表
      └─ 命中解释：规则、评分、白名单、CC/Bot、payload
```

推荐交互：

- 顶部：站点选择器、时间范围、刷新按钮、运行状态提示。
- 中部：七个 tab 或分栏卡片：站点策略 / 规则管理 / 误报白名单 / 请求解析 / CC-Bot / 语义指纹 / 访问统计与日志解释。
- 右侧抽屉：规则详情、策略详情、白名单详情、请求解析详情、CC/Bot 命中详情、指纹详情、攻击事件详情。
- 危险操作：禁用规则、规则回滚、指纹升级为拦截、白名单扩大作用域、站点策略发布必须二次确认。
- 空态：无数据时展示真实空态文案，不展示伪造样例数据。

### 14.3 数据真实性要求

严禁以下行为：

- 前端硬编码规则集数量、访问量、QPS、Top Path。
- API 失败时静默回退到假数据。
- 后端返回 `sample*` 数据并标记为真实功能完成。
- 只写数据库但不刷新运行时策略。
- 只更新控制台状态但不影响真实请求处理。

所有配置型操作必须满足闭环：

```text
控制台操作
  -> 后端 API 校验
  -> 持久化
  -> 运行时热更新
  -> 真实请求链路生效
  -> 访问日志 / 攻击日志 / 审计日志可验证
  -> 前端从真实 API 展示结果
```

### 14.4 后端 API 规划

新增 SafeLine 对齐能力后，防护配置页不能只保留规则 / 指纹 / 统计三类 API；必须补齐站点策略、CRS/Coraza、误报白名单、请求解析、CC/Bot、攻击日志解释 API。任何新能力如果没有 API 和前端承接，不能标记为完成。

#### 14.4.0 站点策略 API

新增或完善：

```http
GET    /api/protection/site-policies
GET    /api/protection/site-policies/{siteId}
PUT    /api/protection/site-policies/{siteId}
POST   /api/protection/site-policies/{siteId}/publish
POST   /api/protection/site-policies/{siteId}/rollback
GET    /api/protection/site-policies/{siteId}/audit
```

策略字段必须覆盖：

```go
type SiteProtectionPolicy struct {
    SiteID              uint
    Mode                string // observe/loose/standard/strict/custom
    EnabledRuleGroups   []string
    CRSParanoiaLevel    int
    InboundThreshold    int
    OutboundThreshold   int
    DefaultAction       string // observe/captcha/block/allow
    CCPolicyIDs         []uint
    WhitelistIDs        []uint
    RuntimeVersion      string
    PublishedAt         int64
    UpdatedAt           int64
}
```

站点策略验收闭环：

- 控制台修改站点策略后持久化。
- publish 后刷新 SiteRuntime 或下一次请求加载新版本。
- rollback 后恢复上一版本并写审计日志。
- 真实请求能证明规则组、阈值、CRS PL、默认动作发生变化。

#### 14.4.1 规则管理 / CRS API

新增或完善：

```http
GET    /api/protection/rule-sets
GET    /api/protection/rules
POST   /api/protection/rules
PUT    /api/protection/rules/{id}
DELETE /api/protection/rules/{id}
POST   /api/protection/rules/{id}/enable
POST   /api/protection/rules/{id}/disable
GET    /api/protection/rule-groups
POST   /api/protection/rule-groups
PUT    /api/protection/rule-groups/{id}
DELETE /api/protection/rule-groups/{id}
GET    /api/protection/crs/status
POST   /api/protection/crs/reload
POST   /api/protection/crs/update
GET    /api/protection/crs/exclusions
POST   /api/protection/crs/exclusions
PUT    /api/protection/crs/exclusions/{id}
DELETE /api/protection/crs/exclusions/{id}
POST   /api/protection/rules/reload
POST   /api/protection/rules/rollback
```

规则字段：

```go
type ProtectionRule struct {
    ID          uint
    RuleID      string
    Name        string
    Description string
    Category    string // sqli/xss/rce/lfi/scanner/bot/custom/semantic
    Severity    string // low/medium/high/critical
    Score       int
    Action      string // observe/captcha/block/allow
    Enabled     bool
    GroupID     uint
    SiteID      uint // 0 means global
    Pattern     string
    Target      string // path/query/header/body/json/multipart/ua/ip
    Source      string // crs/custom/semantic/system
    Version     string
    CreatedAt   int64
    UpdatedAt   int64
}
```

规则管理验收闭环：

- 新增规则后，规则进入检测引擎或规则管理器。
- 禁用规则后，真实攻击请求不再被该规则拦截。
- 修改 severity/score/action 后，pipeline 结果变化可被测试验证。
- 规则组绑定站点后，只影响对应站点。
- Coraza/CRS 开关、规则版本、PL、异常分阈值可被 API 查询和配置。
- CRS rule exclusion 支持按站点、规则 ID、变量、路径、参数建立例外。
- reload/rollback 写审计日志。

#### 14.4.2 误报白名单 API

新增或完善：

```http
GET    /api/protection/whitelists
POST   /api/protection/whitelists
PUT    /api/protection/whitelists/{id}
DELETE /api/protection/whitelists/{id}
POST   /api/protection/whitelists/{id}/enable
POST   /api/protection/whitelists/{id}/disable
POST   /api/protection/attack-events/{id}/create-whitelist
```

白名单字段必须覆盖：

```go
type FalsePositiveWhitelist struct {
    ID          uint
    SiteID      uint
    Type        string // url/param/ip/cidr/rule-exclusion/header/cookie
    Pattern     string
    RuleIDs     []string
    Variables   []string // ARGS:name, REQUEST_HEADERS:name, JSON:path
    Reason      string
    ExpiresAt   int64
    Enabled     bool
    CreatedFrom string // manual/attack-event
    CreatedAt   int64
    UpdatedAt   int64
}
```

误报白名单验收闭环：

- 从攻击事件可一键生成白名单或 CRS exclusion。
- 白名单命中后真实请求不再被对应规则拦截，但必须写审计事件。
- 白名单作用域必须可控，不能默认全局放行。
- 过期白名单不能继续生效。

#### 14.4.3 请求解析 API

新增或完善：

```http
POST /api/protection/request-parser/preview
GET  /api/protection/attack-events/{id}/request-analysis
```

请求解析返回必须覆盖：

```text
rawRequest
normalizedURI
normalizedQuery
headers
cookies
bodyText
jsonFields
multipartFields
matchedVariables
decodeSteps
parseErrors
```

请求解析验收闭环：

- URL 编码、HTML 实体、Unicode、双重编码能展示规范化步骤。
- JSON、multipart、form、cookie、header 字段能进入检测目标。
- 攻击日志详情能显示原始片段、规范化片段、命中变量和规则原因。

#### 14.4.4 CC / Bot API

新增或完善：

```http
GET    /api/protection/cc-policies
POST   /api/protection/cc-policies
PUT    /api/protection/cc-policies/{id}
DELETE /api/protection/cc-policies/{id}
POST   /api/protection/cc-policies/{id}/enable
POST   /api/protection/cc-policies/{id}/disable
GET    /api/protection/cc-events
GET    /api/protection/cc-blocks
DELETE /api/protection/cc-blocks/{id}
```

CC/Bot API 验收闭环：

- 策略 CRUD 真实读写数据库。
- 保存后刷新运行时策略快照。
- site/path/ua/404/login-failure scope 都能通过真实请求验证。
- captcha/temp-block/long-block 处置能在攻击日志和 CC 事件中解释。

#### 14.4.5 攻击日志解释 API

新增或完善：

```http
GET /api/protection/attack-events
GET /api/protection/attack-events/{id}
GET /api/protection/attack-events/{id}/explanation
GET /api/protection/attack-events/{id}/timeline
```

解释字段必须覆盖：

```text
sitePolicy
matchedRules
matchedRuleGroups
crsAnomalyScore
scoreBreakdown
requestVariables
normalizationSteps
whitelistDecision
ccBotDecision
semanticDecision
finalAction
operatorSuggestion
```

攻击日志解释验收闭环：

- 每条 block/observe/captcha/temp-block/long-block 事件能说明“为什么这样处置”。
- 能显示哪些规则加了多少分、阈值是多少、最终动作是什么。
- 如果因白名单跳过，必须显示跳过原因和白名单 ID。
- 如果因 CC/Bot 命中，必须显示 policyId、scope、key、count、threshold、blockUntil。

#### 14.4.6 语义指纹 API

新增或完善：

```http
GET  /api/protection/semantic-fingerprints
GET  /api/protection/semantic-fingerprints/{id}
POST /api/protection/semantic-fingerprints/{id}/observe
POST /api/protection/semantic-fingerprints/{id}/activate
POST /api/protection/semantic-fingerprints/{id}/rollback
POST /api/protection/semantic-fingerprints/{id}/promote-rule
```

指纹字段：

```go
type SemanticFingerprint struct {
    ID                uint
    Hash              string
    Language          string // sql/javascript/unknown
    Skeleton          string
    ExamplePayload    string
    Action            string // observe/block/allow
    Status            string // observing/active/rollback
    RuleID            string
    Hits              int64
    FalsePositiveHits int64
    FalsePositiveRate float64
    Source            string // ast-cluster/manual/feature-loop
    SiteID            uint
    CreatedAt         int64
    UpdatedAt         int64
}
```

语义指纹验收闭环：

- 真实请求触发语义分析后生成或命中指纹。
- observing 状态只记录日志，不拦截。
- activate 后同类 payload 被拦截。
- rollback 后恢复观察或禁用，不再拦截。
- promote-rule 后生成可见规则，并进入规则管理列表。
- 每次状态变更写审计日志。

#### 14.4.7 访问统计 API

新增或完善：

```http
GET /api/protection/traffic/overview
GET /api/protection/traffic/trend
GET /api/protection/traffic/top-ip
GET /api/protection/traffic/top-path
GET /api/protection/traffic/status-codes
GET /api/protection/traffic/sites
GET /api/protection/traffic/export
```

查询参数：

```text
siteId
startTime
endTime
interval=minute|hour|day
path
sourceIp
statusCode
decision=allow|block|observe|captcha
```

访问统计返回必须来自真实数据源：

- `access_logs`
- `attack_logs`
- `reports` 聚合表或实时 SQL 聚合

访问统计验收闭环：

- 真实 allow 请求后，总请求数增加。
- 真实 block 请求后，拦截数和拦截率变化。
- Top Path / Top IP 由真实日志聚合产生。
- 按站点过滤只展示该站点数据。
- 无日志时返回空数组和 0，不返回样例数据。

### 14.5 前端实现规划

需要替换：

- `web/src/views/ProtectionConfigPlaceholderView.vue`

建议新增：

```text
web/src/views/ProtectionConfigView.vue
web/src/api/protection.ts
web/src/stores/protection.ts
web/src/components/protection/SitePolicyPanel.vue
web/src/components/protection/RuleManagementPanel.vue
web/src/components/protection/CrsManagementPanel.vue
web/src/components/protection/WhitelistPanel.vue
web/src/components/protection/RequestParserPanel.vue
web/src/components/protection/CCBotPanel.vue
web/src/components/protection/SemanticFingerprintPanel.vue
web/src/components/protection/TrafficStatsPanel.vue
web/src/components/protection/AttackExplanationPanel.vue
web/src/components/protection/SitePolicyDrawer.vue
web/src/components/protection/RuleDetailDrawer.vue
web/src/components/protection/WhitelistDetailDrawer.vue
web/src/components/protection/RequestAnalysisDrawer.vue
web/src/components/protection/CCBotEventDrawer.vue
web/src/components/protection/FingerprintDetailDrawer.vue
web/src/components/protection/AttackEventDrawer.vue
```

现有占位或伪数据页面必须处理：

- `web/src/views/RulesView.vue` 当前硬编码规则集数据，不能作为完成态。
- `web/src/views/TrafficView.vue` 当前硬编码访问统计，不能作为完成态。
- `web/src/api/fingerprints.ts` 当前有 fallback 假数据，必须移除；API 失败应显示错误态。

前端验收：

- `/protection-config` 不再显示“规划中”。
- 站点策略、CRS/规则管理、误报白名单、请求解析、CC/Bot、语义指纹、访问统计、攻击日志解释都从真实 API 加载。
- 加载中、空态、错误态完整。
- 保存、发布、启停、回滚、升级规则、创建白名单、解除封禁均有确认和结果反馈。
- API 失败不得显示 fallback 假数据。
- CRS 状态、规则评分、站点阈值、白名单命中、CC/Bot 动作链、payload 解释在页面上可见。
- 页面视觉密度、字段、操作路径对齐 SafeLine / 雷池风格。

### 14.6 测试规划

后端测试：

```text
internal/httpserver/protection_site_policy_test.go
internal/httpserver/protection_rules_test.go
internal/httpserver/protection_crs_test.go
internal/httpserver/protection_whitelist_test.go
internal/httpserver/protection_request_parser_test.go
internal/httpserver/protection_cc_bot_test.go
internal/httpserver/protection_attack_explanation_test.go
internal/httpserver/protection_semantic_fingerprints_test.go
internal/httpserver/protection_traffic_test.go
internal/rules/rule_repository_test.go
internal/detection/coraza_engine_test.go
internal/requestparser/request_parser_test.go
internal/featureloop/fingerprint_runtime_test.go
```

必须覆盖：

- 站点策略保存、发布、回滚影响真实 SiteRuntime。
- 规则 CRUD 持久化。
- CRS/Coraza 规则加载、PL、阈值、reload 影响真实 pipeline 决策。
- 规则启停影响真实 pipeline 决策。
- 规则组绑定站点后只影响该站点。
- 误报白名单和 CRS exclusion 只在限定作用域生效，并写审计。
- 请求解析覆盖 URL/query/header/cookie/body/json/form/multipart 和规范化步骤。
- CC/Bot 策略真实触发 observe/captcha/temp-block/long-block。
- 攻击日志 explanation 能解释规则、评分、白名单、CC/Bot、语义和最终动作。
- 语义指纹 observing / active / rollback 行为。
- 指纹升级为规则后进入规则列表并影响真实请求。
- 访问统计来自真实 access/attack logs。
- API 无数据时返回空结果，不返回 mock。

前端测试 / 构建：

```bash
cd web && npm run build
```

后端验证：

```bash
go test ./internal/httpserver ./internal/rules ./internal/detection ./internal/requestparser ./internal/featureloop ./internal/reports
go test ./...
go vet ./...
```

### 14.7 能力映射与无悬空要求

防护配置页不是独立新页面，而是 T120-T129 生产化能力，以及 T135-T142 SafeLine 对齐能力的统一产品化入口。任何“为后续铺路”的后端能力，必须在 T130-T142 中找到对应前端入口、API、运行时验证和日志/审计证明；不允许出现“能力已做但控制台无法配置/查看/验证”的悬空状态。

| 来源任务 | 已铺能力 | 防护配置/控制台承接位置 | 必须打通的闭环 | 对接任务 |
| --- | --- | --- | --- | --- |
| T120 实战攻击验证集 | SQLi/XSS/路径遍历/命令注入/恶意 UA/编码绕过验证用例 | 规则管理、攻击事件、访问统计 | 验证用例 -> 真实请求 -> 规则/语义/CC 命中 -> attack log -> 控制台可筛选/查看 | T130/T131/T133/T134 |
| T121 默认防护策略 | 宽松/标准/严格，站点级策略模式 | 规则管理顶部策略区、站点策略摘要 | 控制台切换策略 -> Site 持久化 -> Runtime 热更新 -> 阈值/规则组/CC/语义行为变化 -> 日志证明 | T130/T131/T134 |
| T122 误报处理闭环 | URL/参数/IP 白名单、规则例外、审计事件 | 规则管理例外规则、攻击事件一键加白、审计记录 | 攻击日志 -> 生成建议 -> 创建白名单/例外 -> Runtime 生效 -> 白名单命中审计可见 | T131/T134 |
| T123 请求规范化增强 | URL/HTML/Unicode/JSON/multipart 进入检测 | 规则详情命中解释、攻击事件 payload 解释 | 编码 payload -> 规范化检测命中 -> 日志展示原始片段和命中原因 -> 规则详情可解释 | T131/T133/T134 |
| T124 规则评分和规则组 | severity/score/group、站点阈值、ruleGroups | 规则管理、防护类别开关、站点级规则组 | 控制台启停 SQLi/XSS/Scanner/RCE/LFI 等组 -> Runtime 只运行启用组 -> score/threshold 决策 -> 日志可见 | T131/T134 |
| T125 CC / Bot 增强 | 多维限速、登录失败、404 扫描、captcha/temp/long block | CC/Bot 配置摘要、人机验证联动、访问统计异常来源 | 控制台配置策略 -> CC runtime 生效 -> 触发 observe/captcha/block -> 访问统计和日志可见 | T130/T133/T134 |
| T126 日志可观测性增强 | 攻击详情、QPS、block rate、Top IP/Path/type、导出、脱敏 | 访问统计、攻击事件详情、规则命中解释 | 真实 allow/block 请求 -> access/attack logs -> 聚合 API -> 控制台趋势/Top/导出/脱敏展示 | T133/T134 |
| T127 上线安全机制 | fail-open/closed、健康检查、备份/回滚、紧急旁路、站点关闭 | 防护配置安全状态、系统设置、站点操作 | 控制台操作 -> 配置持久化/回滚 -> Runtime 状态变化 -> 审计事件和健康状态可见 | T130/T134 |
| T128 真实链路性能压测 | QPS、P50/P95/P99、CPU、内存、GC、日志队列、upstream 错误率 | 访问统计/运行状态/压测报告入口 | 压测执行 -> 报告落库或文件归档 -> 控制台可查看摘要和报告 -> 上线验收引用 | T133/T134 |
| T129 语义增强闭环 | AST 检测、攻击骨架聚类、观察规则、升级拦截 | 语义指纹、规则管理语义规则 | 真实 payload -> 生成/命中指纹 -> observing/active/rollback/promote-rule -> Runtime 生效 -> 日志/审计可见 | T132/T134 |
| T135 CC / Bot 深度增强 | 策略持久化、后置 404、登录失败、captcha、临时/长期封禁 | CC/Bot 防护、访问统计、攻击日志解释 | 控制台策略 -> Runtime 限速/挑战/封禁 -> 日志解释 -> 统计可见 | T135/T141/T142 |
| T136 Coraza + OWASP CRS | 完整 CRS、Coraza transaction、PL、异常分、CRS reload | 规则管理 / CRS、站点策略、攻击日志解释 | CRS 加载 -> 真实请求命中 -> 分数累计 -> 策略决策 -> 日志解释 | T136/T137/T138/T142 |
| T137 规则组评分 | 规则组、severity/score、anomaly threshold、final action | 规则管理、站点策略、攻击事件详情 | 规则组启停 -> scoreBreakdown -> threshold 决策 -> 前端解释 | T137/T138/T142 |
| T138 站点策略 | 默认策略、站点覆盖、发布、版本、回滚 | 站点策略顶部区、审计记录、运行状态 | 策略发布/回滚 -> SiteRuntime 热更新 -> 真实请求行为变化 -> 审计可查 | T138/T134 |
| T139 误报白名单 | URL/参数/IP/CIDR/header/cookie/rule-exclusion、过期、审计 | 误报白名单、攻击事件一键加白、规则例外 | 攻击事件 -> 创建白名单 -> 限定作用域生效 -> 命中审计可见 | T139/T142 |
| T140 请求解析 | raw/normalized、JSON/multipart/form/header/cookie/body、decode steps | 请求解析、攻击事件 payload 解释、规则命中变量 | 编码/复杂 body -> parser -> 检测变量 -> 日志展示规范化和命中原因 | T140/T142 |
| T141 CC / Bot 生产化 | 策略优先级、可疑 UA、多路径扫描、封禁解除、人机验证 | CC/Bot 防护、封禁列表、访问统计异常来源 | 真实请求 -> CC/Bot 处置 -> captcha/block/解除封禁 -> 日志和统计可见 | T141/T142 |
| T142 攻击日志解释 | explanation JSON、评分组成、白名单/CC/语义决策、运营建议 | 攻击事件详情、规则详情、白名单创建、策略跳转 | attack log -> explanation -> 建议操作 -> 配置变更 -> Runtime 验证 | T142 |

**无悬空验收规则：**

- 每个 T120-T142 能力必须至少满足一种控制台承接方式：配置入口、详情展示、统计展示、审计记录、报告入口。
- 每个配置入口必须证明不是只改数据库：必须有 runtime 热更新或下一次请求生效的集成测试。
- 每个展示入口必须证明不是假数据：必须从真实 `access_logs`、`attack_logs`、规则库、语义指纹库、审计表或压测报告读取。
- 每个“启用/禁用/回滚/升级”动作必须写审计日志。
- 每个能力完成时必须更新本映射表的状态说明；如果某项能力暂不接入控制台，必须在文档中明确原因和后续任务编号。

### 14.8 任务拆分

#### T130：防护配置页面真实化（已完成）

**目标：** 替换占位页，建立站点策略 / CRS 规则管理 / 误报白名单 / 请求解析 / CC-Bot / 语义指纹 / 访问统计与攻击日志解释的真实页面结构。

**验收：**

- [x] `/protection-config` 展示真实 tab/panel，不再显示规划中。
- [x] 页面结构必须承接 T135-T142，不允许只保留旧的规则管理 / 语义指纹 / 访问统计三块。
- [x] 前端 API 层不再使用 fallback 假数据。
- [x] 无后端数据时展示空态。
- [x] `npm run build` 通过。

**完成记录：**

- 新增 `web/src/views/ProtectionConfigView.vue`，以 SafeLine 风格提供站点策略、规则管理 / CRS、误报白名单、请求解析、CC / Bot、语义指纹、访问统计 / 攻击日志解释七个真实 API 面板。
- 新增 `web/src/api/protection.ts`，统一访问 `/api/protection/*`，只返回真实 API 结果；失败进入错误态，不做 sample/fallback。
- `/protection-config` 路由已从占位页切换到真实页面；旧 `RulesView.vue`、`TrafficView.vue` 已移除硬编码假规则数和 Top Path，只保留迁移入口说明。
- 验证命令：`cd web && npm run build` 通过。

**下一任务：** T131：规则管理闭环。

#### T131：规则管理闭环（已完成）

**目标：** 实现规则 CRUD、规则组、规则启停、热更新、回滚，并预留 CRS/Coraza 规则源和 rule exclusion 承接位。

**验收：**

- [x] 规则配置持久化。
- [x] 修改规则后 runtime 热更新。
- [x] 真实请求能证明规则启停/分数/action 生效。
- [x] 页面能显示规则 source：crs/custom/semantic/system。
- [x] 规则操作写审计日志。

**完成记录：**

- 新增 `database.ProtectionRule` 持久化模型并加入 `AutoMigrate`。
- 扩展 detection manager，支持数据库规则热插入、启停、删除、运行时覆盖，并在 reload 后保留控制台规则。
- 新增 `/api/protection/rules`、`/api/protection/rules/{id}`、`/api/protection/rules/{id}/enable|disable` 与 `/api/protection/rule-sets`，规则操作写入审计日志。
- `cmd/aegis-waf` 将 detection engine 注入控制台服务，启动时加载已持久化规则，后续修改会进入真实 pipeline。
- 防护配置页规则面板支持 custom 规则新增、编辑、启停、删除，并展示 `crs/custom/semantic/system` source。
- 新增 `internal/httpserver/t131_protection_rules_test.go`，通过创建规则 -> 请求被拦截、禁用规则 -> 同请求放行、修改 action/score -> 同请求转观察的真实 pipeline 测试证明闭环。
- 验证命令：`go test ./...` 通过；`cd web && npm run build` 通过。

**下一任务：** T132：语义指纹闭环。

#### T132：语义指纹闭环（已完成）

**目标：** 将语义指纹从展示项升级为观察、启用、回滚、升级规则的真实闭环。

**验收：**

- [x] 指纹来自真实语义分析/特征闭环数据。
- [x] observing 不拦截，active 拦截，rollback 恢复。
- [x] promote-rule 后生成规则并进入规则管理。
- [x] 相关操作写审计日志。

**完成记录：**

- `internal/httpserver/semantic_fingerprints.go` 补齐 `promote-rule` 操作：从语义指纹生成 `database.ProtectionRule`，source/category 均为 `semantic`，持久化进入规则管理，并通过 `detectionEngine.UpsertRuntimeRule` + `Reload` 热加载到真实检测运行时。
- rollback 不再只改指纹状态：同步删除 semantic 来源规则、删除 runtime rule、触发 reload，并从 XDP semantic fingerprint map 删除。
- `internal/httpserver/t132_semantic_fingerprint_closure_test.go` 增加闭环测试：promote-rule 后同 payload 被 detection 阶段真实拦截，规则能在 `/api/protection/rules` 看到；rollback 后 DB 规则删除且同 payload 放行；语义指纹和规则操作均产生审计记录。
- 前端 `web/src/api/fingerprints.ts`、`web/src/stores/fingerprints.ts`、`web/src/views/FingerprintsView.vue` 增加 `promote-rule` 类型和“升级规则”按钮，页面文案明确规则管理承接和 rollback 删除语义规则/XDP 同步。
- 验证命令：`go test ./internal/detection ./internal/httpserver ./internal/database` 通过；`cd web && npm run build` 通过（仅 Vite chunk-size 警告）。

**下一任务：** T133：访问统计与攻击事件入口闭环。

#### T133：访问统计与攻击事件入口闭环（已完成）

**目标：** 防护配置页访问统计全部由真实日志聚合产生，并作为攻击日志解释、误报处理、CC/Bot 分析的入口。

**验收：**

- [x] overview/trend/top-ip/top-path/status-codes/sites 均来自真实 access/attack logs。
- [x] 支持站点、时间范围、动作、规则组、攻击类型过滤。
- [x] 真实 allow/block/observe/captcha/temp-block 请求会改变统计。
- [x] 能从统计下钻到攻击事件详情或访问路径详情。
- [x] 无数据时返回空态，不返回样例数据。

**完成记录：**

- 新增 `/api/protection/traffic/overview`、`/api/protection/traffic/trend`、`/api/protection/traffic/top-ip`、`/api/protection/traffic/top-path`、`/api/protection/traffic/status-codes`、`/api/protection/traffic/sites` 与 `/api/protection/attack-events`，全部基于 `database.AccessLog` / `database.AttackLog` 聚合，不走 sample/fallback。
- 扩展日志过滤：支持 `siteId/site/siteName`、毫秒时间戳或日期字符串 `startTime/endTime`、`action/decision`、`ruleGroup`、`attackType`、`sourceIp`、`path`、`status` 等筛选。
- 防护配置页访问统计面板接入 status-codes/sites 聚合，顶部增加动作、规则组/阶段、攻击类型筛选；Top IP/Path/状态码/站点统计提供下钻详情，指向真实 access logs 与 attack events 查询入口。
- 新增 `internal/httpserver/t133_traffic_statistics_test.go`，用真实 DB 日志证明 overview、trend、top-ip、top-path、status-codes、sites、attack-events 过滤、下钻和空态均不返回样例数据。
- 验证命令：`go test ./internal/detection ./internal/httpserver ./internal/database` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T134：防护配置联调验收。

#### T134：防护配置联调验收（已完成）

**目标：** 证明防护配置页面所有操作都不是“只改控制台”，而是能影响真实 WAF 流量；并把 T135-T142 作为后续验收扩展范围。

**验收：**

- [x] 新增规则 -> 攻击请求被拦截。
- [x] 禁用规则 -> 同请求放行或进入 observe。
- [x] 修改站点策略阈值/规则组 -> 同请求决策变化。
- [x] 创建误报白名单 -> 限定请求不再被对应规则拦截。
- [x] CC/Bot 策略 -> 真实请求触发 observe/captcha/block。
- [x] 启用语义指纹 -> 相似 payload 被拦截。
- [x] 回滚指纹 -> 同 payload 不再因该指纹拦截。
- [x] 攻击事件详情能解释规则、评分、白名单/CC/语义和最终动作。
- [x] 访问统计反映上述请求变化。
- [x] 全量验证命令通过。

**完成记录：**

- 新增 `internal/httpserver/t134_protection_integration_test.go`，使用真实 `httpserver.Server`、真实 DB、真实站点 runtime、真实 detection/semantic pipeline 和真实 access/attack logs 进行防护配置联调验收。
- 测试覆盖：控制台新增 custom 规则后真实攻击请求被拦截；禁用同规则后同 payload 放行；调整站点 `blockScoreThreshold` 与 `ruleGroups` 后同规则在 observe/deny 间切换；新增参数白名单后限定请求跳过检测；新增 CC 策略后真实请求从放行变为拦截；语义指纹 `promote-rule` 后相似 payload 被拦截，`rollback` 后恢复放行。
- 验证攻击事件与访问统计：联调产生的真实 access/attack logs 可通过 `/api/protection/attack-events` 解释 detection/cc 阶段、规则/评分/动作，并通过 `/api/protection/traffic/overview` 反映请求量与拦截变化。
- 验证命令：`go test ./internal/detection ./internal/httpserver ./internal/database` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T135：CC / Bot 深度增强与真实运行时闭环。

#### T135：CC / Bot 深度增强与真实运行时闭环（已完成）

**目标：** 在 T125 基础上继续增强 SafeLine / 雷池风格 CC / Bot 防护，补齐策略持久化、真实运行时执行、后置 404 / 登录失败检测、captcha 联动、临时/长期封禁、日志解释和前端配置闭环。

**当前基线：**

- `internal/cc/limiter.go` 已具备基础滑动窗口、站点/路径/UA 维度、`observe/captcha/temp-block/long-block` 动作枚举和临时封禁状态。
- `database.CCPolicy` 已有策略模型和部分控制台 API 骨架。
- 但不能只看模型或单元测试。T135 必须证明 CC / Bot 策略从控制台保存后进入真实 HTTP 请求链路，并对真实站点请求产生 observe / captcha / temp-block / long-block 效果。

**功能目的：**

- 防高频请求：同一个 IP 对同一站点、同一路径、同一 UA 的高频访问触发限速。
- 防扫描器：大量 404、敏感路径探测、异常 UA、短时间多路径访问进入观察、验证码或封禁。
- 防登录爆破：登录接口失败次数超阈值后逐级升级动作。
- 防基础自动化：对固定 UA、固定 IP、固定路径的脚本化访问进行渐进式处置。
- 对齐 SafeLine / 雷池：页面能配置 CC 策略，运行时能执行，攻击日志能解释命中策略和动作。

**策略维度：**

```text
site                IP + site，统计某 IP 对某站点的总访问频率
path                IP + site + path，统计某 IP 对某路径的访问频率
ua / user-agent     IP + site + UA，统计某 IP 使用同一 UA 的访问频率
404 / not-found     IP + site，只有响应状态为 404 时计数，用于发现扫描器
login-failure       IP + site + login path，只有登录接口失败时计数，用于防爆破
```

**策略字段建议：**

```go
type CCPolicy struct {
    ID            uint
    SiteID        uint   // 0 表示全局策略，非 0 表示站点策略
    Name          string
    Enabled       bool
    Scope         string // site / path / ua / 404 / login-failure:/login
    PathPattern   string // 可选，适用于 path/login-failure
    WindowSeconds int
    Threshold     int
    Action        string // observe>captcha>temp-block>long-block
    Priority      int
    CreatedAt     int64
    UpdatedAt     int64
}
```

**动作链：**

支持以下动作：

```text
observe       只记录，不影响业务
captcha       返回人机验证 challenge；通过后放行
temp-block    临时封禁，默认 10 分钟
long-block    长封禁，默认 24 小时
block         直接拦截，兼容旧策略
```

动作链示例：

```text
observe>captcha>temp-block>long-block
```

行为要求：

- 第一次超过阈值：observe。
- 第二次超过阈值：captcha。
- 第三次超过阈值：temp-block。
- 第四次及之后：long-block。
- `temp-block` / `long-block` 生效期间，相同 key 后续请求直接命中封禁，不再重新累计。
- 旧策略如果只写 `block`、`captcha`、`observe`，必须保持兼容。

**运行时闭环：**

```text
控制台创建/更新 CCPolicy
  -> 写入数据库
  -> reloadPolicies / SiteRuntime 刷新
  -> 请求进入 WAF
  -> Host 匹配 SiteRuntime
  -> 读取全局 + 站点 CCPolicy
  -> 按 scope 生成限速 key
  -> Limiter 滑动窗口计数
  -> 超阈值后按动作链升级
  -> observe：放行但写安全事件
  -> captcha：返回 challenge 并写攻击/行为日志
  -> temp-block / long-block：返回 403，并可加入 dataplane/XDP fast-block map
  -> allow：继续进入规则检测/语义检测/反代 upstream
```

**key 规范：**

```text
site:          site:<siteID>:<sourceIP>
path:          path:<siteID>:<sourceIP>:<normalizedPath>
ua:            ua:<siteID>:<sourceIP>:<normalizedUserAgent>
404:           404:<siteID>:<sourceIP>
login-failure: login:<siteID>:<sourceIP>:<loginPath>
```

兼容要求：如已有测试或旧代码依赖 `<siteID>:<ip>:<path>` 这类 path key，允许内部兼容，但新增逻辑和日志解释必须能输出明确维度。

**登录失败限速：**

- 支持 `Scope=login-failure:/login`，没有显式路径时默认 `/login*`。
- 只有响应状态为 `401/403/429` 或上游返回登录失败标记时计数。
- 第一版可以用状态码判断，后续再接业务登录失败特征。
- 命中后写安全事件，事件类型为 `login-bruteforce`。

**404 扫描限速：**

- 支持 `Scope=404` 或 `Scope=not-found`。
- 只有 upstream 返回 404 时计数。
- 用于发现目录扫描、漏洞扫描器和路径爆破。
- 命中后写安全事件，事件类型为 `scanner-404`。

**Bot / 扫描器基础检测：**

T135 不要求完整浏览器指纹，但必须支持基础自动化识别：

- UA 黑名单或可疑 UA：`sqlmap`、`nikto`、`nmap`、`masscan`、`curl`、`python-requests`、`Go-http-client`。
- 高频多路径访问。
- 高频 404。
- 登录失败次数异常。
- 同 IP 同 UA 高频请求。

高级浏览器指纹、JS challenge、设备指纹可以留到后续任务；但 T135 的 `captcha` 动作必须和现有人机验证模块打通，不能只是保存配置。

**后端实现要求：**

- `internal/cc/limiter.go`
  - 支持 `SiteID`、`SourceIP`、`Path`、`UserAgent`、`StatusCode` 输入。
  - 支持 site/path/ua/404/login-failure scope。
  - 支持动作链解析，分隔符兼容 `>`、`,`、`|`。
  - 支持 violation 计数和 active block 短路。
  - 支持 temp-block 默认 10 分钟、long-block 默认 24 小时。

- `internal/database/models.go`
  - `CCPolicy` 支持 scope、threshold、window、action、enabled、siteId、priority。
  - 必要时增加 `PathPattern` 或从 `Scope` 中解析路径。

- `internal/httpserver/console_api.go`
  - CC 策略 CRUD 必须真实读写数据库。
  - API validator 允许 `observe`、`captcha`、`block`、`temp-block`、`long-block` 和动作链字符串。
  - 保存后刷新运行时策略快照。

- `internal/httpserver/server.go`
  - `evaluateCC` 必须传入真实 `User-Agent`。
  - 请求前可执行 site/path/ua 高频判断。
  - upstream 返回后必须能执行 404/login-failure 这类后置判断。
  - `captcha` 必须返回 challenge 或跳转到 challenge 流程。
  - `temp-block` / `long-block` 必须返回 403，并写清楚原因。

- `internal/auditlog` / attack log
  - observe、captcha、temp-block、long-block 都要写安全事件。
  - 事件里记录 policyId、policyName、scope、key、count、threshold、action、blockUntil。

- `internal/dataplane`
  - 对 temp-block / long-block 的 IP，允许写入 fast-block map；Windows/mock 环境至少要有可测 mock 行为。

**前端实现要求：**

防护配置或 CC 防护页面必须提供真实配置入口：

```text
CC / Bot 防护
  ├─ 策略列表
  │   ├─ 策略名称
  │   ├─ 作用站点
  │   ├─ 统计维度 site/path/ua/404/login-failure
  │   ├─ 时间窗口
  │   ├─ 阈值
  │   ├─ 动作链
  │   ├─ 状态
  │   └─ 最近命中次数
  ├─ 新增/编辑策略
  ├─ 启停策略
  └─ 删除策略
```

不能展示假命中次数；没有后端统计时显示 `--` 或“暂无真实命中”。

**验收：**

- [x] 支持 IP+site、IP+path、IP+UA 多维限速。
- [x] 支持登录失败和 404 扫描限速。
- [x] 支持 observe/captcha/temp-block/long-block 动作链。
- [x] 策略通过 API 保存到数据库，不是前端本地状态。
- [x] 策略保存后能进入真实 runtime 请求链路。
- [x] User-Agent 维度不是空字段，真实从请求头传入 limiter。
- [x] 404 策略能基于 upstream 返回状态码触发。
- [x] 登录失败策略能基于登录接口失败状态码触发。
- [x] captcha 动作能接入现有人机验证 challenge/token 闭环。
- [x] temp-block / long-block 生效期间重复请求直接被拦截。
- [x] 命中策略必须写安全事件，事件可被攻击事件/访问统计读取。
- [x] 不允许只做模型、只做页面、只做单元测试后标记完成。

**完成记录：**

- `internal/cc/limiter.go` 基线能力已覆盖 site/path/ua/404/login-failure scope、动作链解析、violation 计数、active temp/long block 短路；本任务重点补齐真实 HTTP runtime 闭环。
- `internal/httpserver/server.go` 新增响应后 CC 评估：请求前只执行 site/path/ua 等前置策略；upstream 返回后再执行 `404/not-found` 与 `login-failure:*` 后置策略，避免同一请求被前后置重复计数。
- `statusRecorder` 改为缓冲 upstream 响应，后置 404/login-failure 命中 block/captcha/temp/long-block 时可覆盖原 upstream 状态并返回 challenge/403；未命中时再 flush 原响应。
- CC 命中统一生成 `pipeline.Result` 检测命中信息，写入 attack log：记录 policyId、policyName、scope、key、count、threshold、action、blockUntil；`404` 映射为 `scanner-404`，`login-failure` 映射为 `login-bruteforce`。
- `console_api.go` 允许 `observe>captcha>temp-block>long-block` 这类动作链通过 `/api/cc-protection` 持久化，兼容 `>`、`,`、`|` 分隔。
- 前端 `CcProtectionView.vue` 和 `api/ccProtection.ts` 已支持 site/path/ua/404/login-failure scope 与动作链输入，不再只暴露 block/captcha/observe 单选。
- 新增 `internal/httpserver/t135_cc_bot_runtime_test.go`：通过真实站点、真实 upstream、真实 API 创建策略，证明 UA 动作链 observe -> captcha -> temp-block、active block 短路、404 后置扫描拦截、login-failure 后置 captcha、策略持久化和攻击事件解释均生效。
- 验证命令：`go test ./internal/cc ./internal/detection ./internal/httpserver ./internal/database` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T137：规则组评分和异常分决策闭环。

**建议测试：**

- `internal/cc`: `TestLimiterIsolatesSitePathAndUserAgentKeys`
- `internal/cc`: `TestLimiterEvaluates404ScopeOnlyForNotFoundStatus`
- `internal/cc`: `TestLimiterEvaluatesLoginFailureScopeOnlyForFailedLogin`
- `internal/cc`: `TestLimiterEscalatesObserveCaptchaTempBlockLongBlock`
- `internal/cc`: `TestLimiterShortCircuitsActiveTempAndLongBlock`
- `internal/httpserver`: `TestT135EvaluateCCForwardsUserAgent`
- `internal/httpserver`: `TestT135CCPolicyCRUDPersistsActionChain`
- `internal/httpserver`: `TestT135RuntimeAppliesCCPolicyToRealRequest`
- `internal/httpserver`: `TestT135NotFoundScanPolicyRunsAfterUpstreamResponse`
- `internal/httpserver`: `TestT135CaptchaActionUsesChallengeFlow`

**验证命令：**

```bash
gofmt -w internal/cc internal/database internal/httpserver internal/auditlog internal/dataplane
go test ./internal/cc -run 'TestLimiter|TestT135' -count=1
go test ./internal/httpserver -run 'TestT135|TestGlobalCaptcha|TestWAF' -count=1
go test ./...
go vet ./...
cd web && npm run build
```

**完成状态更新要求：**

T135 完成后，必须在任务状态或提交说明中明确：

- 已完成哪些 scope。
- 哪些动作已真实接入运行时。
- 404/login-failure 是否为后置检测。
- captcha 是否真实联动人机验证模块。
- temp-block/long-block 是否联动 dataplane fast-block。
- 前端是否已接真实 API。
- 如有未完成项，必须标注为“部分接入”，不能写“完成”。

#### T136：Coraza + OWASP CRS 完整接入

**目标：** 把当前本地 seed/custom 规则升级为可运行的 Coraza + OWASP CRS 引擎，支持 CRS 规则加载、版本管理、paranoia level、anomaly scoring 和审计日志。

**实现要求：**

- 新增 `internal/detection/coraza_engine.go`，封装 Coraza transaction。
- 新增 `internal/detection/coraza_engine_test.go`，覆盖 SQLi/XSS/RCE/LFI/编码绕过基础 CRS 命中。
- 新增 `internal/crs` 或 `internal/rules/crs`，负责 CRS 规则目录、版本、reload、状态查询。
- 保留现有 custom/semantic 规则引擎，但 pipeline 必须支持 Coraza/CRS + custom + semantic 组合执行。
- 配置项至少包含：enabled、rulesDir、paranoiaLevel、inboundThreshold、outboundThreshold、requestBodyLimit、auditLogEnabled、failOpen。

**前端承接：**

- 防护配置 -> 规则管理 / CRS 必须展示 CRS 状态、版本、规则数量、PL、异常分阈值、reload/update 操作。
- 规则详情必须能展示 CRS rule id、tags、severity、score、matched variable。

**验收：**

- [x] 完整 CRS 规则能被加载，不是只加载几条 seed 规则。
- [x] 真实请求触发 CRS 后进入 detection/pipeline；attack log 由既有 `writeLogs` 在命中/拦截时写入。
- [x] 改变 PL 或 threshold 后，同一 payload 的处理结果可变化。
- [x] CRS reload/update 写审计日志。

**完成记录：**

- 新增 `internal/crs/status.go`：扫描 CRS `.conf` 目录，统计版本、文件数、规则数、PL、入站/出站阈值，并支持 reload/status。
- 新增 `internal/detection/coraza_engine.go` 与 `composite_engine.go`：Coraza transaction 接入 OWASP CRS，输出 `source=crs` 命中，并与现有 custom runtime 规则组合执行。
- `internal/config/config.go` 增加 `crs` 配置段和环境变量绑定：enabled、rulesDir、paranoiaLevel、inboundThreshold、outboundThreshold、requestBodyLimit、auditLogEnabled、failOpen。
- `cmd/aegis-waf/main.go` 在 `crs.enabled` 时启用 Coraza + custom 组合引擎；保留 custom rule watcher 和 SIGHUP reload。
- `internal/httpserver` 增加 `/api/protection/crs/status` 与 `/api/protection/crs/reload`，reload 后刷新 detection engine 并写 `crs_reload` audit event；规则集概览展示 CRS 规则集。
- `web/src/api/protection.ts` 与 `web/src/views/ProtectionConfigView.vue` 增加 CRS 状态、版本、规则数、PL、阈值、最近 reload 和 reload 按钮。
- 新增测试：`internal/crs/status_test.go`、`internal/detection/coraza_engine_test.go`、`internal/httpserver/t136_crs_api_test.go`。
- 验证命令：`go test ./internal/crs ./internal/detection ./internal/httpserver ./cmd/aegis-waf` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T137：规则组评分和异常分决策闭环。

#### T137：规则组评分和异常分决策闭环

**目标：** 建立接近 SafeLine 的“规则组 + 分数 + 阈值 + 动作”决策模型，而不是单条规则直接 block。

**实现要求：**

- 统一规则命中结果结构：ruleId、source、group、severity、score、variable、rawValue、normalizedValue、message。
- 建立 group 分类：sqli、xss、rce、lfi、scanner、bot、protocol、custom、semantic。
- 站点策略可启停规则组并配置 inbound/outbound threshold。
- pipeline 根据命中分数累计 anomaly score，再结合站点策略决定 observe/captcha/block/allow。
- 攻击日志记录 scoreBreakdown 和 finalAction。

**前端承接：**

- 规则管理页展示规则组开关、每组规则数、默认分数、站点覆盖状态。
- 攻击事件详情展示评分组成：每条规则加分、总分、阈值、最终动作。

**验收：**

- [x] 同一 payload 在低阈值站点 block，在高阈值站点 observe/allow。
- [x] 禁用某规则组后，该组规则不参与评分。
- [x] 攻击日志可解释评分来源。

**完成记录：**

- `internal/pipeline` 增加异常分阈值后的最终动作闭环：命中规则累计 anomaly score，低于拦截阈值时转为 observe，高于阈值时保持 block，并在结果中保留 `finalAction`。
- `internal/database/models.go`、`internal/auditlog/writer.go` 增加攻击日志评分解释字段：`finalAction` 与 JSON `scoreBreakdown`，记录总分、阈值和逐条规则的 group/id/score。
- `internal/httpserver/console_api.go` 在攻击日志 API 中透出 `finalAction` 和 `scoreBreakdown`，前端无需二次推断最终处置。
- `web/src/api/attackLogs.ts` 与 `web/src/views/AttackLogsView.vue` 增加评分解释类型和详情展示：最终动作、异常总分、异常阈值、逐条规则组/id/分数。
- 新增/更新 T137 定向测试，覆盖低阈值 block、高阈值 observe、规则组禁用不计分、攻击日志评分解释持久化与 API 返回。
- 验证命令：`go test ./internal/pipeline ./internal/auditlog ./internal/httpserver -run 'TestT137|Test.*Attack' -count=1` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T138：站点策略发布、版本和回滚闭环。

#### T138：站点策略发布、版本和回滚闭环（已完成）

**目标：** 把全局配置升级为站点级策略体系，支持默认策略、站点覆盖、发布、版本、回滚和运行时热更新。

**实现要求：**

- 新增或完善 SiteProtectionPolicy、PolicyVersion、PolicyAudit 数据模型。
- 支持 mode：observe、loose、standard、strict、custom。
- 支持站点绑定规则组、CRS PL、异常分阈值、默认动作、CC/Bot 策略、白名单集合。
- SiteRuntime 必须加载站点策略快照，并支持 publish/reload/rollback。
- 所有策略变更写审计日志。

**前端承接：**

- 防护配置顶部站点策略区展示当前模式、版本、运行时状态、最近发布时间。
- 支持保存草稿、发布、回滚、查看审计。

**验收：**

- [x] 站点 A/B 可使用不同规则组、阈值和动作。
- [x] publish 后真实请求立即或下一次请求生效。
- [x] rollback 后真实请求恢复旧策略行为。

**完成记录：**

- `internal/database/models.go` 新增 `SiteProtectionPolicy`、`PolicyVersion`、`PolicyAudit`，`internal/database/database.go` 已加入 AutoMigrate，支持站点策略当前态、发布版本快照和发布/回滚审计持久化。
- `internal/httpserver/console_api.go` 扩展 `/api/protection/site-policies`：支持列表/单站点查询、草稿保存、`publish`、`rollback`、`versions`、`audit`，发布/回滚会同步更新 `Site` 的 `PolicyMode`、`BlockScoreThreshold`、`RuleGroups`、WAF/CC/语义开关并触发 runtime reload。
- 发布会生成唯一 runtime version 和 `PolicyVersion`，回滚按目标版本恢复策略；策略变更同时写入 `PolicyAudit` 与通用 `AuditEvent(type=site_policy)`。
- `web/src/api/protection.ts` 增加站点策略发布、版本、回滚、审计 API；`web/src/views/ProtectionConfigView.vue` 的站点策略表展示运行版本、发布时间，并提供发布、版本/审计查看和回滚入口，全部接真实 API。
- 新增 `internal/httpserver/t138_site_policy_test.go`，用真实站点、真实 runtime、真实规则和真实 HTTP 请求验证：A/B 站点差异策略、发布后热更新生效、版本持久化、回滚后恢复旧拦截行为、策略/版本/审计入库。
- 验证命令：`go test ./internal/pipeline ./internal/auditlog ./internal/httpserver -run 'TestT137|TestT138|Test.*Attack' -count=1` 通过；`cd web && npm run build` 通过（仅 Vite/Rollup 注释与 chunk-size 警告）。

**下一任务：** T139：误报白名单和 CRS Rule Exclusion 闭环。

#### T139：误报白名单和 CRS Rule Exclusion 闭环（已完成）

**目标：** 支持 SafeLine 风格误报处理，从攻击日志一键生成低风险、可审计、可过期的白名单或 CRS exclusion。

**实现要求：**

- [x] 支持白名单类型：url、param、ip、cidr、header、cookie、rule-exclusion。
- [x] 支持作用域：global/site/path/ruleId/variable。
- [x] 支持 expiresAt、reason、createdFrom、enabled。
- [x] 检测 pipeline 在评分前应用精确 rule exclusion，在最终处置前应用白名单策略。
- [x] 白名单命中必须写 audit/security event，不能静默绕过。

**前端承接：**

- [x] 防护配置 -> 误报白名单提供列表、新增、编辑、启停、删除、过期提示。
- [x] 攻击事件详情提供“一键加白”，预填 ruleId、变量、路径、参数和值摘要。

**验收：**

- [x] 同一误报请求在创建白名单前 block，创建后 allow/observe。
- [x] 白名单只影响限定站点/路径/变量，不影响其它攻击。
- [x] 过期或禁用后不再生效。

**完成记录：**

- `internal/database/models.go` 扩展 `AccessRule`：新增 `cidr_whitelist`、`header_whitelist`、`cookie_whitelist` 类型，以及 `scope`、`ruleId`、`variable`、`expiresAt`、`createdFrom` 字段，用统一持久化模型承接白名单和 CRS rule exclusion。
- `internal/accesscontrol/accesscontrol.go` 增加 CIDR/IP、URL、参数、Header、Cookie 白名单匹配；`internal/httpserver/server.go` 在 runtime 快照中按站点、路径、过期时间过滤规则，并在评分前通过 `DisabledRuleIDs` 应用 rule exclusion。
- `internal/httpserver/console_api.go` 扩展 `/api/protection/whitelists` 支持列表、新增、编辑、启停、删除和 siteId/enabled 筛选；攻击日志 `/whitelist-suggestions` 返回 scope/ruleId/variable 等预填字段，`/whitelist` 创建后写审计并热更新 runtime。
- `web/src/api/protection.ts`、`web/src/api/attackLogs.ts`、`web/src/views/ProtectionConfigView.vue` 接入白名单 CRUD、作用域/过期/规则/变量展示和新增/编辑弹窗；攻击事件一键加白会透传后端建议字段。
- 新增 `internal/httpserver/t139_false_positive_test.go`，用真实 runtime 请求验证：创建白名单前 block、站点/路径白名单后 allow、其它站点/路径仍 block、过期白名单不生效、rule exclusion 在评分前禁用命中规则，并校验审计事件。
- 验证命令：`go test ./internal/pipeline ./internal/auditlog ./internal/httpserver -run 'TestT137|TestT138|TestT139|Test.*Attack' -count=1` 通过；`cd web && npm run build` 通过（仅既有 Vite/Rollup 注释和 chunk-size 警告）。

**下一任务：** T140：请求解析和规范化解释闭环。

#### T140：请求解析和规范化解释闭环（已完成）

**目标：** 补齐真实 WAF 必备的 request parser，让 URL、query、header、cookie、JSON、form、multipart、body 都能规范化并进入检测，同时在日志中解释命中原因。

**实现要求：**

- 新增 `internal/requestparser` 或完善现有解析模块。
- 支持 URL decode、HTML entity decode、Unicode decode、重复解码限制、路径清洗、大小写规范化。
- 支持 content-type：json、form-urlencoded、multipart、text/plain、octet-stream 限制读取。
- 记录 rawValue、normalizedValue、decodeSteps、parseErrors、matchedVariable。
- 对解析失败和 body 超限提供 fail-open/fail-closed 策略。

**前端承接：**

- 攻击事件详情展示 raw request 与 normalized request 对照。
- 请求解析 tab 支持粘贴请求样本 preview，返回字段树和规范化步骤。

**验收：**

- 编码绕过 payload 能被规范化后命中规则。
- JSON/multipart/form 字段能作为规则 target。
- 攻击日志能展示命中变量和规范化过程。

**完成记录：**

- `internal/requestparser/requestparser.go` 补齐 URL、query、header、cookie、JSON、form、multipart、text/plain/body 等解析和规范化，保留 raw/normalized/decodeSteps/parseErrors/matchedVariable。
- `internal/httpserver/server.go` 将解析结果接入真实 WAF 请求链路和攻击日志 payload 解释；`/api/protection/request-parser/preview` 提供控制台粘贴样本预览。
- `web/src/views/ProtectionConfigView.vue` 的请求解析面板接入真实 preview API，无数据时展示空态，不返回 mock。
- 新增/更新 `internal/requestparser/requestparser_test.go` 与 `internal/httpserver/t140_request_parser_test.go`，覆盖编码绕过、JSON/form/multipart 字段、日志解释和 preview API。
- 验证命令：`go test ./internal/requestparser ./internal/httpserver -run 'TestRequestParser|TestT140' -count=1` 通过；`cd web && npm run build` 通过（仅既有 Vite/Rollup 注释和 chunk-size 警告）。

**下一任务：** T141：CC / Bot 防护生产化补齐。

#### T141：CC / Bot 防护生产化补齐（已完成）

**目标：** 在 T135 基础上继续做生产化补齐，让 CC/Bot 不只是限速器，而是策略、事件、封禁、人机验证和统计的完整闭环。

**实现要求：**

- 支持策略优先级、全局策略 + 站点策略合并。
- 支持 suspicious UA、固定 UA 高频、多路径扫描、高频 404、登录失败、短时间大量不同 path。
- captcha 动作接入真实 challenge/token 校验。
- temp-block/long-block 与 dataplane fast-block 或 mock fast-block 联动。
- 支持管理员解除封禁。

**前端承接：**

- CC/Bot tab 展示策略、近期命中、当前封禁、解除封禁、动作链解释。
- 访问统计可按 CC/Bot event type 筛选。

**验收：**

- [x] 真实请求触发 observe/captcha/temp-block/long-block。
- [x] captcha 通过后可放行，失败继续拦截或升级。
- [x] 封禁期间重复请求被短路拦截。
- [x] 攻击日志说明 policyId、scope、key、count、threshold、blockUntil。
- [x] 管理员可查看当前 active CC 封禁并按 key/IP 解除封禁。

**完成记录：**

- `internal/cc/limiter.go` 已支持策略优先级排序、全局 + 站点策略合并、active block 快照、按 key 解除封禁和按 IP 批量解除封禁。
- `internal/httpserver/console_api.go` 新增 `/api/protection/cc-blocks`：GET 返回真实 limiter active block 列表，DELETE 支持解除指定 key 或 `ip/<sourceIp>`，并写入审计事件。
- `/api/cc-protection` 策略 API 持久化 `siteId` 与 `priority`，更新时保留既有 hits/createdAt，保存后刷新 runtime 策略快照。
- `web/src/api/ccProtection.ts`、`web/src/stores/ccProtection.ts`、`web/src/views/CcProtectionView.vue` 接入 siteId/priority 字段、当前封禁列表、解除 key/IP 操作，全部调用真实 API。
- `internal/httpserver/t135_cc_bot_runtime_test.go` 扩展真实请求闭环：触发 temp-block 后通过 `/api/protection/cc-blocks` 查到封禁，解除 key 后同 IP/UA 请求恢复进入动作链。
- 验证命令：`gofmt -w internal/httpserver/console_api.go internal/httpserver/t135_cc_bot_runtime_test.go && go test ./internal/cc ./internal/httpserver ./internal/database` 通过；`cd web && npm run build` 通过（仅既有 Vite/Rollup 注释和 chunk-size 警告）。

**下一任务：** T142：攻击日志解释和运营建议闭环。

#### T142：攻击日志解释和运营建议闭环（已完成）

**目标：** 攻击日志不只是列表，而是能解释“命中了什么、为什么拦截、如何处理误报、如何调策略”的运营入口。

**实现要求：**

- [x] attack log 增加 explanation JSON：sitePolicy、matchedRules、scoreBreakdown、requestVariables、normalizationSteps、whitelistDecision、ccBotDecision、semanticDecision、finalAction。
- [x] 增加 operatorSuggestion：加白建议、调阈值建议、启用/禁用规则组建议、封禁建议。
- [x] 支持脱敏和导出，避免泄露密码、token、cookie。
- [x] 支持从攻击日志跳转规则详情、白名单创建、站点策略、CC/Bot 策略。

**前端承接：**

- [x] 攻击事件详情抽屉展示命中时间线、评分组成、payload 对照、白名单/CC/语义决策和建议操作。
- [x] 访问统计能按攻击类型、规则组、动作、站点聚合。

**验收：**

- [x] 每条 block/observe/captcha/temp-block/long-block 事件都有 explanation。
- [x] 管理员能从日志直接执行加白或跳转到策略配置。
- [x] 导出数据已脱敏。

**完成记录：**

- `internal/database/models.go` 扩展 `AttackLog`：新增 `explanationJson` 与 `operatorSuggestion` 持久化字段，和既有 `finalAction`、`scoreBreakdown` 一起承接运营解释数据。
- `internal/auditlog/writer.go` 在真实攻击日志生成时写入 explanation JSON：包含站点策略、命中规则、评分组成、请求变量、规范化步骤、白名单/CC/Bot/语义决策、最终动作和原因；敏感变量按 `password/token/cookie/key` 等字段名持久化前脱敏。
- `internal/auditlog/writer.go` 生成 operatorSuggestion：支持误报加白、站点阈值复核、规则组复核、CC/Bot 策略与语义指纹跳转建议。
- `internal/httpserver/console_api.go` 在攻击日志列表、搜索和导出中透出 explanation/suggestion，并对 payload、explanation、suggestion、CSV 导出统一脱敏。
- `web/src/api/attackLogs.ts` 与 `web/src/views/AttackLogsView.vue` 接入解释和建议字段，详情抽屉展示站点策略、命中规则、请求变量/规范化、白名单/CC/语义决策和建议操作入口。
- 新增 `internal/httpserver/t142_attack_log_explanation_test.go`，用真实站点、规则、编码 payload 和攻击日志 API/CSV 导出验证 explanation、operatorSuggestion、搜索和脱敏闭环。
- 验证命令：`gofmt -w internal/auditlog/writer.go internal/httpserver/console_api.go internal/httpserver/t142_attack_log_explanation_test.go && go test ./internal/auditlog ./internal/httpserver -run 'TestT142|TestT140|TestT139|TestT137|Test.*Attack' -count=1` 通过。

**下一任务：** T143：进入阶段 15 推荐下一步，补齐 T142 之后的新任务拆解或扩展生产化验收。

---

## 15. T142 之后后续优化开发文档

T120-T142 的 SafeLine 对齐与控制台闭环任务已完成。下一阶段从 `T143` 开始，目标不是继续堆页面，而是把现有 WAF 做到“真实可部署、低误报、可解释、可压测、可回滚”。所有后续优化如果涉及前端展示、后端策略、运行时链路、日志统计、部署端口或 API 变化，必须在同一个任务中写清楚联动范围，禁止只改一端。

### 15.1 总体优化方向

优先级从高到低：

1. **部署与监听闭环：** 解决站点 listenPort、HTTPS/443、Docker 端口映射、TLS 证书、运行时监听器热更新之间的断点。
2. **检测准确率：** 在现有 SQLChop/XSSChop 基础上补深度解码、词法分析、轻量 AST、证据评分，减少 entropy-only 误拦。
3. **策略可解释：** 所有 block/observe/captcha/temp-block 必须解释：命中什么、加几分、阈值多少、为什么不是误报。
4. **前端真实闭环：** 控制台只能展示真实 API 数据；配置保存后必须影响 runtime；API 失败展示错误态，不回退 mock。
5. **生产安全：** 支持 fail-open/fail-closed、紧急旁路、配置备份/回滚、灰度发布和健康检查。
6. **性能压测：** 用真实链路测纯反代、规则检测、语义分析、CC/Bot、日志写入和 upstream 慢响应。

### 15.2 后续任务拆解

#### T143：站点监听端口与 HTTPS/443 闭环

**目标：** 让控制台添加/编辑站点时配置的 `listenPort`、`tlsMode`、证书和域名，真实影响 HTTP/HTTPS 监听器；解决“添加站点信息后没有监听 443”的产品断点。

**问题背景：**

当前站点配置已经能保存 `listenPort` / `tlsMode`，但真实监听通常仍由主服务启动参数或 Docker 端口映射决定。只在数据库里保存 `listenPort:443` 不等于进程已经 `ListenAndServeTLS(:443)`，Docker 部署还需要宿主机端口映射，例如 `443:443`。

**后端实现要求：**

- 新增或完善 listener manager，管理 `port -> http.Server` 映射。
- 站点创建/更新/删除后，根据所有启用站点重新计算需要监听的端口集合。
- 支持 HTTP 端口和 HTTPS 端口并存：`tlsMode=off` 使用 HTTP listener，`tlsMode=enabled` 使用 TLS listener。
- 支持 SNI / Host 匹配：同一 443 端口可承载多个 HTTPS 站点。
- 443/80 这类特权端口启动失败时必须返回明确错误，并在控制台展示。
- Docker 部署时必须校验宿主机端口映射是否存在；容器内监听 443 但宿主机未映射时，控制台要提示“容器已监听但宿主机未开放”。
- 站点状态页返回 listener 状态：`configured/listening/error/not-mapped`。
- 监听器变化必须写审计日志：新增监听、关闭监听、TLS 加载失败、端口占用、权限不足。

**建议文件：**

- 修改：`internal/httpserver/server.go`
- 新增：`internal/gateway/listener_manager.go`
- 新增：`internal/gateway/listener_manager_test.go`
- 修改：`internal/httpserver/console_api.go`
- 修改：`internal/database/models.go`
- 修改：`docker-compose.yml`
- 修改：`Dockerfile.backend`
- 修改：`docs/docker-production-deploy.md`

**API 联动：**

```http
GET  /api/sites/{id}/runtime-status
GET  /api/system/listeners
POST /api/system/listeners/reload
```

返回字段至少包含：

```text
port
protocol=http|https
status=listening|error|not-mapped|disabled
siteIds
domains
tlsCertId
tlsError
bindError
dockerPublished
lastReloadAt
```

**前端实现要求：**

- 站点列表增加“监听状态”列：监听中、未监听、端口占用、未映射、证书错误。
- 新增/编辑站点弹窗中，`tlsMode=enabled` 时必须要求选择证书或上传证书。
- 保存站点后自动刷新 runtime status，不允许只提示“保存成功”。
- 如果用户配置 443 但后端未监听，给出明确原因：权限、端口占用、Docker 未映射、证书缺失、TLS 加载失败。
- 系统设置或站点详情页提供 listener 状态面板，展示当前监听端口、协议、绑定站点、错误原因。

**验收：**

- [ ] 新增 `listenPort=8888,tlsMode=off` 站点后，真实进程监听 8888，请求能进入对应站点。
- [ ] 新增 `listenPort=443,tlsMode=enabled` 站点后，真实进程监听 443 或返回可解释错误。
- [ ] Docker 环境未映射 443 时，前端显示 `not-mapped`，不能误报“HTTPS 已生效”。
- [ ] 删除最后一个使用某端口的站点后，该 listener 可关闭或标记空闲。
- [ ] 修改证书后不重启进程即可更新 TLS 配置。
- [ ] `/api/system/listeners` 与站点列表展示一致。

**验证命令：**

```bash
go test ./internal/gateway ./internal/httpserver -run 'TestT143|TestListener' -count=1
go test ./...
cd web && npm run build
```

#### T144：SQLChop/XSSChop 深度检测增强

**目标：** 在已完成的轻量 SQL/XSS 语义信号基础上，形成“深度解码 -> 词法分析 -> 轻量 AST/结构特征 -> 证据评分 -> 可解释日志”的检测链路，提升 SQLi/XSS 变体识别，降低普通高熵内容误报。

**后端实现要求：**

- 请求进入检测前统一走 request parser 的 normalized fields。
- SQLChop 增强：识别 UNION 变体、布尔盲注、时间盲注、注释绕过、函数调用、堆叠语句、宽字节/编码绕过。
- XSSChop 增强：识别 script tag、event handler、javascript/data URL、DOM sink、SVG/MathML、模板注入式 payload。
- entropy 只能作为辅助证据，不能单独 block。
- 每条语义命中必须输出 `group/severity/score/evidence/normalizedValue`。
- 站点策略必须能控制语义检测开关、语义阈值、observe/block 模式。
- 语义命中要进入 attack log explanation 和 scoreBreakdown。

**建议文件：**

- 修改：`internal/detection/semantic.go`
- 修改：`internal/detection/semantic_test.go`
- 修改：`internal/pipeline/pipeline.go`
- 修改：`internal/requestparser/requestparser.go`
- 修改：`internal/auditlog/writer.go`
- 修改：`internal/httpserver/console_api.go`

**前端联动：**

- 防护配置 -> 站点策略增加“语义增强”开关、模式、阈值说明。
- 攻击事件详情展示 SQLChop/XSSChop 的证据列表：原始 payload、规范化 payload、命中 token、结构特征、分数。
- 规则管理中将语义规则 source 标为 `semantic`，不能混到 custom 规则里看不出来源。
- Dashboard / 访问统计支持按 `semantic-sqli`、`semantic-xss` 类型筛选。

**验收：**

- [ ] 编码后的 SQLi/XSS payload 能被规范化后命中。
- [ ] 单纯高熵字符串不因 entropy-only 被拦截。
- [ ] SQL/XSS 语义命中写入 attack log explanation。
- [ ] 站点关闭 `semanticProtection` 后，同 payload 不再因语义阶段拦截。
- [ ] 严格模式比标准模式使用更低语义拦截阈值。

#### T145：防护模式与默认策略产品化

**目标：** 把 `observe/loose/standard/strict/custom` 做成用户能理解、能切换、能验证的站点级防护模式，避免“前端显示默认模式但后端仍是 strict”这类错位。

**后端实现要求：**

- 明确定义 `policyMode` 枚举：`observe/loose/standard/strict/custom`。
- API 保存站点时，未传 `policyMode` 保留原值；传了必须校验并返回保存后的真实值。
- 每种模式绑定默认规则组、阈值、语义开关、CC 开关、默认动作。
- 切换模式后刷新 SiteRuntime，并写策略审计日志。
- 攻击日志必须记录当时生效的 `policyMode`、阈值和 runtime version。

**前端联动：**

- 站点编辑和防护配置页使用相同枚举，不允许中文 label 直接当后端 value。
- 保存后用 API response 回填页面状态，不能只保留本地表单值。
- 模式旁展示影响说明：宽松偏 observe，标准拦常见高危，严格加强语义/CC。
- 如果保存失败或后端返回旧值，前端必须提示策略未生效。

**验收：**

- [ ] 前端选择“标准模式”时，请求 payload 为 `policyMode:"standard"`。
- [ ] 后端返回站点详情也是 `policyMode:"standard"`。
- [ ] 切换 strict/standard 后，同一 payload 决策可按阈值变化。
- [ ] 攻击日志能看到当时生效模式，方便排查误拦。

#### T146：攻击事件误报闭环二次增强

**目标：** 管理员从攻击事件详情能直接完成“确认误报 -> 生成最小作用域白名单 -> 验证生效 -> 审计可追踪”。

**后端实现要求：**

- 攻击事件详情返回 whitelist suggestions，包含推荐类型、站点、路径、参数、规则 ID、过期时间建议。
- 创建白名单默认最小作用域：站点 + path + variable + ruleId。
- 白名单命中必须写 audit/security event。
- 支持一键验证：后端用原事件 payload 重放检测，返回创建白名单前后的决策差异。

**前端联动：**

- 攻击事件详情抽屉增加“误报处理”区。
- 一键加白前展示作用域和风险提示。
- 加白后提供“验证同类请求”按钮，展示 allow/observe/block 变化。
- 白名单页面能反查来源攻击事件。

**验收：**

- [ ] 从攻击事件创建白名单后，限定 payload 放行或 observe。
- [ ] 其它路径、其它参数、其它站点不受影响。
- [ ] 前端能看到白名单来源和审计记录。

#### T147：生产部署与运维验收文档补齐

**目标：** 把开发完成的能力转为可部署、可排障、可回滚的生产说明，避免只在本机测试通过。

**必须补齐文档：**

- `docs/docker-production-deploy.md`：端口映射、443/TLS、环境变量、数据卷、日志目录、健康检查。
- `DEPLOY.md`：单机部署、Docker 部署、升级、回滚、常见故障。
- `README.md`：当前真实完成能力、未完成能力、验证命令。

**运维联动：**

- 后端 `/healthz` 增加 listener、DB、runtime、rule engine、log queue 状态摘要。
- 前端系统设置页展示运行状态，不只显示静态配置。
- Docker compose 默认暴露控制台端口和常用 WAF 入口端口；443 是否开启要和证书配置一致。

**验收：**

- [ ] 按文档从空环境能启动后端、前端、数据库。
- [ ] 能添加 HTTP 站点并真实转发。
- [ ] 能添加 HTTPS/443 站点或得到明确不可用原因。
- [ ] 能通过文档排查端口未监听、Docker 未映射、证书错误、策略未生效。

#### T148：真实链路回归与性能压测

**目标：** 用可重复脚本证明 WAF 在真实链路中可用，并输出性能报告。

**后端/脚本要求：**

- 新增 smoke 脚本：启动测试 upstream、创建站点、发正常请求、发 SQLi/XSS/CC 请求、检查日志和统计。
- 新增 benchmark 脚本：分别测试纯反代、规则检测、语义检测、CC、日志高写入。
- 压测结果保存为文档或报告文件，包含 QPS、P50/P95/P99、CPU、内存、错误率。

**前端联动：**

- 访问统计页能展示压测期间真实请求趋势。
- 攻击事件页能按压测样本筛选攻击类型。
- 系统状态页展示日志队列、rule engine、listener 状态。

**验收：**

- [ ] smoke 脚本一键通过。
- [ ] benchmark 输出报告，不用口头估计性能。
- [ ] 压测期间 access_logs / attack_logs / dashboard 统计一致。
- [ ] 性能报告明确测试环境、配置、命令和结果。


#### T149：常见攻击规则库与 90% 防护率基线（已完成）

**目标：** 不再只补零散规则，而是建立“多类内置规则包 + CRS + 自研语义检测 + 行为检测 + 威胁情报 + 攻击/正常样本集 + 自动评测报告”的规则工程体系。目标不是口头承诺“100% 防住”，而是在可复现公开样本集、常见扫描器 payload、OWASP Top 10、真实误报样本组成的验证集上达到 90%+ 常见攻击阻断率，并控制标准模式误报率。

**市面常见攻击防护范围：**

- 注入类：SQLi、NoSQLi、命令注入、模板注入 SSTI、LDAP/XPath 注入初版规则。
- 前端执行类：XSS、DOM XSS、SVG/MathML XSS、HTML/JS 编码绕过。
- 文件/路径类：路径穿越、LFI/RFI、任意文件读取、文件上传、WebShell。
- 服务端请求类：SSRF、云元数据地址访问、内网地址探测、危险协议 `file/gopher/dict`。
- XML/API 类：XXE、JSON 注入、GraphQL introspection/depth abuse、JWT none alg/畸形 token。
- 协议异常类：重复 Content-Length、Transfer-Encoding 混淆、请求走私特征、异常 header/path/query 长度。
- 自动化攻击类：sqlmap/nuclei/nikto/dirsearch/gobuster/zgrab 等扫描器、404 扫描、登录爆破、API 高频访问。
- CVE 探测类：常见高危路径、Log4Shell/JNDI、Spring/Actuator、PHPUnit、WordPress、Tomcat Manager、Solr 等探测样本。

**后端实现要求：**

- 新增或拆分内置规则包：SQLi、XSS、RCE/命令注入、路径穿越/LFI/RFI、SSRF、XXE、文件上传/WebShell、Scanner/CVE 探测、HTTP 协议异常、API/JSON/GraphQL/JWT 异常、Bot/自动化攻击、常见 CMS/中间件 CVE 探测。
- 推荐规则文件布局：`rules/REQUEST-901-SQLI.conf`、`REQUEST-902-XSS.conf`、`REQUEST-903-RCE.conf`、`REQUEST-904-LFI-RFI-TRAVERSAL.conf`、`REQUEST-905-SSRF.conf`、`REQUEST-906-XXE.conf`、`REQUEST-907-UPLOAD-WEBSHELL.conf`、`REQUEST-908-SCANNER-CVE.conf`、`REQUEST-909-PROTOCOL-ANOMALY.conf`、`REQUEST-910-API-JSON-GRAPHQL-JWT.conf`、`REQUEST-911-BOT-AUTOMATION.conf`。
- 每条规则必须带 `id/name/group/category/severity/score/phase/variable/operator/pattern/action/tags/message/remediation` 等元数据。
- 规则分层：高置信硬规则直接高分；组合规则走 anomaly score；语义规则提供 evidence/normalizedValue/scoreBreakdown。
- 支持规则包热加载、加载失败回滚旧规则、规则包版本展示。
- 建立 `testdata/security-corpus/attacks` 与 `testdata/security-corpus/benign`，覆盖攻击样本、正常样本、编码绕过样本、误报样本。
- 新增安全评测模块，输出总体阻断率、分类阻断率、误报率、漏拦样本、误报样本、命中规则 ID、规则版本和退化项列表。
- 评测指标必须按模式区分：observe 不拦截但记录，standard 追求低误报，strict 提高覆盖率，custom 按用户配置计算。
- 明确防护率目标：总体攻击阻断率 >= 90%；SQLi/XSS/Traversal/Scanner >= 95%；RCE/SSRF/XXE/Upload/API >= 85%；standard 误报率 <= 3%；strict 误报率 <= 5%。

**前端实现要求：**

- 防护配置/规则管理页展示规则包、规则组、规则数量、版本、启停状态、最近更新时间。
- 规则详情抽屉展示规则元数据、命中变量、分数、动作、说明、修复建议和误报处理入口。
- 新增“防护覆盖率”页或卡片，展示最近一次安全评测：总体阻断率、误报率、各攻击类型覆盖率。
- 支持按攻击类型、规则组、严重级别、动作筛选规则。
- API 失败或评测数据不存在时展示明确空态，不允许用假覆盖率。

**验收：**

- [x] 内置规则覆盖 SQLi/XSS/RCE/Traversal/SSRF/XXE/Upload/Scanner/Protocol/API/Bot/CVE 至少 12 类。
- [x] 每个规则包至少包含高置信规则、组合评分规则、正常样本回归和绕过样本回归。
- [x] 安全评测输出 `Attack block rate >= 90%` 与 `standard false positive rate <= 3%`。
- [x] 每类规则至少有攻击样本和正常样本回归测试。
- [x] 规则包 reload 失败时保留旧规则，前端显示失败原因。
- [x] 攻击事件详情能看到命中规则的元数据和解释。

**验证命令：**

```bash
go test ./internal/detection ./internal/pipeline ./internal/httpserver ./internal/securityeval -run 'TestT149|TestSecurityCoverage|TestRulePack' -count=1
go test ./internal/detection ./internal/pipeline ./internal/httpserver ./internal/gateway -count=1
cd web && npm run build
```

**完成记录：**

- 新增 11 个 T149 内置规则包：`REQUEST-901-SQLI.conf` 到 `REQUEST-911-BOT-AUTOMATION.conf`，覆盖 SQLi、XSS、RCE、Traversal/LFI/RFI、SSRF、XXE、Upload/WebShell、Scanner/CVE、Protocol、API/GraphQL/JWT、Bot/Automation；并更新 `REQUEST-900-AEGIS-SEED.conf` 保持 legacy/seed 基线规则可用。
- 新增安全样本库 `testdata/security-corpus/attacks` 与 `testdata/security-corpus/benign`，包含 34 条攻击样本与 15 条良性/误报回归样本，覆盖编码绕过、API、协议、扫描器、上传、SSRF、XXE 等分类。
- 新增 `internal/securityeval` 评测模块和 `cmd/aegis-securityeval` CLI，复用现有 Coraza-backed detection 与 `internal/pipeline`，输出总体阻断率、分类阻断率、误报率、漏拦/误报样本和规则版本。
- 新增 `/api/protection/security-coverage` 与前端防护配置/规则管理页“安全覆盖率”卡片，展示真实评测结果；API 失败时展示错误态，不回退假数据。
- 生成 `docs/security-coverage-report.md`：当前规则文件 12 个、SecRule 73 条、攻击阻断率 94.12%（32/34）、良性误报 0/15，满足 T149 `>=90%` 与误报上限门禁。
- 新增测试 `internal/securityeval/securityeval_test.go`、`internal/httpserver/t149_security_coverage_api_test.go`，验证规则包数量、样本规模、覆盖率门禁、报告字段和 API 输出。
- 验证命令：`go test ./internal/securityeval ./internal/httpserver -run 'TestT149|TestRulePack|TestSecurityCoverage' -count=1` 通过；`go test ./internal/detection ./internal/pipeline ./internal/httpserver ./internal/gateway ./internal/securityeval -count=1` 通过；`npm --prefix web run build` 通过；`go run ./cmd/aegis-securityeval -out docs/security-coverage-report.md` 通过。
- 提交：`6e1e9de8 Expand security rule corpus and coverage gate` 已推送到 `origin/master`。

**边界说明 / 与后续任务融合：**

- T149 已完成“首批可复现规则库 + 样本库 + securityeval 门禁 + 前端覆盖率摘要”。
- T150 继续负责产品化规则管理：单规则启停、score/action 调整、导入导出、规则版本回滚和命中统计。
- T151 继续负责更深层 SQLChop/XSSChop/RCE/SSRF 语义 evidence，不把 T149 的规则包基线误认为全部语义检测完成。
- T155/T156 可复用本次 `internal/securityeval` 与 `docs/security-coverage-report.md`，但仍需补齐情报更新流水线、baseline 对比、退化失败和 CI/持续回归门禁。

**下一任务：** T150：CRS 与自研规则产品化管理。

#### T150：CRS 与自研规则产品化管理

**目标：** 让 CRS、自研规则、语义规则都能在控制台中被理解、搜索、启停、调参和回滚，达到雷池式规则管理体验。

**后端实现要求：**

- 支持 CRS 版本、规则文件、规则组、paranoia level、anomaly threshold 的 API 查询和修改。
- 支持单规则启停、规则组启停、动作调整、score 调整，并写入持久化策略。
- 支持自定义规则 CRUD、导入/导出 YAML/JSON、规则语法校验、测试匹配接口。
- 规则变更必须触发 detection manager 热更新，失败时回滚并记录审计日志。
- 规则命中统计按规则 ID、站点、时间窗口聚合。

**前端实现要求：**

- 防护配置新增“规则库”页签：CRS 规则、自研规则、语义规则、自定义规则分栏。
- 规则表支持搜索、分组、严重级别、启停、动作、命中次数、最近命中时间。
- 规则编辑/导入时先调用后端校验，失败定位到具体字段/行号。
- 每次发布规则变更后展示 runtime version 和热更新结果。
- 提供“回滚上一个规则版本”按钮和确认弹窗。

**验收：**

- [ ] 单条规则禁用后，同 payload 不再命中该规则。
- [ ] 修改规则 score/动作后，真实请求决策随之变化。
- [ ] 导入错误规则不会污染 runtime，前端显示校验错误。
- [ ] 规则回滚后恢复旧行为，并写审计日志。

#### T151：高级语义检测与绕过样本增强

**目标：** 把 SQLChop/XSSChop 扩展为多类攻击的语义增强检测，减少纯正则绕过，提高解释能力。

**后端实现要求：**

- SQLChop 增强 UNION/布尔盲注/时间盲注/注释绕过/函数调用/堆叠语句/宽字节与多重编码识别。
- XSSChop 增强 SVG/MathML、事件处理器、javascript/data URL、DOM sink、模板注入式 payload。
- 新增 RCEChop/SSRFChop/UploadChop/ProtocolChop 的轻量证据模型。
- 所有语义命中必须输出 `evidence/normalizedValue/tokens/structure/score/action`。
- 语义检测受站点模式控制：standard 保守，strict 更敏感，custom 可调阈值。

**前端实现要求：**

- 攻击详情展示语义证据列表、规范化前后 payload、命中 token、结构特征和分数来源。
- 防护策略页支持语义检测开关、模式、阈值、observe/block 动作说明。
- Dashboard 支持按 semantic-sqli、semantic-xss、semantic-rce、semantic-ssrf 类型筛选。

**验收：**

- [ ] 编码/变形 SQLi、XSS、RCE、SSRF 样本可命中。
- [ ] entropy-only 或普通技术文本不被单独拦截。
- [ ] 关闭 semanticProtection 后同 payload 不因语义阶段阻断。
- [ ] 攻击日志完整保存语义 evidence。

#### T152：扫描器、Bot 与自动化攻击防护

**目标：** 对常见扫描器、漏洞探测、404 扫描、登录爆破、API 高频访问形成产品级防护。

**后端实现要求：**

- 建立 scanner/bot 指纹：UA、Header 缺失组合、路径字典、请求节奏、状态码分布。
- 支持 nuclei/sqlmap/nikto/dirsearch/gobuster/zgrab 等常见工具识别。
- 404 高频、登录失败、路径爆破、API 高频访问进入 CC/Bot 策略链。
- 支持 observe/captcha/temp-block/long-block/block 动作链和封禁过期。
- 封禁列表可查询、解封、审计。

**前端实现要求：**

- CC/Bot 页面新增模板：登录防爆破、404 扫描、API 高频、静态资源刷流量、扫描器拦截。
- 展示当前封禁 IP、触发策略、剩余时间、最近请求、解封按钮。
- 展示 Bot/Scanner 趋势图和 Top IP/Top UA/Top Path。
- 攻击事件支持按 scanner/bot/cc/login-bruteforce 分类筛选。

**验收：**

- [ ] sqlmap/nuclei/nikto UA 或典型路径探测能被识别并记录。
- [ ] 404 高频触发后可 temp-block，解封后恢复访问。
- [ ] 登录失败策略只影响指定登录路径，不误伤其它路径。
- [ ] 前端封禁列表与 runtime 状态一致。

#### T153：文件上传、WebShell 与内容检测闭环

**目标：** 补齐上传场景防护，覆盖可执行后缀、双后缀、Content-Type 欺骗、WebShell 关键词和 magic mismatch。

**后端实现要求：**

- 请求解析器提取 multipart 文件名、扩展名、Content-Type、前若干 KB 内容摘要。
- 检测可执行脚本后缀、双后缀、路径穿越文件名、危险 magic/content mismatch。
- WebShell 规则覆盖 PHP/JSP/ASP/ASPX 常见函数与一句话木马模式。
- 支持站点级上传策略：允许扩展名、禁止扩展名、最大大小、observe/block。
- 攻击日志保存文件名、扩展名、Content-Type、命中证据，避免保存完整敏感文件。

**前端实现要求：**

- 防护配置新增“上传防护”区域：扩展名策略、大小限制、WebShell 检测开关、动作。
- 攻击事件详情展示上传文件风险字段和证据。
- 规则管理中上传规则归类为 upload/webshell。

**验收：**

- [ ] `.php`、`.jpg.php`、JSP/ASP WebShell 样本被拦截。
- [ ] 正常图片/文档上传不误拦。
- [ ] 文件名路径穿越被拦截。
- [ ] 上传日志不保存完整文件内容。

#### T154：协议异常、请求走私与 API 安全增强

**目标：** 覆盖 HTTP 协议异常、请求走私特征、JSON/XML/GraphQL/JWT 常见攻击面。

**后端实现要求：**

- 检测重复 Content-Length、Transfer-Encoding 混淆、非法 method、异常 header、path/query/header/body 过长。
- JSON body 进入规则变量，支持嵌套字段命中与日志定位。
- XML 检测 XXE：DOCTYPE、ENTITY、SYSTEM、file/http 外部实体。
- GraphQL 检测 introspection、depth/alias abuse 初版规则。
- JWT 检测 none alg、畸形 token、异常 header/payload 字段。

**前端实现要求：**

- 防护配置新增“协议/API 防护”开关和阈值说明。
- 攻击事件可展示 JSON path、XML 节点、GraphQL operation、JWT header 风险。
- 访问统计支持按 API/Protocol anomaly 类型聚合。

**验收：**

- [ ] XXE、GraphQL introspection abuse、JWT none alg 样本能识别。
- [ ] 正常 JSON/API 请求不误拦。
- [ ] 协议异常日志给出明确字段和原因。

#### T155：威胁情报与规则更新流水线

**目标：** 让规则和威胁情报可以持续更新，而不是一次性写死；规则更新必须形成“获取 -> 校验 -> 评测 -> 发布 -> 回滚 -> 前端可见”的完整流水线，支撑对市面新攻击、新 CVE、新扫描器 payload 的持续防护。

**持续更新范围：**

- 官方/内置规则包版本更新。
- CRS 规则包版本更新。
- 自研语义指纹包更新。
- CVE 探测路径字典更新。
- Scanner/Bot UA 与行为指纹更新。
- 恶意 IP / Tor / 代理出口 / 云元数据防护列表更新。
- WebShell 指纹与上传风险后缀更新。

**后端实现要求：**

- 支持威胁情报源配置：恶意 IP、Tor/代理出口、扫描器 UA、CVE 路径字典。
- 支持手动更新、定时更新、签名/校验、失败回滚。
- 规则包和情报包带版本、来源、更新时间、hash。
- 更新后自动运行安全评测子集，失败则禁止发布到 runtime。
- 支持灰度发布：先 observe 记录命中，再按站点/规则组切到 block。
- 更新过程必须写审计：来源、版本、hash、评测结果、发布人/触发器、发布时间、回滚点。
- 新 CVE 临时规则必须支持 emergency 发布，同时在前端标记为临时规则并要求后续归档。

**前端实现要求：**

- 系统设置新增“规则/情报更新”页：当前版本、来源、更新时间、更新状态、手动更新按钮。
- 展示最近更新日志、失败原因、回滚按钮。
- 显示更新后阻断率/误报率变化。
- 支持查看本次更新新增/删除/修改的规则、影响的规则组、可能影响的站点。
- 当评测退化或误报率上升时，前端必须显示阻断发布原因和“仅 observe 灰度”的选择。

**验收：**

- [ ] 手动更新规则包成功后 runtime 生效且版本变化。
- [ ] hash/格式错误的包不会发布。
- [ ] 更新导致评测退化时阻止上线或要求强确认。
- [ ] 新增规则更新后，前端能看到版本、hash、评测结果和回滚入口。
- [ ] emergency CVE 临时规则能快速发布，并在后续规则库中可追踪。

#### T156：安全覆盖率报告与持续回归门禁

**目标：** 把“能防住 90% 常见攻击”变成 CI/本地都可验证的门禁，而不是口头承诺。

**后端/脚本要求：**

- 新增 `scripts/security_coverage_report.py` 或 Go CLI，读取安全评测输出生成 Markdown/HTML 报告。
- 报告包含分类阻断率、误报率、退化样本、Top missed payload、Top false positives、规则版本。
- 支持 baseline 对比：本次 vs 上次，阻断率下降或误报率上升超过阈值时失败。
- 将报告保存到 `docs/security-coverage-report.md`。

**前端实现要求：**

- Dashboard 或规则中心展示最近一次覆盖率报告摘要。
- 点击分类可跳转到规则/事件列表查看未覆盖样本或误报样本。
- 当覆盖率低于阈值时显示风险提示。

**验收：**

- [ ] 一条命令生成覆盖率报告。
- [ ] 报告中清楚展示总体阻断率、分类阻断率、误报率和规则版本。
- [ ] 覆盖率退化会导致测试失败。
- [ ] 前端展示报告摘要，不使用静态假数据。

#### T157：前端防护中心 1:1 产品化完善

**目标：** 把规则、防护模式、覆盖率、攻击事件、误报处理整合成接近雷池使用习惯的“防护中心”。

**后端实现要求：**

- 提供防护中心汇总 API：站点风险、规则包状态、最近攻击、覆盖率、误报待处理、策略未发布项。
- 所有汇总数据来自真实 DB/runtime/securityeval，不允许样例数据。
- API 返回空态原因和更新时间。

**前端实现要求：**

- 防护中心首页展示：防护站点数、今日攻击、规则覆盖率、误报率、规则包状态、待处理建议。
- 规则中心、攻击事件、误报处理、策略发布之间提供明确跳转路径。
- 删除所有防护相关 mock/fallback 假数据；API 失败时展示错误态和重试。
- 页面布局、筛选、详情抽屉、状态标签尽量贴近雷池。

**验收：**

- [ ] 防护中心数据全部来自真实 API。
- [ ] API 失败不显示假数据。
- [ ] 攻击事件能跳转到规则详情、误报处理、封禁操作。
- [ ] 页面构成可用于演示“规则能力 + 运行态防护 + 覆盖率”。

#### T158：管理认证、权限与安全操作审计

**目标：** 规则和策略变更属于高危操作，必须补齐管理员认证、权限和审计。

**后端实现要求：**

- 初始化管理员账号、密码 hash、登录/session 或 JWT、退出登录、修改密码。
- RBAC：管理员、运维、只读观察者。
- 对站点、规则、策略、白名单、证书、更新、封禁等操作记录审计日志。
- 审计日志保存操作者、IP、User-Agent、对象、动作、修改前后 diff。

**前端实现要求：**

- 登录页、首次初始化页、修改密码页。
- 根据角色隐藏或禁用高危操作。
- 系统设置新增审计日志页，支持筛选对象、动作、操作者、时间。
- 高危操作二次确认，并展示影响范围。

**验收：**

- [ ] 未登录不能访问管理 API。
- [ ] 只读用户不能修改规则/策略。
- [ ] 规则变更审计日志包含 diff。
- [ ] 前端权限与后端权限一致，不能只靠前端隐藏。

#### T159：告警通知与安全运营闭环

**目标：** 让 WAF 不只是被动记录，还能在攻击和系统异常时主动通知。

**后端实现要求：**

- 支持 Webhook/邮件/飞书/企业微信/Telegram 等通知通道的可扩展配置。
- 告警规则：攻击数突增、CC 触发、scanner 爆发、listener 异常、源站不可达、证书快过期、规则更新失败。
- 告警去重、静默窗口、恢复通知。
- 告警发送结果入库，失败可重试。

**前端实现要求：**

- 系统设置新增通知通道配置和测试发送按钮。
- 告警规则页面支持启停、阈值、通道、静默时间。
- 告警历史页展示发送状态、失败原因、关联攻击/系统事件。

**验收：**

- [ ] CC 爆发或 listener 异常能触发告警。
- [ ] 测试通知能显示成功/失败详情。
- [ ] 静默窗口内不会重复刷屏。

#### T160：日志保留、导出与生产数据治理

**目标：** 补齐长期运行所需的数据保留、清理、导出和容量控制。

**后端实现要求：**

- 支持 access log、attack log、audit log 的保留天数配置。
- 后台定时清理过期日志，清理结果写审计/系统事件。
- 支持按站点、时间、攻击类型导出 CSV/JSON。
- 提供数据库大小、日志增长速率、队列积压指标。
- SQLite 到 PostgreSQL/MySQL 的部署说明和迁移策略。

**前端实现要求：**

- 系统设置新增“数据保留”页：各类日志保留天数、当前数据量、预计剩余容量。
- 攻击事件/访问日志/审计日志页面提供导出按钮和导出进度。
- 数据清理高危操作二次确认。

**验收：**

- [ ] 日志保留策略自动清理过期数据。
- [ ] 导出文件内容与筛选条件一致。
- [ ] 前端显示真实数据量和清理结果。

### 15.3 前后端联动总表

| 优化项 | 后端变化 | 前端变化 | 运行时/日志联动 | 验收重点 |
| --- | --- | --- | --- | --- |
| T143 监听/443 | listener manager、TLS/SNI、Docker 映射检测 | 站点监听状态、listener 面板、证书错误提示 | listener reload、审计日志、runtime status | 443 未监听时必须说明真实原因 |
| T144 SQL/XSS 语义增强 | SQLChop/XSSChop、证据评分、normalized fields | 语义开关、证据详情、语义类型筛选 | attack explanation、scoreBreakdown | entropy-only 不拦截 |
| T145 防护模式 | policyMode 枚举、默认策略、runtime version | 模式选择、保存回填、策略说明 | SiteRuntime 热更新、策略审计 | 前端 label 与后端 value 不错位 |
| T146 误报闭环 | whitelist suggestion、最小作用域、重放验证 | 攻击事件一键加白、风险确认、验证按钮 | 白名单命中审计、事件来源反查 | 只放行误报，不扩大绕过面 |
| T147 部署运维 | healthz 状态、Docker/端口/TLS 文档 | 系统运行状态页 | listener/DB/rule/log queue 状态 | 空环境按文档可部署 |
| T148 回归压测 | smoke/benchmark 脚本、报告输出 | 统计页展示真实趋势 | access/attack/dashboard 一致 | 有真实工具输出和报告 |
| T149 规则库与防护率基线 | 多类规则包、安全样本集、自动评测 | 规则包/覆盖率展示、规则详情解释 | securityeval、attack explanation、规则版本 | 攻击阻断率 >=90%，误报率可控 |
| T150 CRS/规则产品化 | CRS 版本、规则启停、动作/score、回滚 | 规则库分栏、搜索、编辑、导入导出 | detection hot reload、审计、命中统计 | 单规则变更影响真实请求 |
| T151 高级语义检测 | SQL/XSS/RCE/SSRF/Upload/Protocol evidence | 语义证据、normalized payload、类型筛选 | scoreBreakdown、semantic runtime policy | 变形攻击命中，entropy-only 不误拦 |
| T152 Scanner/Bot 防护 | 指纹、404/登录/API 高频、封禁链 | CC/Bot 模板、封禁列表、趋势图 | limiter runtime、security events、block expiry | 自动化攻击可识别、可解封 |
| T153 上传/WebShell | multipart 文件风险、WebShell 规则、上传策略 | 上传防护配置、文件证据详情 | upload attack logs、脱敏摘要 | 恶意上传拦截，正常上传不过拦 |
| T154 协议/API 安全 | smuggling/XXE/GraphQL/JWT/JSON path | 协议/API 防护页、字段级证据 | protocol anomaly logs、API 分类统计 | 协议异常可解释 |
| T155 规则/情报更新 | 情报源、签名校验、更新回滚、评测门禁 | 更新中心、版本、失败原因、回滚 | rule/intel version、update audit | 坏包不上线，更新后可验证 |
| T156 覆盖率报告 | 报告生成、baseline 对比、退化失败 | Dashboard/规则中心展示报告摘要 | coverage report、CI gate | 防护率不是口头承诺 |
| T157 防护中心产品化 | 汇总 API、真实 runtime/DB/securityeval 数据 | 防护中心首页、跳转闭环、无 mock | 防护态势、误报待处理、策略未发布 | 前端可演示完整防护能力 |
| T158 认证权限审计 | 管理员、RBAC、操作 diff 审计 | 登录/初始化/RBAC/审计日志页 | audit log、actor/IP/UA/diff | 高危策略变更可追踪 |
| T159 告警通知 | Webhook/邮件/IM、规则、去重、恢复 | 通道配置、告警规则、告警历史 | alert events、send result、retry | 攻击/异常主动通知 |
| T160 日志数据治理 | 保留策略、导出、清理、容量指标 | 数据保留页、导出进度、容量展示 | retention audit、DB size metrics | 长期运行不爆库 |

### 15.4 开发纪律补充

- 每个任务完成后必须更新本章对应完成记录，不能只改代码不改文档。
- 涉及配置保存的任务，必须证明：API 保存 -> 数据库 -> Runtime -> 真实请求 -> 日志/前端可见。
- 涉及前端页面的任务，必须移除 fallback/mock，API 失败展示错误态。
- 涉及检测策略的任务，必须同时写误报样本测试和攻击样本测试。
- 涉及部署/端口/TLS 的任务，必须在 Docker 和本机直跑两种场景说明差异。
- 涉及性能承诺的任务，必须提供真实压测命令和结果，不能写“理论可支持”。
- 涉及“防住 90% 常见攻击”的任务，必须用安全样本集、阻断率、误报率和覆盖率报告证明，不能写绝对承诺；报告必须列出样本来源、规则版本、漏拦样本和误报样本。
- 涉及规则持续更新的任务，必须实现校验、评测、发布、回滚、审计和前端状态展示，不能只写下载/覆盖文件脚本。
- 涉及规则/策略/白名单/封禁/证书/更新的前端入口，必须有后端权限校验和审计日志，不能只靠前端隐藏。
