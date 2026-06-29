# Aegis-WAF 后端 API 接口清单

来源代码：
- `internal/httpserver/server.go`
- `internal/httpserver/console_api.go`
- `internal/controlplane/server.go`
- `api/control/v1/control.go`

更新时间：2026-06-19

## 基础信息

- HTTP 服务默认地址：由配置 `server.host` + `server.port` 决定，端口为空时默认 `8080`。
- HTTP API 前缀：`/api`
- CORS：允许 `GET,POST,PUT,PATCH,DELETE,OPTIONS`，允许 `Content-Type,Authorization`。
- 当前 `/api/*` 控制台接口只接受 `GET`；`OPTIONS` 返回 `204`；其它方法返回 `405`。
- 当前控制台接口数据大多为样例 / Mock 数据，不是数据库实时聚合。

## HTTP 接口总览

| 方法 | 路径 | 说明 | 状态 |
| --- | --- | --- | --- |
| GET | `/healthz` | HTTP 服务健康检查 | 已实现 |
| GET/POST/... | `/*` | WAF 请求处理入口，非 `/api/` 路径都会进入检测流水线 | 已实现 |
| GET | `/api/dashboard/overview` | 控制台首页总览 | 已实现，样例数据 |
| GET | `/api/sites` | 站点列表 | 已实现，样例数据 |
| GET | `/api/attack-logs` | 攻击日志列表 | 已实现，样例数据 |
| GET | `/api/attack-logs/export` | 攻击日志 CSV 导出 | 已实现，样例数据 |
| GET | `/api/access-rules` | 访问控制规则 | 已实现，样例数据 |
| GET | `/api/cc-protection` | CC 防护策略与统计 | 已实现，样例数据 |
| GET | `/api/captcha` | 验证码设置 | 已实现，样例数据 |
| GET | `/api/settings` | 系统设置 | 已实现，部分来自配置 |
| GET | `/api/semantic-fingerprints` | 语义指纹列表 | 已实现，样例数据 |

## 通用错误

### API 路径不存在

`GET /api/unknown`

状态码：`404`

```json
{
  "message": "api endpoint not found"
}
```

### API 方法不允许

非 `GET` / `OPTIONS` 请求 `/api/*`。

状态码：`405`

```json
{
  "message": "method not allowed"
}
```

## 1. 健康检查

### `GET /healthz`

说明：检查 HTTP 服务是否存活。

响应：`200 application/json`

```json
{
  "status": "ok"
}
```

## 2. WAF 请求处理入口

### `ANY /*`

说明：除 `/healthz` 和 `/api/*` 外，所有路径都进入 WAF 检测流水线。

处理流程：
- 读取请求方法、路径、Host、Remote IP、Header、Query、Body、时间戳。
- 调用 pipeline processor。
- 放行返回 `200`。
- 拦截返回 `403`。
- Body 超过 `security.maxBodySize` 返回 `413`。
- Processor 不存在返回 `503`。
- 未被拦截但处理异常返回 `500`。

响应结构：

```json
{
  "decision": "allow | block | observe",
  "reason": "string",
  "blockedByStage": "string",
  "metrics": [
    {
      "stage": "string",
      "durationMs": 1.23,
      "error": "string",
      "decision": "allow | block | observe"
    }
  ],
  "errors": ["string"]
}
```

## 3. 控制台总览

### `GET /api/dashboard/overview`

说明：控制台首页总览数据。

状态：已实现，但当前返回硬编码样例数据。

响应结构：

```json
{
  "status": {
    "service": "Aegis-WAF",
    "version": "dev",
    "uptime": "1h2m3s",
    "mode": "string",
    "health": "ok"
  },
  "metrics": [
    {
      "key": "requests",
      "label": "今日请求",
      "value": 128420,
      "unit": "ms",
      "trend": 12.5,
      "status": "primary"
    }
  ],
  "pipeline": [
    {
      "stage": "dataplane",
      "label": "数据面 XDP/eBPF",
      "qps": 5120,
      "p95Ms": 0.05,
      "blocked": 78,
      "errorRate": 0,
      "enabled": true
    }
  ],
  "attackTrend": [
    {
      "time": "00:00",
      "requests": 8420,
      "blocked": 18
    }
  ],
  "recentEvents": [
    {
      "id": "evt-001",
      "time": "20:42:11",
      "sourceIp": "203.0.113.24",
      "path": "/login",
      "type": "SQL 注入",
      "action": "block",
      "stage": "semantic"
    }
  ]
}
```

当前样例指标：
- `requests`：今日请求
- `blocked`：拦截攻击
- `rules`：规则数量
- `latency`：平均延迟

## 4. 站点列表

### `GET /api/sites`

说明：受保护站点列表。

状态：已实现，当前返回硬编码样例数据。

响应结构：

```json
{
  "summary": {
    "total": 2,
    "enabled": 2,
    "protectedDomains": 3,
    "blockedToday": 189
  },
  "sites": [
    {
      "id": "site-main",
      "name": "主站业务",
      "domains": ["example.com", "www.example.com"],
      "upstream": "http://10.0.0.12:8080",
      "listenPort": 443,
      "status": "enabled",
      "tlsMode": "custom",
      "wafEnabled": true,
      "ccProtection": true,
      "semanticProtection": true,
      "qps": 3280,
      "blockedToday": 126,
      "updatedAt": "2026-06-18 20:40"
    }
  ]
}
```

## 5. 攻击日志

### `GET /api/attack-logs`

说明：攻击日志列表。

状态：已实现，当前返回硬编码样例数据；未处理分页、筛选参数。

响应结构：

```json
{
  "summary": {
    "total": 2,
    "blocked": 2,
    "observed": 0,
    "critical": 1
  },
  "logs": [
    {
      "id": "atk-20260618-0001",
      "time": "2026-06-18 20:42:11",
      "siteName": "主站业务",
      "sourceIp": "203.0.113.24",
      "method": "POST",
      "path": "/login",
      "attackType": "SQL 注入",
      "severity": "critical",
      "action": "block",
      "stage": "semantic",
      "ruleId": "942100",
      "statusCode": 403,
      "latencyMs": 7.8,
      "payloadSnippet": "username=admin' OR '1'='1"
    }
  ],
  "total": 2
}
```

### `GET /api/attack-logs/export`

说明：导出攻击日志 CSV。

状态：已实现，当前返回硬编码 CSV。

响应头：

```http
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="attack-logs.csv"
```

CSV 字段：

```csv
id,time,source_ip,path,attack_type,action
```

## 6. 访问控制规则

### `GET /api/access-rules`

说明：访问控制规则列表。

状态：已实现，当前返回硬编码样例数据。

响应结构：

```json
{
  "rules": [
    {
      "id": "acl-001",
      "type": "ip_blacklist",
      "value": "203.0.113.0/24",
      "description": "扫描器来源网段",
      "status": "enabled",
      "hits": 128,
      "updatedAt": "2026-06-18 20:12"
    }
  ],
  "total": 2
}
```

## 7. CC 防护

### `GET /api/cc-protection`

说明：CC 防护统计与策略列表。

状态：已实现，当前返回硬编码样例数据。

响应结构：

```json
{
  "stats": {
    "qps": 4720,
    "blockedToday": 338,
    "challengedToday": 91,
    "activePolicies": 2
  },
  "policies": [
    {
      "id": "cc-001",
      "name": "登录接口保护",
      "scope": "/login",
      "threshold": 30,
      "windowSeconds": 60,
      "action": "captcha",
      "enabled": true,
      "hitsToday": 74
    }
  ]
}
```

## 8. 验证码设置

### `GET /api/captcha`

说明：验证码能力与触发规则。

状态：已实现，当前返回硬编码样例数据。

响应结构：

```json
{
  "imageCaptcha": true,
  "sliderCaptcha": true,
  "ttlSeconds": 300,
  "maxAttempts": 5,
  "triggers": [
    {
      "id": "cap-001",
      "name": "登录失败保护",
      "condition": "5 分钟内登录失败 ≥ 3 次",
      "method": "slider",
      "enabled": true,
      "passRate": 86.4,
      "challengesToday": 57
    }
  ]
}
```

## 9. 系统设置

### `GET /api/settings`

说明：系统配置摘要。

状态：已实现；部分字段来自运行时配置，部分字段硬编码。

响应结构：

```json
{
  "serverHost": "0.0.0.0",
  "serverPort": 8080,
  "mode": "console",
  "failOpen": true,
  "maxBodySize": 10485760,
  "enableSemantic": true,
  "enableXdp": false,
  "databaseDriver": "sqlite",
  "rulesDirectory": "rules",
  "loggingLevel": "info"
}
```

字段来源：
- `serverHost`：`cfg.Server.Host`
- `serverPort`：`cfg.Server.Port`
- `mode`：`cfg.Server.Mode`
- `maxBodySize`：`cfg.Security.MaxBodySize`
- `enableSemantic`：`cfg.Security.EnableSemantic`
- `enableXdp`：`cfg.Security.EnableXDP`
- `failOpen`、`databaseDriver`、`rulesDirectory`、`loggingLevel`：当前硬编码

## 10. 语义指纹

### `GET /api/semantic-fingerprints`

说明：语义检测指纹列表。

状态：已实现，当前返回硬编码样例数据。

响应结构：

```json
{
  "fingerprints": [
    {
      "id": "fp-001",
      "hash": "a8f23c7d9b12",
      "language": "sql",
      "action": "deny",
      "status": "active",
      "ruleId": 999214,
      "hits": 184,
      "falsePositiveRate": 0.8,
      "source": "AST 聚类",
      "updatedAt": "2026-06-18 20:31"
    }
  ],
  "total": 2
}
```

## gRPC 控制面接口

控制面服务由配置 `control.enabled` 决定是否启动。

- 支持网络：`unix` 或 `tcp`
- 服务名：`aegis.control.v1.ControlService`
- 编码：JSON gRPC codec

### `/aegis.control.v1.ControlService/Health`

说明：控制面健康检查。

请求：

```json
{}
```

响应：

```json
{
  "status": "SERVING",
  "version": "0.1.0-t024"
}
```

## 前端统计报表需要但当前缺失的接口

统计报表页面需要以下真实聚合能力，但当前后端没有独立 API：

| 需求 | 当前是否有真实接口 | 说明 |
| --- | --- | --- |
| 请求次数 | 部分 | `/api/dashboard/overview` 有样例 `requests`，非真实聚合 |
| 访问次数 PV | 否 | 需要访问日志聚合 |
| 独立访客 UV | 否 | 需要访客标识、Cookie、Token 或 IP+UA 策略 |
| 独立 IP | 否 | 当前 AccessLog 模型未存 IP |
| 拦截次数 | 部分 | `/api/dashboard/overview` 有样例 `blocked`，非真实聚合 |
| 攻击 IP | 否 | 当前 AttackLog 模型未存 Source IP |
| 实时 QPS | 部分 | dashboard pipeline / cc-protection 有样例 QPS |
| 4xx/5xx 错误 | 否 | AccessLog 有 Status 字段，但当前未看到请求写入日志 |
| 地图热力图 | 否 | 需要 IP 地理库和国家/省份聚合 |
| Top5 国家 | 否 | 需要 IP 地理库和访问/拦截聚合 |
| 访问/拦截趋势 | 部分 | `/api/dashboard/overview.attackTrend` 为样例趋势 |

建议新增：

```http
GET /api/reports/overview?range=24h|7d|30d
```

建议响应字段：

```json
{
  "range": "24h",
  "securityScore": 67,
  "cards": [
    { "key": "requests", "label": "请求次数", "value": 54280, "unit": "次", "trend": 12.8 },
    { "key": "pv", "label": "访问次数 PV", "value": 1286400, "unit": "次", "trend": 8.6 },
    { "key": "uv", "label": "独立访客 UV", "value": 86730, "unit": "人", "trend": 5.1 },
    { "key": "uniqueIp", "label": "独立 IP", "value": 42916, "unit": "个", "trend": -2.4 },
    { "key": "blocked", "label": "拦截次数", "value": 625318, "unit": "次", "trend": 18.2 },
    { "key": "attackIp", "label": "攻击 IP", "value": 13608, "unit": "个", "trend": 7.4 },
    { "key": "qps", "label": "实时 QPS", "value": 54000, "unit": "qps", "trend": 4.8 },
    { "key": "errors", "label": "4xx/5xx 错误", "value": 2208, "unit": "次", "trend": -1.7 }
  ],
  "geo": {
    "scope": "world",
    "items": [
      { "name": "China", "nameZh": "中国", "visits": 827, "blocked": 394, "longitude": 116.4, "latitude": 39.9 }
    ]
  },
  "topCountries": [
    { "name": "China", "nameZh": "中国", "visits": 827, "blocked": 394 }
  ],
  "trend": [
    { "time": "00:00", "visits": 8420, "blocked": 18 }
  ]
}
```
