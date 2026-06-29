# Aegis-WAF

Aegis-WAF 是一个面向高性能场景的 WAF 项目骨架，目标是功能对标雷池个人版，并逐步补齐污点追踪、AST 分析、特征闭环和 XDP 预判能力。

## 当前状态

- 已完成：T000 项目骨架、T001 配置模块（Viper）、T002 日志模块（Zap）、T003 数据库模块（GORM + SQLite/PostgreSQL）、T004 通信层（gRPC/UDS）、T010 数据面骨架（mock）、T011 数据面 XDP/eBPF 适配骨架、T012 Linux-only XDP/eBPF 边界骨架、T013 XDP/eBPF load/attach 路径骨架、T014 eBPF Map 管理模块（语义指纹下刷通道）、T020-T024 检测面 Coraza 规则加载/管理/热更新、T030 SQL AST 解析器、T031 SQL 污点追踪、T032 JS AST 解析器、T033 JS 污点追踪、T034 语法熵值计算模块、T035 Coraza 插件集成、T036 AST骨架提取模块、T037 树编辑距离聚类、T038 指纹→Coraza规则翻译器、T039 eBPF Map 下刷模块、T040 灰度验证+误报回滚控制器、T041 四层数据流水线、T042 请求接收→检测→响应、T050-T058 前端控制台、T060 前后端联调、T061 性能压测脚本与指南、T070-T075 真实站点防护闭环、T080-T082 雷池基础策略能力（访问控制、CC、人机验证最小闭环）、T090 请求规范化、T091 规则评分模式、T092 语义分析按需触发、T100 异步日志队列、T101 配置热加载、T102 XDP/eBPF 快速封禁、T110 前端信息架构重整、T111 防护应用/站点页面复刻、T112 攻击事件页面复刻、T113 访问控制、CC、人机验证页面复刻、T114 统一视觉和交互规范、最小可用版本验收、T120 实战攻击验证集、T121 默认防护策略、T122 攻击日志一键生成白名单/例外规则
- 下一步：T123 请求规范化增强

## 目录结构

- `cmd/aegis-waf`：服务入口
- `configs`：配置示例
- `internal/config`：配置模块
- `internal/logging`：日志模块
- `internal/database`：数据库模块
- `internal/controlplane`：通信控制层
- `internal/dataplane`：数据面
- `internal/detection`：检测面
- `internal/semantic`：语义分析引擎
- `internal/featureloop`：特征闭环
- `internal/pipeline`：请求流水线
- `api`：接口定义
- `web`：前端代码
- `deployments`：部署资源
- `docs`：设计与运维文档
- `rules`：规则文件
- `scripts`：辅助脚本
- `tests`：测试资产

## 配置

配置模块使用 Viper，加载顺序为默认值、YAML 配置文件、环境变量覆盖。环境变量前缀为 `AEGIS_WAF`。

示例配置文件：

```bash
configs/config.example.yaml
```

常用环境变量：

```bash
AEGIS_WAF_SERVER_HOST=127.0.0.1
AEGIS_WAF_SERVER_PORT=9090
AEGIS_WAF_SERVER_MODE=debug
AEGIS_WAF_CONTROL_ENABLED=true
AEGIS_WAF_CONTROL_NETWORK=unix
AEGIS_WAF_CONTROL_ADDRESS=data/aegis-waf.sock
AEGIS_WAF_DATAPLANE_ENABLED=false
AEGIS_WAF_DATAPLANE_MODE=mock
AEGIS_WAF_DATAPLANE_INTERFACE=eth0
AEGIS_WAF_DATAPLANE_XDP_OBJECT_PATH=objects/aegis_waf_xdp.o
AEGIS_WAF_DATAPLANE_XDP_PROGRAM_NAME=aegis_waf_xdp
AEGIS_WAF_DATAPLANE_FAIL_OPEN=true
AEGIS_WAF_SECURITY_MAX_BODY_SIZE=10485760
AEGIS_WAF_SECURITY_ENABLE_SEMANTIC=true
AEGIS_WAF_SECURITY_ENABLE_XDP=false
AEGIS_WAF_DATABASE_DRIVER=sqlite
AEGIS_WAF_DATABASE_DSN=data/aegis-waf.db
AEGIS_WAF_LOGGING_LEVEL=info
AEGIS_WAF_LOGGING_FORMAT=json
AEGIS_WAF_RULES_DIRECTORY=rules
AEGIS_WAF_RULES_CUSTOM_FILES=custom/local.conf,custom/site.conf
AEGIS_WAF_RULES_DISABLED_RULE_IDS=942100,949110
AEGIS_WAF_RULES_AUTO_RELOAD=true
```

## 启动

使用默认配置：

```bash
go run ./cmd/aegis-waf
```

指定配置文件：

```bash
go run ./cmd/aegis-waf -config configs/config.example.yaml
```

## 测试

```bash
go test ./...
```

当前 XDP/eBPF 数据面仍是安全骨架：默认测试不需要 clang、llvm、root、kernel headers、bpf2go 或 CAP_*。Linux 构建标签内已经接入 `github.com/cilium/ebpf` 和 `link.AttachXDP` 的加载/挂载路径，但默认没有配置 eBPF object/program，因此会安全返回缺失对象或程序错误。`dataplane.failOpen=true` 时 XDP 不可用会显式放行，`dataplane.failOpen=false` 时会显式阻断并返回错误。

## 流水线

`internal/pipeline` 提供 T041 四层数据流水线骨架，按顺序编排数据面（XDP/eBPF）、检测面（Coraza 规则引擎）、语义分析（AST + 污点追踪）和特征闭环（学习 + 回滚）。流水线复用现有 `dataplane.Engine`、`detection.Engine` 和 `featureloop` 结果类型，输出统一 `Process(ctx, req) -> Result`，并记录每个阶段与总耗时。阶段错误支持 fail-open 放行继续和 fail-closed 阻断返回。

- `internal/httpserver` 提供 T042 请求接收→检测→响应入口：`/healthz` 直接返回健康状态，其他 HTTP 请求转换为 `pipeline.Request` 后进入流水线。响应使用 JSON，放行返回 200，阻断返回 403，请求体超限返回 413，并带出 decision、reason、blockedByStage 和阶段耗时 metrics。服务入口在 `cmd/aegis-waf` 中组装检测面、可选语义引擎、可选数据面和 HTTP server。

## 性能压测

T061 已补充本地 smoke 压测和 Linux wrk/vegeta 压测入口：

```bash
python scripts/perf_smoke.py --url http://127.0.0.1:9090/?q=1 --requests 1000 --concurrency 32 --duration 10
```

Linux 真实性能压测使用：

```bash
URL=http://127.0.0.1:9090/?q=1 DURATION=30s THREADS=4 CONNECTIONS=256 scripts/perf_linux.sh
```

详细说明见 `docs/performance-t061.md`。Windows smoke 只验证 HTTP 流水线可压测，不代表 XDP/eBPF 性能；真实 XDP 指标必须在 Linux 环境启用 `dataplane.mode=xdp` 后测试。

## 计划中的任务

- T030-T035 语义分析引擎
- T036-T040 特征闭环
- T050-T058 前端控制台
- T060-T073 集成、测试、部署与文档

## Runtime health and operations

The backend exposes production health at `GET /healthz`. The response includes listener ports, database ping status, runtime site/host counts, rule engine counts, and audit log queue depth/drop counts. The console system settings page reads the same live status through `GET /api/settings`.

Deployment acceptance for T147: confirm `database.status=ok`, runtime counts match configured sites, rules are loaded, log queue drops are not increasing, and enabled site `listenPort` values are listening via `GET /api/system/listeners`.
