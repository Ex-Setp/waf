# Aegis WAF v1 Docker 部署包

这是整理后的线上 Docker 部署目录，只保留运行和构建必需文件，已排除测试文件、缓存、node_modules、临时数据和本地数据库。

## 目录说明

```text
api/                 后端 API 类型/包
cmd/aegis-waf/       后端启动入口
configs/             生产配置
internal/            后端业务代码，不含 *_test.go
rules/               自定义规则目录
web/                 前端源码，不含 node_modules/dist
Dockerfile.backend   后端镜像构建文件
Dockerfile.frontend  前端镜像构建文件
docker-compose.yml   一键部署编排
deployments/nginx.conf 前端 Nginx + /api 反代配置
data/                SQLite 数据、ACME 缓存、运行时文件；线上持久化
```

## 启动

在本目录执行：

```bash
docker compose up -d --build
```

访问：

```text
控制台: http://服务器IP:8088/
后端 API: http://服务器IP:8080/api/...
站点转发: 使用控制台里配置的监听端口直接访问，例如 http://服务器IP:18080/
```

默认端口：

| 服务 | 宿主机端口 | 容器端口 | 说明 |
| --- | --- | --- | --- |
| frontend | 8088 | 80 | 控制台页面，Nginx 反代 /api |
| backend | 8080 + 站点监听端口 | host 网络 | WAF 后端 API / 动态站点反向代理入口 |

## 站点转发端口

后端容器默认使用 `network_mode: host`，这是为了实现雷池式体验：客户在控制台新增站点并填写监听端口后，后端会直接在宿主机监听该端口，不需要客户手动修改 `docker-compose.yml` 的 `ports`。

示例：控制台新增站点 `test.local`，监听端口 `18080`，上游 `http://example-app:80` 后，可直接测试：

```bash
curl -H 'Host: test.local' http://服务器IP:18080/
```

如果宿主机防火墙或云安全组未放行该端口，需要在系统/云平台放行；不需要改 compose。

## 停止

```bash
docker compose down
```

停止但保留数据：不会删除 `./data`。

## 重新构建

```bash
docker compose build --no-cache
docker compose up -d
```

## 查看日志

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

## 数据持久化

默认使用 SQLite：

```text
./data/aegis-waf.db
```

请备份 `data/`、`configs/`、`rules/`。

## 修改配置

生产配置文件：

```text
configs/config.docker.yaml
```

常用项：

| 配置 | 含义 | 默认 |
| --- | --- | --- |
| `server.port` | 后端监听端口 | `8080` |
| `database.dsn` | SQLite 数据库路径 | `/app/data/aegis-waf.db` |
| `rules.directory` | 规则目录 | `/app/rules` |
| `security.enableSemantic` | 语义检测 | `true` |
| `dataplane.enabled` | XDP/eBPF 快速封禁 | `false` |
| `crs.enabled` | OWASP CRS/Coraza | `false` |

修改后重启：

```bash
docker compose restart backend
```

## CRS / eBPF 说明

本部署包默认关闭 CRS 和 eBPF：

- `crs.enabled: false`
- `dataplane.enabled: false`

这样普通 Docker 环境可直接启动。

如果要启用 CRS，需要准备 CRS 规则目录并调整 `configs/config.docker.yaml`。

如果要启用 eBPF/XDP，需要 Linux 内核能力、网卡名、权限和挂载配置，不建议第一次上线直接开启。

## 健康检查

```bash
docker compose ps
curl http://127.0.0.1/healthz
```

`/healthz` 是前端 Nginx 健康检查。

后端可检查：

```bash
curl http://127.0.0.1:8080/api/dashboard/overview
```

## 注意

1. 该目录是部署包，不包含测试文件。
2. 不要把 `web/node_modules` 放进来，镜像构建时会自动 `npm ci`。
3. 不要把本地 `.db` 数据库文件提交到镜像，线上数据在 `data/` volume。
4. 默认配置适合先跑通 Docker；生产域名、HTTPS、CRS、eBPF 可后续逐步开启。
