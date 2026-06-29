# Docker 生产部署说明

## 为什么后端使用 host 网络

WAF 站点管理支持按站点 `listenPort` 动态监听端口，例如站点填 `8888`，后端运行时会启动 `0.0.0.0:8888`。

如果后端容器使用 Docker bridge 网络，容器内部新增监听端口不会自动暴露到宿主机，必须提前写 `ports` 映射。为了实现类似雷池的“添加站点端口即宿主机监听”体验，生产环境后端应使用 host 网络。

## 启动

```bash
docker compose -f deployments/docker-compose.prod.yml up -d
```

## 验证

查看宿主机是否监听站点端口：

```bash
sudo ss -lntp | grep ':8888\b'
```

查看后端进程：

```bash
ps -ef | grep aegis-waf | grep -v grep
```

请求站点端口：

```bash
curl -v -H 'Host: 你的站点域名' http://127.0.0.1:8888/
```

## 注意

- `network_mode: host` 下后端服务端口直接占用宿主机端口。
- 站点端口不能和已有宿主机进程冲突。
- 前端管理台仍通过 `8080:80` 暴露。
- 如果生产机已存在旧容器，需要先停止旧的 `aegis-waf-backend`，否则容器名和端口会冲突。

## T147 production operations acceptance

After starting production compose, verify live operations state:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/settings
curl -fsS http://127.0.0.1:8080/api/system/listeners
```

`/healthz` returns listener, database, runtime/site counts, rule engine, and log queue status. Accept deployment when `database.status` is `ok`, runtime site counts match configured sites, loaded rules are visible, log queue has no growing `droppedAccess`, and every enabled site `listenPort` is reported as listening.
