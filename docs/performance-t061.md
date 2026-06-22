# T061 性能压测指南

T061 目标：验证 Aegis-WAF HTTP 流水线吞吐、延迟，以及 Linux XDP/eBPF 模式的内核态能力。

## 压测分层

1. Windows / 本地 smoke：验证服务可跑、接口可压、统计格式正确，不代表真实性能上限。
2. Linux mock 数据面：验证 Go HTTP + 检测/语义流水线吞吐。
3. Linux XDP/eBPF 数据面：验证真实高性能路径，才用于验收单核 QPS、P95 延迟和 XDP 指纹匹配延迟。

## Windows smoke

```bash
AEGIS_WAF_SERVER_HOST=127.0.0.1 \
AEGIS_WAF_SERVER_PORT=9090 \
AEGIS_WAF_CONTROL_ENABLED=false \
AEGIS_WAF_DATAPLANE_ENABLED=false \
go run ./cmd/aegis-waf
```

另开终端：

```bash
python scripts/perf_smoke.py --url http://127.0.0.1:9090/?q=1 --requests 1000 --concurrency 32 --duration 10
```

输出 JSON 包含：`qps`、`latencyMs.p95`、状态码分布和错误统计。

## Linux mock 压测

```bash
AEGIS_WAF_SERVER_HOST=127.0.0.1 \
AEGIS_WAF_SERVER_PORT=9090 \
AEGIS_WAF_CONTROL_ENABLED=false \
AEGIS_WAF_DATAPLANE_ENABLED=false \
go run ./cmd/aegis-waf
```

```bash
URL=http://127.0.0.1:9090/?q=1 DURATION=30s THREADS=4 CONNECTIONS=256 scripts/perf_linux.sh
```

## Linux XDP/eBPF 压测

前置条件：Linux、root/CAP_BPF/CAP_NET_ADMIN、clang/llvm、bpftool、网卡名、已编译 eBPF object。

```bash
AEGIS_WAF_SERVER_HOST=127.0.0.1 \
AEGIS_WAF_SERVER_PORT=9090 \
AEGIS_WAF_CONTROL_ENABLED=false \
AEGIS_WAF_DATAPLANE_ENABLED=true \
AEGIS_WAF_DATAPLANE_MODE=xdp \
AEGIS_WAF_DATAPLANE_INTERFACE=eth0 \
AEGIS_WAF_DATAPLANE_XDP_OBJECT_PATH=objects/aegis_waf_xdp.o \
AEGIS_WAF_DATAPLANE_XDP_PROGRAM_NAME=aegis_waf_xdp \
AEGIS_WAF_SECURITY_ENABLE_XDP=true \
go run ./cmd/aegis-waf
```

```bash
URL=http://127.0.0.1:9090/?q=1 DURATION=60s THREADS=8 CONNECTIONS=1024 RATE=10000 scripts/perf_linux.sh
```

## 验收标准

- 单核 QPS：目标 ≥ 5000（Linux 环境用 wrk/vegeta 验证）。
- P95 延迟：目标 ≤ 10ms。
- CC 防护触发响应：目标 ≤ 100ms。
- XDP 语义指纹匹配延迟：目标 ≤ 50μs，需要 Linux + bpftool/自研内核态测量。

## 结果文件

`scripts/perf_linux.sh` 默认写入：

```bash
perf-results/YYYYMMDD_HHMMSS/
```

包含 `summary.txt`、`wrk.txt`、`vegeta.txt`，如果存在 bpftool 还会采集 `bpftool-prog.txt` 和 `bpftool-map.txt`。
