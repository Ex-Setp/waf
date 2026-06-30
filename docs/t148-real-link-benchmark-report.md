# T148 真实链路回归与性能压测报告

## 环境

- 平台：Windows-10-10.0.26100-SP0
- Python：3.9.13
- Go：go version go1.25.1 windows/amd64
- Smoke 命令：`python scripts/t148_real_link_smoke.py --report .tmp/t148-reports/t148-smoke-latest.json`
- Benchmark 命令：`python scripts/t148_benchmark.py --requests 12 --concurrency 3 --report .tmp/t148-reports/t148-benchmark-latest.md`

## Smoke 验收结果

真实链路 smoke 已通过。脚本会编译临时 `aegis-waf`，启动测试 upstream，创建真实站点和 CC 策略，通过动态 listener 发请求，并校验 access logs、attack logs、traffic overview、dashboard、healthz 一致性。

本次结果摘要：

- 请求总数：6
- 状态分布：200=2，403=4
- access logs：6
- attack logs：4
- traffic overview：totalRequests=6，blockedRequests=4，blockRate=66.67%
- dashboard：requests=6，blocked=4
- listener：activePorts 包含动态测试端口
- rule engine：ruleCount=2，enabledRuleCount=2
- log queue：queuedAccess=0，queuedAttack=0，droppedAccess=0

## Benchmark 结果

本次 benchmark 使用小样本参数验证脚本闭环和各场景指标输出，不代表生产极限性能。

| Scenario | QPS | p50 ms | p95 ms | p99 ms | CPU % | RSS MB | Error % | Statuses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pure_reverse_proxy | 772.64 | 2.945 | 3.198 | 3.232 | 100.6 | 24.82 | 0.0 | 200:12 |
| rule_detection | 373.31 | 2.089 | 15.7 | 25.096 | 0.0 | 25.95 | 0.0 | 403:12 |
| semantic_detection | 73.41 | 37.59 | 78.559 | 80.151 | 66.91 | 27.52 | 0.0 | 403:12 |
| cc | 261.8 | 4.893 | 24.175 | 25.818 | 34.09 | 28.1 | 0.0 | 200:5, 403:7 |
| high_log_write | 372.03 | 2.587 | 15.957 | 24.852 | 0.0 | 28.23 | 0.0 | 200:12 |

运行时一致性：

- health status：ok
- listener：activeCount=1，configuredSites=5
- rule engine：ruleCount=2，enabledRuleCount=2
- log queue：queuedAccess=0，queuedAttack=0，droppedAccess=0
- traffic overview：totalRequests=60，blockedRequests=31，blockRate=51.67%

## 回归测试命令

```bash
GOCACHE="$PWD/.tmp/gocache" go test ./internal/httpserver -run TestT148 -count=1
GOCACHE="$PWD/.tmp/gocache" go test ./internal/httpserver -run 'TestT127|TestT148' -count=1
GOCACHE="$PWD/.tmp/gocache" go test ./internal/detection ./internal/pipeline ./internal/httpserver -run 'TestT148|TestT147|TestT146|TestT145|TestT144' -count=1
python scripts/t148_real_link_smoke.py --report .tmp/t148-reports/t148-smoke-latest.json
python scripts/t148_benchmark.py --requests 12 --concurrency 3 --report .tmp/t148-reports/t148-benchmark-latest.md
```

## 注意事项

- `.tmp/t148-reports/` 是本地运行产物，不需要提交。
- benchmark 默认输出 Markdown 和同名 JSON，方便后续 CI 或线上环境留档。
- 本次同时修复了 upstream 请求在响应体读取完成前取消 context 的问题，否则高并发 benchmark 会出现 `IncompleteRead`，导致真实反代/日志写入场景误报错误率。
