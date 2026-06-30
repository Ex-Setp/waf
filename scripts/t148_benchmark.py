#!/usr/bin/env python
"""T148 dependency-free benchmark runner for Aegis-WAF real-link scenarios."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from t148_common import (
    HOST,
    T148Error,
    ProcessProbe,
    Sample,
    Upstream,
    api_json,
    build_binary,
    create_cc_policy,
    create_site,
    environment_report,
    free_port,
    neutral_sqli_payload,
    positive_int,
    repo_root,
    request_url,
    semantic_payload,
    start_waf,
    stop_process,
    summarize_samples,
    usage_delta,
    wait_for_json,
    wait_for_site_listener,
    write_config,
    write_json_report,
    write_rules,
)


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    host: str
    make_url: Callable[[str, int], str]
    method: str = "GET"
    body: str = ""
    headers: dict[str, str] | None = None


def run_benchmark(args: argparse.Namespace) -> dict[str, object]:
    repo = repo_root()
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="aegis-t148-bench-"))
    workdir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report) if args.report else repo / ".tmp" / "t148-reports" / f"t148-benchmark-{time.strftime('%Y%m%d-%H%M%S')}.md"
    admin_port = args.admin_port or free_port()
    site_port = args.site_port or free_port()
    upstream_port = args.upstream_port or free_port()
    rules_dir = workdir / "rules"
    config_path = workdir / "config.yaml"
    db_path = workdir / "aegis-t148-benchmark.db"
    waf_log = workdir / "waf.log"
    upstream = Upstream(upstream_port)
    proc = None
    try:
        write_rules(rules_dir)
        write_config(config_path, admin_port, db_path, rules_dir)
        binary = build_binary(repo, workdir)
        upstream.start()
        proc = start_waf(binary, config_path, waf_log)
        probe = ProcessProbe(proc.pid)
        api_base = f"http://{HOST}:{admin_port}"
        wait_for_json(f"{api_base}/healthz", timeout=20.0)

        scenarios = setup_scenarios(api_base, upstream.url, site_port)
        wait_for_site_listener(api_base, site_port)

        results = []
        for scenario in scenarios:
            result = run_scenario(scenario, site_port, args.requests, args.concurrency, args.timeout, probe)
            results.append(result)
            time.sleep(args.cooldown)

        health = api_json("GET", f"{api_base}/healthz")
        traffic = api_json("GET", f"{api_base}/api/protection/traffic/overview")
        report = {
            "success": True,
            "environment": environment_report(sys.argv, config_path, admin_port, site_port),
            "benchmark": {
                "requestsPerScenario": args.requests,
                "concurrency": args.concurrency,
                "timeoutSeconds": args.timeout,
                "cooldownSeconds": args.cooldown,
            },
            "results": results,
            "runtime": {
                "health": health,
                "trafficOverview": traffic,
                "workdir": str(workdir),
                "wafLog": str(waf_log),
                "reportPath": str(report_path),
            },
        }
        write_markdown_report(report_path, report)
        write_json_report(report_path.with_suffix(".json"), report)
        return report
    finally:
        stop_process(proc)
        upstream.stop()
        if not args.keep_workdir and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def setup_scenarios(api_base: str, upstream_url: str, site_port: int) -> list[Scenario]:
    pure = create_site(api_base, "t148-bench-proxy", "t148-proxy.local", upstream_url, site_port, waf=False, cc=False, semantic=False)
    create_site(api_base, "t148-bench-rule", "t148-rule.local", upstream_url, site_port, waf=True, cc=False, semantic=False, groups=["sqli", "xss"], threshold=7)
    create_site(api_base, "t148-bench-semantic", "t148-semantic.local", upstream_url, site_port, waf=True, cc=False, semantic=True, groups=["semantic"], threshold=7)
    cc = create_site(api_base, "t148-bench-cc", "t148-cc.local", upstream_url, site_port, waf=False, cc=True, semantic=False)
    create_cc_policy(api_base, str(cc["id"]), "t148-bench-cc", threshold=5, scope="/bench/cc*", action="block")
    logwrite = create_site(api_base, "t148-bench-logwrite", "t148-logwrite.local", upstream_url, site_port, waf=False, cc=False, semantic=False)
    return [
        Scenario("pure_reverse_proxy", "WAF disabled site through the real reverse proxy", str(pure_host(pure, "t148-proxy.local")), lambda base, i: f"{base}/bench/proxy?i={i}"),
        Scenario("rule_detection", "Runtime rule engine detection and block path", "t148-rule.local", lambda base, i: f"{base}/bench/rule?q={urllib.parse.quote(neutral_sqli_payload())}&i={i}"),
        Scenario("semantic_detection", "Semantic SQL/XSS structure detection path", "t148-semantic.local", lambda base, i: f"{base}/bench/semantic?{semantic_payload()}&i={i}"),
        Scenario("cc", "CC policy counting and block path", "t148-cc.local", lambda base, i: f"{base}/bench/cc?i={i}"),
        Scenario("high_log_write", "High access log write volume with allowed requests", str(pure_host(logwrite, "t148-logwrite.local")), lambda base, i: f"{base}/bench/logwrite?i={i}"),
    ]


def pure_host(site: dict[str, object], fallback: str) -> str:
    domains = site.get("domains")
    if isinstance(domains, list) and domains:
        return str(domains[0])
    return fallback


def run_scenario(scenario: Scenario, site_port: int, requests: int, concurrency: int, timeout: float, probe: ProcessProbe) -> dict[str, object]:
    base = f"http://{HOST}:{site_port}"
    started_usage = probe.sample()
    started = time.perf_counter()
    samples: list[Sample] = []

    def one(index: int) -> Sample:
        return request_url(scenario.make_url(base, index), scenario.host, method=scenario.method, body=scenario.body, headers=scenario.headers, timeout=timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(one, index) for index in range(requests)]
        for future in concurrent.futures.as_completed(futures):
            samples.append(future.result())

    elapsed = time.perf_counter() - started
    ended_usage = probe.sample()
    summary = summarize_samples(samples, elapsed)
    summary.update(usage_delta(started_usage, ended_usage, elapsed))
    summary.update({"name": scenario.name, "description": scenario.description})
    return summary


def write_markdown_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = report["environment"]  # type: ignore[index]
    bench = report["benchmark"]  # type: ignore[index]
    results = report["results"]  # type: ignore[index]
    runtime = report["runtime"]  # type: ignore[index]
    lines = [
        "# Aegis-WAF T148 Benchmark Report",
        "",
        "## Environment",
        "",
        f"- Platform: {env['platform']}",
        f"- Python: {env['python']}",
        f"- Go: {env['goVersion']}",
        f"- Command: `{env['command']}`",
        f"- Config: `{env['config']}`",
        f"- Admin URL: `{env['adminURL']}`",
        f"- Site URL: `{env['siteURL']}`",
        "",
        "## Configuration",
        "",
        f"- Requests per scenario: {bench['requestsPerScenario']}",
        f"- Concurrency: {bench['concurrency']}",
        f"- Timeout seconds: {bench['timeoutSeconds']}",
        f"- Cooldown seconds: {bench['cooldownSeconds']}",
        "",
        "## Results",
        "",
        "| Scenario | QPS | p50 ms | p95 ms | p99 ms | CPU % | RSS MB | Error % | Statuses |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in results:
        latency = item["latencyMs"]
        statuses = ", ".join(f"{code}:{count}" for code, count in sorted(item["statusCounts"].items()))
        lines.append(
            f"| {item['name']} | {item['qps']} | {latency['p50']} | {latency['p95']} | {latency['p99']} | "
            f"{item['cpuPercent']} | {item['memoryRssMB']} | {item['errorRate']} | {statuses} |"
        )
    lines.extend(
        [
            "",
            "## Runtime Consistency",
            "",
            f"- Health status: `{runtime['health'].get('status')}`",
            f"- Listener: `{json.dumps(runtime['health'].get('listener'), ensure_ascii=False)}`",
            f"- Rule engine: `{json.dumps(runtime['health'].get('ruleEngine'), ensure_ascii=False)}`",
            f"- Log queue: `{json.dumps(runtime['health'].get('logQueue'), ensure_ascii=False)}`",
            f"- Traffic overview: `{json.dumps(runtime['trafficOverview'], ensure_ascii=False)}`",
            f"- Workdir: `{runtime['workdir']}`",
            f"- WAF log: `{runtime['wafLog']}`",
            f"- JSON report: `{runtime['reportPath'].rsplit('.', 1)[0]}.json`",
            "",
            "## Raw JSON",
            "",
            "```json",
            json.dumps(report, ensure_ascii=False, indent=2),
            "```",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run T148 real-link benchmark scenarios and write a report.")
    parser.add_argument("--requests", type=positive_int, default=200, help="requests per scenario")
    parser.add_argument("--concurrency", type=positive_int, default=16, help="concurrent client workers")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-request timeout seconds")
    parser.add_argument("--cooldown", type=float, default=0.5, help="pause between scenarios")
    parser.add_argument("--admin-port", type=int, default=0, help="admin API port; 0 picks a free port")
    parser.add_argument("--site-port", type=int, default=0, help="dynamic site listener port; 0 picks a free port")
    parser.add_argument("--upstream-port", type=int, default=0, help="test upstream port; 0 picks a free port")
    parser.add_argument("--workdir", default="", help="reuse a working directory instead of a temporary one")
    parser.add_argument("--keep-workdir", action="store_true", help="keep temporary config, DB, rules, binary, and logs")
    parser.add_argument("--report", default="", help="Markdown report path; default is .tmp/t148-reports/t148-benchmark-*.md")
    args = parser.parse_args()
    try:
        report = run_benchmark(args)
    except Exception as err:  # noqa: BLE001 - command-line script prints concise failure.
        print(f"T148 benchmark failed: {err}", file=sys.stderr)
        return 1
    print(f"Wrote report: {report['runtime']['reportPath']}")  # type: ignore[index]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
