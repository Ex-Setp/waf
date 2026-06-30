#!/usr/bin/env python
"""T148 repeatable real-link smoke test for Aegis-WAF."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

from t148_common import (
    HOST,
    SITE_HOST,
    T148Error,
    Upstream,
    api_json,
    build_binary,
    create_cc_policy,
    create_site,
    environment_report,
    free_port,
    neutral_sqli_payload,
    neutral_xss_payload,
    repo_root,
    request_url,
    start_waf,
    stop_process,
    wait_for_json,
    wait_for_site_listener,
    write_config,
    write_json_report,
    write_rules,
)


def run_smoke(args: argparse.Namespace) -> dict[str, object]:
    repo = repo_root()
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="aegis-t148-smoke-"))
    workdir.mkdir(parents=True, exist_ok=True)
    admin_port = args.admin_port or free_port()
    site_port = args.site_port or free_port()
    upstream_port = args.upstream_port or free_port()
    rules_dir = workdir / "rules"
    config_path = workdir / "config.yaml"
    db_path = workdir / "aegis-t148-smoke.db"
    waf_log = workdir / "waf.log"
    upstream = Upstream(upstream_port)
    proc = None
    try:
        write_rules(rules_dir)
        write_config(config_path, admin_port, db_path, rules_dir)
        binary = build_binary(repo, workdir)
        upstream.start()
        proc = start_waf(binary, config_path, waf_log)
        api_base = f"http://{HOST}:{admin_port}"
        wait_for_json(f"{api_base}/healthz", timeout=20.0)

        site = create_site(
            api_base,
            "t148-smoke",
            SITE_HOST,
            upstream.url,
            site_port,
            waf=True,
            cc=True,
            semantic=True,
            groups=["sqli", "xss", "semantic"],
            threshold=7,
        )
        create_cc_policy(api_base, str(site["id"]), "t148-smoke-cc", threshold=1, scope="/cc*", action="block")
        wait_for_site_listener(api_base, site_port)

        base = f"http://{HOST}:{site_port}"
        samples = [
            request_url(f"{base}/normal?case=allow", SITE_HOST),
            request_url(f"{base}/search?q={urllib.parse.quote(neutral_sqli_payload())}", SITE_HOST),
            request_url(
                f"{base}/comment",
                SITE_HOST,
                method="POST",
                body="body=" + urllib.parse.quote(neutral_xss_payload()),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
        ]
        for idx in range(3):
            samples.append(request_url(f"{base}/cc-sample?i={idx}", SITE_HOST))

        expected_requests = len(samples)
        api_site = urllib.parse.quote("t148-smoke")

        def access_ready() -> bool:
            logs = api_json("GET", f"{api_base}/api/access-logs?site={api_site}&pageSize=100")
            return int(logs.get("total", 0)) >= expected_requests

        deadline = time.time() + 10.0
        while time.time() < deadline and not access_ready():
            time.sleep(0.2)

        access_logs = api_json("GET", f"{api_base}/api/access-logs?site={api_site}&pageSize=100")
        attack_logs = api_json("GET", f"{api_base}/api/attack-logs?site={api_site}&pageSize=100")
        traffic = api_json("GET", f"{api_base}/api/protection/traffic/overview?site={api_site}")
        dashboard = api_json("GET", f"{api_base}/api/dashboard/overview")
        health = api_json("GET", f"{api_base}/healthz")
        filters = {
            attack_type: api_json("GET", f"{api_base}/api/protection/attack-events?site={api_site}&attackType={attack_type}")
            for attack_type in ("sqli", "xss", "cc")
        }

        validate_smoke(samples, access_logs, attack_logs, traffic, dashboard, health, filters, expected_requests)
        result: dict[str, object] = {
            "success": True,
            "environment": environment_report(sys.argv, config_path, admin_port, site_port),
            "workdir": str(workdir),
            "statusCounts": status_counts(samples),
            "accessLogs": {"total": access_logs["total"]},
            "attackLogs": {"total": attack_logs["total"], "summary": attack_logs.get("summary", {})},
            "trafficOverview": traffic,
            "dashboardMetrics": dashboard.get("metrics", []),
            "health": {
                "status": health.get("status"),
                "listener": health.get("listener"),
                "ruleEngine": health.get("ruleEngine"),
                "logQueue": health.get("logQueue"),
            },
        }
        if args.report:
            write_json_report(Path(args.report), result)
        return result
    finally:
        stop_process(proc)
        upstream.stop()
        if not args.keep_workdir and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def validate_smoke(
    samples: list[object],
    access_logs: dict[str, object],
    attack_logs: dict[str, object],
    traffic: dict[str, object],
    dashboard: dict[str, object],
    health: dict[str, object],
    filters: dict[str, dict[str, object]],
    expected_requests: int,
) -> None:
    statuses = [getattr(sample, "status") for sample in samples]
    if statuses[0] != 200:
        raise T148Error(f"normal request status={statuses[0]}, want 200")
    if not any(status == 403 for status in statuses[1:]):
        raise T148Error(f"expected at least one blocked sample, got statuses={statuses}")
    access_total = int(access_logs.get("total", 0))
    attack_total = int(attack_logs.get("total", 0))
    if access_total < expected_requests:
        raise T148Error(f"access log total={access_total}, want >= {expected_requests}")
    if attack_total < 4:
        raise T148Error(f"attack log total={attack_total}, want >= 4")
    if int(traffic.get("totalRequests", 0)) != access_total:
        raise T148Error(f"traffic totalRequests={traffic.get('totalRequests')} does not match access total={access_total}")
    if int(traffic.get("blockedRequests", 0)) <= 0:
        raise T148Error(f"traffic blockedRequests should be positive: {traffic}")
    metrics = {item.get("key"): item.get("value") for item in dashboard.get("metrics", []) if isinstance(item, dict)}
    if int(metrics.get("requests", 0)) != access_total:
        raise T148Error(f"dashboard requests={metrics.get('requests')} does not match access total={access_total}")
    if int(metrics.get("blocked", 0)) != attack_total:
        raise T148Error(f"dashboard blocked={metrics.get('blocked')} does not match attack total={attack_total}")
    if health.get("status") not in {"ok", "degraded"}:
        raise T148Error(f"unexpected health status: {health}")
    for attack_type, response in filters.items():
        if int(response.get("total", 0)) <= 0:
            raise T148Error(f"attackType filter {attack_type!r} returned no events")


def status_counts(samples: list[object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sample in samples:
        status = str(getattr(sample, "status"))
        counts[status] = counts.get(status, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Run T148 real-link WAF smoke against a temporary upstream and site.")
    parser.add_argument("--admin-port", type=int, default=0, help="admin API port; 0 picks a free port")
    parser.add_argument("--site-port", type=int, default=0, help="dynamic site listener port; 0 picks a free port")
    parser.add_argument("--upstream-port", type=int, default=0, help="test upstream port; 0 picks a free port")
    parser.add_argument("--workdir", default="", help="reuse a working directory instead of a temporary one")
    parser.add_argument("--keep-workdir", action="store_true", help="keep temporary config, DB, rules, binary, and logs")
    parser.add_argument("--report", default="", help="optional JSON report path")
    args = parser.parse_args()
    try:
        result = run_smoke(args)
    except Exception as err:  # noqa: BLE001 - command-line script prints concise failure.
        print(f"T148 smoke failed: {err}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
