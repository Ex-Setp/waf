#!/usr/bin/env python
"""Small dependency-free HTTP smoke benchmark for Aegis-WAF.

This is intended for local readiness checks before running the real T061 Linux
wrk/vegeta benchmark. It measures end-to-end HTTP throughput from the client
process, not kernel/XDP performance.
"""
from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Sample:
    ok: bool
    status: int
    latency_ms: float
    error: str = ""


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def make_request(url: str, method: str, body: bytes, headers: dict[str, str], timeout: float) -> Sample:
    started = time.perf_counter()
    try:
        req = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            status = resp.getcode()
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(ok=200 <= status < 500, status=status, latency_ms=elapsed)
    except urllib.error.HTTPError as err:
        err.read()
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(ok=True, status=err.code, latency_ms=elapsed)
    except Exception as err:  # noqa: BLE001 - benchmark reports all request errors.
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(ok=False, status=0, latency_ms=elapsed, error=str(err))


def run_benchmark(args: argparse.Namespace) -> dict[str, object]:
    deadline = time.perf_counter() + args.duration
    issued = 0
    lock = threading.Lock()
    samples: list[Sample] = []
    headers = {"User-Agent": "aegis-waf-perf-smoke/1.0", "Content-Type": "application/x-www-form-urlencoded"}
    payload = args.body.encode("utf-8")

    def worker() -> Sample | None:
        nonlocal issued
        with lock:
            if issued >= args.requests or time.perf_counter() >= deadline:
                return None
            issued += 1
        return make_request(args.url, args.method, payload, headers, args.timeout)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(worker) for _ in range(args.concurrency)}
        while futures:
            for future in as_completed(futures):
                futures.remove(future)
                sample = future.result()
                if sample is not None:
                    samples.append(sample)
                    with lock:
                        more = issued < args.requests and time.perf_counter() < deadline
                    if more:
                        futures.add(executor.submit(worker))
                break
    elapsed = max(time.perf_counter() - started, 1e-9)

    latencies = [sample.latency_ms for sample in samples]
    status_counts: dict[str, int] = {}
    errors: dict[str, int] = {}
    for sample in samples:
        status_counts[str(sample.status)] = status_counts.get(str(sample.status), 0) + 1
        if not sample.ok:
            errors[sample.error] = errors.get(sample.error, 0) + 1

    return {
        "url": args.url,
        "requests": len(samples),
        "concurrency": args.concurrency,
        "elapsedSeconds": round(elapsed, 3),
        "qps": round(len(samples) / elapsed, 2),
        "latencyMs": {
            "min": round(min(latencies), 3) if latencies else 0,
            "avg": round(statistics.fmean(latencies), 3) if latencies else 0,
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
            "max": round(max(latencies), 3) if latencies else 0,
        },
        "statusCounts": status_counts,
        "errors": errors,
        "success": bool(samples) and not errors,
    }


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local dependency-free Aegis-WAF HTTP smoke benchmark.")
    parser.add_argument("--url", default="http://127.0.0.1:9090/?q=1", help="target URL")
    parser.add_argument("--requests", type=positive_int, default=1000, help="maximum requests to issue")
    parser.add_argument("--concurrency", type=positive_int, default=32, help="concurrent client workers")
    parser.add_argument("--duration", type=float, default=10.0, help="maximum duration in seconds")
    parser.add_argument("--timeout", type=float, default=3.0, help="per-request timeout in seconds")
    parser.add_argument("--method", choices=("GET", "POST"), default="GET", help="HTTP method")
    parser.add_argument("--body", default="username=admin&q=1", help="request body for POST")
    args = parser.parse_args()

    result = run_benchmark(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
