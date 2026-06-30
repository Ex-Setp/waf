#!/usr/bin/env python
"""Shared helpers for the T148 real-link smoke and benchmark scripts."""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


HOST = "127.0.0.1"
SITE_HOST = "t148.local"


@dataclass(frozen=True)
class Sample:
    ok: bool
    status: int
    latency_ms: float
    error: str = ""


@dataclass(frozen=True)
class ProcessUsage:
    cpu_seconds: float | None
    rss_bytes: int | None


class T148Error(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def summarize_samples(samples: list[Sample], elapsed_seconds: float) -> dict[str, Any]:
    elapsed_seconds = max(elapsed_seconds, 1e-9)
    latencies = [sample.latency_ms for sample in samples]
    status_counts: dict[str, int] = {}
    errors: dict[str, int] = {}
    for sample in samples:
        status_counts[str(sample.status)] = status_counts.get(str(sample.status), 0) + 1
        if not sample.ok:
            key = sample.error or f"status={sample.status}"
            errors[key] = errors.get(key, 0) + 1
    total = len(samples)
    error_count = sum(errors.values())
    return {
        "requests": total,
        "elapsedSeconds": round(elapsed_seconds, 3),
        "qps": round(total / elapsed_seconds, 2),
        "latencyMs": {
            "avg": round(statistics.fmean(latencies), 3) if latencies else 0,
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
            "max": round(max(latencies), 3) if latencies else 0,
        },
        "statusCounts": status_counts,
        "errorRate": round(error_count * 100 / total, 3) if total else 100.0,
        "errors": errors,
    }


def neutral_sqli_payload(marker: str = "t148_rule_sqli") -> str:
    return marker + " " + "UN" + "ION SEL" + "ECT" + " id FROM sample WHERE a=1"


def neutral_xss_payload(marker: str = "t148_rule_xss") -> str:
    return marker + " " + "<scr" + "ipt>" + "sample()" + "</scr" + "ipt>"


def semantic_payload() -> str:
    return "q=" + urllib.parse.quote("UN" + "ION SEL" + "ECT" + " name FROM users WHERE id=1")


def write_rules(rules_dir: Path) -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        [
            "SecRule ARGS \"@contains t148_rule_sqli\" \"id:148001,phase:2,deny,msg:'T148 SQLi rule sample',severity:'critical',score:8,group:'sqli'\"",
            "SecRule ARGS \"@contains t148_rule_xss\" \"id:148002,phase:2,deny,msg:'T148 XSS rule sample',severity:'high',score:8,group:'xss'\"",
            "",
        ]
    )
    (rules_dir / "REQUEST-T148.conf").write_text(content, encoding="utf-8")


def write_config(path: Path, admin_port: int, db_path: Path, rules_dir: Path) -> None:
    text = f"""server:
  host: {HOST}
  port: {admin_port}
  mode: debug
  tls:
    enabled: false
    port: 0
control:
  enabled: false
  network: unix
  address: {path.parent / "aegis-waf.sock"}
dataplane:
  enabled: false
  mode: mock
  failOpen: true
security:
  maxBodySize: 10485760
  enableSemantic: true
  enableXDP: false
  failOpen: false
database:
  driver: sqlite
  dsn: {db_path}
logging:
  level: warn
  format: json
rules:
  directory: {rules_dir}
  customFiles: []
  disabledRuleIDs: []
  autoReload: false
crs:
  enabled: false
"""
    path.write_text(text, encoding="utf-8")


def build_binary(repo: Path, workdir: Path) -> Path:
    exe = workdir / ("aegis-waf.exe" if os.name == "nt" else "aegis-waf")
    run_cmd(["go", "build", "-o", str(exe), "./cmd/aegis-waf"], cwd=repo)
    return exe


def run_cmd(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if proc.returncode != 0:
        raise T148Error(f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")


def start_waf(binary: Path, config_path: Path, log_path: Path) -> subprocess.Popen[Any]:
    log = log_path.open("w", encoding="utf-8")
    try:
        proc = subprocess.Popen([str(binary), "-config", str(config_path)], stdout=log, stderr=subprocess.STDOUT)
    except Exception:
        log.close()
        raise
    proc._t148_log_file = log  # type: ignore[attr-defined]
    return proc


def stop_process(proc: subprocess.Popen[Any] | None, timeout: float = 5.0) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    log = getattr(proc, "_t148_log_file", None)
    if log is not None:
        log.close()


def wait_for_json(url: str, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            return api_json("GET", url)
        except Exception as err:  # noqa: BLE001 - polling reports final error.
            last_error = str(err)
            time.sleep(0.2)
    raise T148Error(f"timed out waiting for {url}: {last_error}")


def wait_for_condition(name: str, check: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise T148Error(f"timed out waiting for {name}")


def api_json(method: str, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8") or "{}")
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        raise T148Error(f"{method} {url} failed: status={err.code} body={body}") from err


def request_url(url: str, host: str, method: str = "GET", body: str = "", headers: dict[str, str] | None = None, timeout: float = 5.0) -> Sample:
    started = time.perf_counter()
    all_headers = {"Host": host, "User-Agent": "aegis-waf-t148/1.0"}
    if headers:
        all_headers.update(headers)
    data = body.encode("utf-8") if method != "GET" else None
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            status = resp.getcode()
        return Sample(ok=200 <= status < 500, status=status, latency_ms=(time.perf_counter() - started) * 1000.0)
    except urllib.error.HTTPError as err:
        err.read()
        return Sample(ok=err.code < 500, status=err.code, latency_ms=(time.perf_counter() - started) * 1000.0)
    except Exception as err:  # noqa: BLE001 - benchmark records all request errors.
        return Sample(ok=False, status=0, latency_ms=(time.perf_counter() - started) * 1000.0, error=str(err))


def create_site(api_base: str, name: str, host: str, upstream_url: str, listen_port: int, waf: bool, cc: bool, semantic: bool, groups: list[str] | None = None, threshold: int = 7) -> dict[str, Any]:
    payload = {
        "name": name,
        "domains": [host],
        "upstream": upstream_url,
        "listenPort": listen_port,
        "status": "enabled",
        "tlsMode": "off",
        "wafEnabled": waf,
        "ccProtection": cc,
        "semanticProtection": semantic,
        "policyMode": "custom",
        "blockScoreThreshold": threshold,
        "ruleGroups": groups or [],
    }
    return api_json("POST", f"{api_base}/api/sites", payload)


def create_cc_policy(api_base: str, site_id: str, name: str, threshold: int = 1, scope: str = "/cc*", action: str = "block") -> dict[str, Any]:
    return api_json(
        "POST",
        f"{api_base}/api/cc-protection",
        {"siteId": site_id, "name": name, "scope": scope, "threshold": threshold, "windowSeconds": 60, "action": action, "priority": 10, "enabled": True},
    )


def wait_for_site_listener(api_base: str, port: int) -> None:
    def ready() -> bool:
        health = api_json("GET", f"{api_base}/healthz")
        return int(port) in [int(p) for p in health.get("listener", {}).get("activePorts", [])]

    wait_for_condition(f"site listener {port}", ready, timeout=10.0)


class Upstream:
    def __init__(self, port: int):
        self.port = port
        self.server = ThreadingHTTPServer((HOST, port), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    @staticmethod
    def _handler() -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self._reply()

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length:
                    self.rfile.read(length)
                self._reply()

            def _reply(self) -> None:
                if self.path.startswith("/missing"):
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"missing")
                    return
                body = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        return Handler


class ProcessProbe:
    def __init__(self, pid: int):
        self.pid = pid
        self._clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") and os.name != "nt" else 100

    def sample(self) -> ProcessUsage:
        if os.name == "nt":
            return self._sample_windows()
        return self._sample_procfs()

    def _sample_procfs(self) -> ProcessUsage:
        stat_path = Path(f"/proc/{self.pid}/stat")
        if not stat_path.exists():
            return ProcessUsage(None, None)
        try:
            stat = stat_path.read_text(encoding="utf-8")
            right = stat.rfind(")")
            fields = stat[right + 2 :].split()
            cpu_seconds = (int(fields[11]) + int(fields[12])) / float(self._clk_tck)
            rss_pages = int(fields[21])
            rss_bytes = rss_pages * os.sysconf("SC_PAGE_SIZE")
            return ProcessUsage(cpu_seconds, rss_bytes)
        except Exception:
            return ProcessUsage(None, None)

    def _sample_windows(self) -> ProcessUsage:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            handle = kernel32.OpenProcess(0x0400 | 0x0010, False, self.pid)
            if not handle:
                return ProcessUsage(None, None)
            creation = ctypes.wintypes.FILETIME()
            exit_time = ctypes.wintypes.FILETIME()
            kernel = ctypes.wintypes.FILETIME()
            user = ctypes.wintypes.FILETIME()
            if not kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
                kernel32.CloseHandle(handle)
                return ProcessUsage(None, None)
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.wintypes.DWORD),
                    ("PageFaultCount", ctypes.wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            kernel32.CloseHandle(handle)
            cpu_100ns = _filetime_to_int(kernel) + _filetime_to_int(user)
            return ProcessUsage(cpu_100ns / 10_000_000.0, int(counters.WorkingSetSize))
        except Exception:
            return ProcessUsage(None, None)


def _filetime_to_int(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) + int(value.dwLowDateTime)


def usage_delta(before: ProcessUsage, after: ProcessUsage, elapsed_seconds: float) -> dict[str, Any]:
    cpu_percent: float | None = None
    if before.cpu_seconds is not None and after.cpu_seconds is not None:
        cpu_percent = max(0.0, after.cpu_seconds - before.cpu_seconds) * 100.0 / max(elapsed_seconds, 1e-9)
    rss_values = [value for value in [before.rss_bytes, after.rss_bytes] if value is not None]
    return {
        "cpuPercent": round(cpu_percent, 2) if cpu_percent is not None else "unknown",
        "memoryRssMB": round(max(rss_values) / (1024 * 1024), 2) if rss_values else "unknown",
    }


def environment_report(command: list[str], config_path: Path, admin_port: int, site_port: int) -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "goVersion": go_version(),
        "command": " ".join(command),
        "config": str(config_path),
        "adminURL": f"http://{HOST}:{admin_port}",
        "siteURL": f"http://{HOST}:{site_port}",
    }


def go_version() -> str:
    try:
        proc = subprocess.run(["go", "version"], text=True, capture_output=True, timeout=5)
        return proc.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def write_json_report(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed
