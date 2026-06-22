#!/usr/bin/env bash
set -euo pipefail

# T061 Linux performance benchmark wrapper for Aegis-WAF.
# Requires wrk and/or vegeta on PATH. Run on a Linux host for real XDP/eBPF tests.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="${URL:-http://127.0.0.1:9090/?q=1}"
DURATION="${DURATION:-30s}"
THREADS="${THREADS:-4}"
CONNECTIONS="${CONNECTIONS:-256}"
RATE="${RATE:-5000}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/perf-results/$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$OUT_DIR"

printf 'Aegis-WAF T061 benchmark\n' | tee "$OUT_DIR/summary.txt"
printf 'url=%s duration=%s threads=%s connections=%s rate=%s\n' "$URL" "$DURATION" "$THREADS" "$CONNECTIONS" "$RATE" | tee -a "$OUT_DIR/summary.txt"
printf 'uname=%s\n' "$(uname -a)" | tee -a "$OUT_DIR/summary.txt"

if command -v wrk >/dev/null 2>&1; then
  wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" --latency "$URL" | tee "$OUT_DIR/wrk.txt"
else
  echo 'wrk not found; skipping wrk run' | tee "$OUT_DIR/wrk.txt"
fi

if command -v vegeta >/dev/null 2>&1; then
  printf 'GET %s\n' "$URL" | vegeta attack -duration="$DURATION" -rate="$RATE" | tee "$OUT_DIR/vegeta.bin" | vegeta report | tee "$OUT_DIR/vegeta.txt"
else
  echo 'vegeta not found; skipping vegeta run' | tee "$OUT_DIR/vegeta.txt"
fi

if command -v bpftool >/dev/null 2>&1; then
  bpftool prog show > "$OUT_DIR/bpftool-prog.txt" || true
  bpftool map show > "$OUT_DIR/bpftool-map.txt" || true
fi

printf 'results=%s\n' "$OUT_DIR" | tee -a "$OUT_DIR/summary.txt"
