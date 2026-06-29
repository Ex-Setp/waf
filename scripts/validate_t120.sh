#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" GOPATH="$PWD/.gopath" go test ./internal/httpserver -run 'TestT120RealWorldValidationSet' -count=1 -v
