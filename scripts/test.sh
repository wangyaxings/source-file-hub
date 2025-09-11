#!/usr/bin/env bash
set -euo pipefail

# Ensure we run from repo root
cd "$(dirname "$0")/.."

export DISABLE_HTTPS_REDIRECT=true

echo "Running unit tests with race detector and coverage..."
go test ./... -race -count=1 -coverprofile=coverage.out

echo
echo "Coverage summary:"
go tool cover -func=coverage.out | tail -n 1 || true

echo "Done. Full report in coverage.out (use 'go tool cover -html=coverage.out')."

