#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup_ports() {
  pkill -f "/target/release/prismux" || true
  pkill -f "/udplex_test" || true
}

run_with_retry() {
  local title="$1"
  shift
  local attempt=1
  local max_attempts=2
  while true; do
    echo "$title (attempt $attempt/$max_attempts)"
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -ge "$max_attempts" ]]; then
      return 1
    fi
    cleanup_ports
    sleep 2
    attempt=$((attempt + 1))
  done
}

cleanup_ports

echo "[1/4] Running UDPlex (Go) integration benchmarks..."
run_with_retry "UDPlex benchmark" bash -lc "
  cd \"$ROOT_DIR/UDPlex/tests/integration\"
  go run udp_integration.go
"

echo "[2/4] Running Prismux (Rust) integration benchmarks..."
run_with_retry "Prismux benchmark" bash -lc "
  cd \"$ROOT_DIR/tests/integration\"
  go run udp_integration_rust.go
"

mkdir -p "$ROOT_DIR/metrics"

echo "[3/4] Comparing metrics..."
python3 "$ROOT_DIR/scripts/compare_metrics.py" \
  --go "$ROOT_DIR/UDPlex/metrics/latest.json" \
  --rust "$ROOT_DIR/metrics/latest.json" \
  --out "$ROOT_DIR/metrics/comparison_wsl.json" \
  --md "$ROOT_DIR/metrics/comparison_wsl.md"

echo "[4/4] Done"
echo "- JSON: $ROOT_DIR/metrics/comparison_wsl.json"
echo "- Markdown: $ROOT_DIR/metrics/comparison_wsl.md"
