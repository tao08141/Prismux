#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PERF_BIN="/usr/lib/linux-tools/5.15.0-170-generic/perf"
OUT_DATA="$ROOT_DIR/metrics/perf_auth_only.data"
OUT_SCRIPT="$ROOT_DIR/metrics/perf_auth_only.script"
OUT_FOLDED="$ROOT_DIR/metrics/perf_auth_only.folded"
OUT_SVG="$ROOT_DIR/metrics/perf_auth_only.svg"
OUT_REPORT="$ROOT_DIR/metrics/perf_auth_only_report.txt"

cd "$ROOT_DIR"

RUSTFLAGS="-A dead_code" cargo build --release --bin prismux

pkill -f "/target/release/prismux" || true
sleep 1

./target/release/prismux -c examples/auth_server.yaml >/tmp/prismux_auth_server.log 2>&1 &
S_PID=$!
./target/release/prismux -c examples/auth_client.yaml >/tmp/prismux_auth_client.log 2>&1 &
C_PID=$!

cleanup() {
  kill "$S_PID" "$C_PID" 2>/dev/null || true
  wait "$S_PID" 2>/dev/null || true
  wait "$C_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 3

sudo "$PERF_BIN" record -F 199 -g --call-graph dwarf -p "${S_PID},${C_PID}" -o "$OUT_DATA" -- \
python3 - <<'PY'
import socket
import threading
import time

recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv.bind(("127.0.0.1", 5201))
recv.settimeout(0.05)
stop = False

def receiver():
    while not stop:
        try:
            recv.recvfrom(4096)
        except Exception:
            pass

t = threading.Thread(target=receiver, daemon=True)
t.start()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"x" * 1068
end = time.time() + 15
sent = 0
while time.time() < end:
    s.sendto(payload, ("127.0.0.1", 5202))
    sent += 1

stop = True
t.join(timeout=1)
print(f"sent={sent}")
PY

sudo "$PERF_BIN" script -i "$OUT_DATA" > "$OUT_SCRIPT"
inferno-collapse-perf "$OUT_SCRIPT" > "$OUT_FOLDED"
inferno-flamegraph "$OUT_FOLDED" > "$OUT_SVG"
sudo "$PERF_BIN" report -i "$OUT_DATA" --stdio --no-children --percent-limit 0.05 --sort symbol > "$OUT_REPORT"

echo "Generated:"
echo "  $OUT_DATA"
echo "  $OUT_SCRIPT"
echo "  $OUT_FOLDED"
echo "  $OUT_SVG"
echo "  $OUT_REPORT"
