#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_metrics(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    results = {item["name"]: item for item in data.get("results", [])}
    return data, results


def pct_delta(old, new):
    if old == 0:
        return None
    return (new - old) / old * 100.0


def main():
    ap = argparse.ArgumentParser(description="Compare UDPlex(go) and Prismux(rust) metrics")
    ap.add_argument("--go", required=True, dest="go_path")
    ap.add_argument("--rust", required=True, dest="rust_path")
    ap.add_argument("--out", required=True)
    ap.add_argument("--md", required=True)
    args = ap.parse_args()

    go_meta, go_results = load_metrics(Path(args.go_path))
    rust_meta, rust_results = load_metrics(Path(args.rust_path))

    names = sorted(set(go_results) & set(rust_results))
    rows = []
    for name in names:
        g = go_results[name]
        r = rust_results[name]
        row = {
            "name": name,
            "go": {
                "throughput_pps": g.get("throughput_pps", 0.0),
                "mbps": g.get("mbps", 0.0),
                "loss_rate": g.get("loss_rate", 0.0),
                "avg_latency_ms": g.get("avg_latency_ms", 0.0),
                "success": g.get("success", False),
            },
            "rust": {
                "throughput_pps": r.get("throughput_pps", 0.0),
                "mbps": r.get("mbps", 0.0),
                "loss_rate": r.get("loss_rate", 0.0),
                "avg_latency_ms": r.get("avg_latency_ms", 0.0),
                "success": r.get("success", False),
            },
            "delta_pct": {
                "throughput_pps": pct_delta(g.get("throughput_pps", 0.0), r.get("throughput_pps", 0.0)),
                "mbps": pct_delta(g.get("mbps", 0.0), r.get("mbps", 0.0)),
                "loss_rate": pct_delta(g.get("loss_rate", 0.0), r.get("loss_rate", 0.0)),
                "avg_latency_ms": pct_delta(g.get("avg_latency_ms", 0.0), r.get("avg_latency_ms", 0.0)),
            },
        }
        rows.append(row)

    summary = {
        "go_metrics": str(Path(args.go_path)),
        "rust_metrics": str(Path(args.rust_path)),
        "go_timestamp": go_meta.get("timestamp"),
        "rust_timestamp": rust_meta.get("timestamp"),
        "comparisons": rows,
    }

    Path(args.out).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = []
    lines.append("# Prismux vs UDPlex (WSL)\n")
    lines.append(f"- Go metrics: `{args.go_path}`")
    lines.append(f"- Rust metrics: `{args.rust_path}`")
    lines.append("")
    lines.append("| Case | Go Mbps | Rust Mbps | DeltaMbps | Go PPS | Rust PPS | DeltaPPS | Go Loss | Rust Loss |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")

    for row in rows:
        go_mbps = row["go"]["mbps"]
        rs_mbps = row["rust"]["mbps"]
        go_pps = row["go"]["throughput_pps"]
        rs_pps = row["rust"]["throughput_pps"]
        d_mbps = row["delta_pct"]["mbps"]
        d_pps = row["delta_pct"]["throughput_pps"]
        go_loss = row["go"]["loss_rate"] * 100.0
        rs_loss = row["rust"]["loss_rate"] * 100.0

        d_mbps_s = "n/a" if d_mbps is None else f"{d_mbps:+.2f}%"
        d_pps_s = "n/a" if d_pps is None else f"{d_pps:+.2f}%"

        lines.append(
            f"| {row['name']} | {go_mbps:.2f} | {rs_mbps:.2f} | {d_mbps_s} | {go_pps:.0f} | {rs_pps:.0f} | {d_pps_s} | {go_loss:.2f}% | {rs_loss:.2f}% |"
        )

    Path(args.md).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
