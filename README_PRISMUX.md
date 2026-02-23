# Prismux (Rust Refactor)

## Build

```bash
cargo build --release
```

## Run

```bash
./target/release/prismux -c examples/basic.yaml
```

## Integration Metrics (Rust)

```bash
cd tests/integration
go run udp_integration_rust.go
```

Metrics output:

- `metrics/latest.json`
- `metrics/<timestamp>.json`

## WSL Comparison (UDPlex Go vs Prismux Rust)

```bash
bash scripts/run_wsl_bench.sh
```

Comparison output:

- `metrics/comparison_wsl.json`
- `metrics/comparison_wsl.md`
