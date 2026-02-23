# Prismux (Rust Refactor)

## Build

```bash
cargo build --release
```

## Run

```bash
./target/release/prismux -c examples/basic.yaml
```

## Docker

```bash
docker build -t prismux:local .
docker run --rm prismux:local
```

Use your own config:

```bash
docker run --rm -v "$PWD/examples:/configs" prismux:local -c /configs/basic.yaml
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

## GitHub Actions

- `.github/workflows/nightly.yml`: build/test + publish `ghcr.io/<owner>/prismux:dev` and `nightly-<sha>`
- `.github/workflows/release.yml`: on `v*` tag, publish release asset and Docker tags (`vX.Y.Z`, `vX.Y`, `vX`, `latest`)
