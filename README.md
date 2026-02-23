# Prismux (Rust Refactor)

[English](README.md) | [中文](README_ZH.md)

Prismux is a Rust refactor of UDPlex-style UDP multiplexing and forwarding with modular components.

## Quick Start

Build:

```bash
cargo build --release
```

Run:

```bash
./target/release/prismux -c examples/basic.yaml
```

Docker:

```bash
docker run -d --name prismux --network host \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/tao08141/prismux:latest
```

## Documentation

- [Documentation Index](docs/README_EN.md)
- [Global Configuration](docs/config_en.md)
- [Listen Component](docs/listen_en.md)
- [Forward Component](docs/forward_en.md)
- [Filter Component](docs/filter_en.md)
- [Load Balancer Component](docs/load_balancer_en.md)
- [IP Router Component](docs/ip_router_en.md)
- [TCP Tunnel Listen Component](docs/tcp_tunnel_listen_en.md)
- [TCP Tunnel Forward Component](docs/tcp_tunnel_forward_en.md)
- [Auth Protocol](docs/auth_protocol_en.md)
- [Protocol Detector](docs/protocol_detector_en.md)
- [Chinese Documentation](docs/README_ZH.md)

## Metrics

Integration metrics:

```bash
cargo test --release --test udp_integration_rust -- --ignored --nocapture
```

Output:

- `metrics/latest.json`
- `metrics/<timestamp>.json`


## CI/CD

- `.github/workflows/nightly.yml`: build/test + publish `ghcr.io/<owner>/prismux:dev` and `nightly-<sha>`
- `.github/workflows/release.yml`: on `v*` tag, publish release asset and Docker tags (`vX.Y.Z`, `vX.Y`, `vX`, `latest`)
