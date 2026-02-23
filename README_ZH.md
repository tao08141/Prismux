# Prismux（Rust 重构版）

[English](README.md) | [中文](README_ZH.md)

Prismux 是按 UDPlex 思路实现的 Rust 版本 UDP 复用/转发组件化系统。

## 快速开始

构建：

```bash
cargo build --release
```

运行：

```bash
./target/release/prismux -c examples/basic.yaml
```

Docker：

```bash
docker run -d --name prismux --network host \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/tao08141/prismux:latest
```

## 文档

- [文档总览](docs/README_ZH.md)
- [英文文档总览](docs/README_EN.md)
- [全局配置](docs/config_zh.md)
- [Listen 组件](docs/listen_zh.md)
- [Forward 组件](docs/forward_zh.md)
- [Filter 组件](docs/filter_zh.md)
- [Load Balancer 组件](docs/load_balancer_zh.md)
- [IP Router 组件](docs/ip_router_zh.md)
- [TCP Tunnel Listen 组件](docs/tcp_tunnel_listen_zh.md)
- [TCP Tunnel Forward 组件](docs/tcp_tunnel_forward_zh.md)
- [鉴权协议](docs/auth_protocol_zh.md)
- [协议检测器](docs/protocol_detector_zh.md)
- [RESTful API 服务](RESTful_zh.md)
- [Prismux + WireGuard 一键部署](docs/prismux_wireguard_zh.md)

## 指标与测试

集成测试指标：

```bash
cargo test --release --test udp_integration_rust -- --ignored --nocapture
```

输出：

- `metrics/latest.json`
- `metrics/<timestamp>.json`

## CI/CD

- `.github/workflows/nightly.yml`：构建/测试并发布 `ghcr.io/<owner>/prismux:dev` 与 `nightly-<sha>`
- `.github/workflows/release.yml`：`v*` tag 发布 release 产物与 Docker tags（`vX.Y.Z`、`vX.Y`、`vX`、`latest`）
