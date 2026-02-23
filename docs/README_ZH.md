# Prismux 文档（UDPlex 风格）

本目录按 UDPlex 的文档组织方式维护 Prismux（Rust 重构版）说明文档。

## 语言

[English](README_EN.md) | [中文](README_ZH.md)

## 文档导航

- [全局配置](config_zh.md)
- [Listen 组件](listen_zh.md)
- [Forward 组件](forward_zh.md)
- [Filter 组件](filter_zh.md)
- [Load Balancer 组件](load_balancer_zh.md)
- [IP Router 组件](ip_router_zh.md)
- [TCP Tunnel Listen 组件](tcp_tunnel_listen_zh.md)
- [TCP Tunnel Forward 组件](tcp_tunnel_forward_zh.md)
- [鉴权协议](auth_protocol_zh.md)
- [协议检测器](protocol_detector_zh.md)

## 当前实现说明（Rust Refactor）

- 当前版本未实现 API Server（即使 `api.enabled: true` 也只会输出提示日志）。
- `ip_router` 中 `geo:*` 规则已解析但尚未生效，当前仅支持 IP/CIDR 路由。
- `load_balancer` 的 `enable_cache` 参数目前为保留字段，尚未启用。
- `load_balancer` 的 `available_<tag>` 当前表示“组件是否已注册”，不是运行态健康检查。
