# Prismux Documentation (UDPlex Style)

This directory follows a UDPlex-style structure for Prismux (Rust refactor) docs.

## Language

[English](README_EN.md) | [中文](README_ZH.md)

## Navigation

- [Global Configuration](config_en.md)
- [Listen Component](listen_en.md)
- [Forward Component](forward_en.md)
- [Filter Component](filter_en.md)
- [Load Balancer Component](load_balancer_en.md)
- [IP Router Component](ip_router_en.md)
- [TCP Tunnel Listen Component](tcp_tunnel_listen_en.md)
- [TCP Tunnel Forward Component](tcp_tunnel_forward_en.md)
- [Auth Protocol](auth_protocol_en.md)
- [Protocol Detector](protocol_detector_en.md)

## Current Rust Refactor Status

- API server is not implemented yet (setting `api.enabled: true` only logs a warning).
- `ip_router` can parse `geo:*` rules, but GeoIP matching is not active yet.
- `load_balancer.enable_cache` is currently a reserved field.
- `load_balancer` `available_<tag>` currently means "tag exists in router", not runtime health probing.
