# Prismux 全局配置

## 概述

Prismux 使用 YAML/JSON 配置。启动时如果文件后缀是 `.yaml/.yml` 则按 YAML 解析，否则按 JSON 解析。

## 根级参数

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `buffer_size` | `usize` | `1500` | 数据包缓冲区大小（字节）。 |
| `buffer_offset` | `usize` | `64` | 读取时预留偏移量。 |
| `queue_size` | `usize` | `10240` | 路由队列总容量。 |
| `worker_count` | `usize` | `4` | 期望 worker 数；实际运行会取 `max(worker_count, CPU 核数)`。 |
| `services` | `array` | `[]` | 组件数组。 |
| `protocol_detectors` | `map` | `{}` | 协议检测器定义，供 `filter` 组件使用。 |
| `logging.level` | `string` | `info` | 日志等级。 |
| `logging.format` | `string` | `console` | `console` 或 `json`。 |
| `logging.output_path` | `string` | `stdout` | 预留字段，当前未实际用于输出重定向。 |
| `logging.caller` | `bool` | `false` | 预留字段，当前未实际生效。 |
| `api.enabled` | `bool` | `false` | 预留字段，当前 Rust 版未实现 API Server。 |
| `api.port` | `u16` | `0` | 预留字段。 |
| `api.host` | `string` | `""` | 预留字段。 |
| `api.h5_files_path` | `string` | `""` | 预留字段。 |

## 组件类型

`services[].type` 支持：

- `listen`
- `forward`
- `filter`
- `load_balancer`
- `ip_router`
- `tcp_tunnel_listen`
- `tcp_tunnel_forward`

## 最小示例

```yaml
buffer_size: 1500
queue_size: 10240
worker_count: 4
logging:
  level: info
  format: console
services:
  - type: listen
    tag: client_listen
    listen_addr: 0.0.0.0:5202
    timeout: 120
    replace_old_mapping: true
    detour: [client_forward]
  - type: forward
    tag: client_forward
    forwarders: [127.0.0.1:5201]
    connection_check_time: 30
    send_keepalive: true
    detour: [client_listen]
```

## 相关文档

- [Listen 组件](listen_zh.md)
- [Forward 组件](forward_zh.md)
- [Filter 组件](filter_zh.md)
- [Load Balancer 组件](load_balancer_zh.md)
- [IP Router 组件](ip_router_zh.md)
- [TCP Tunnel Listen 组件](tcp_tunnel_listen_zh.md)
- [TCP Tunnel Forward 组件](tcp_tunnel_forward_zh.md)
