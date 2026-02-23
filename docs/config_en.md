# Prismux Global Configuration

## Overview

Prismux accepts YAML or JSON config files. If extension is `.yaml/.yml`, YAML is used; otherwise JSON is used.

## Root Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `buffer_size` | `usize` | `1500` | Packet buffer size (bytes). |
| `buffer_offset` | `usize` | `64` | Reserved offset used when reading packets. |
| `queue_size` | `usize` | `10240` | Total routing queue capacity. |
| `worker_count` | `usize` | `4` | Desired workers; runtime uses `max(worker_count, CPU cores)`. |
| `services` | `array` | `[]` | Component definitions. |
| `protocol_detectors` | `map` | `{}` | Protocol detector definitions used by `filter`. |
| `logging.level` | `string` | `info` | Log level. |
| `logging.format` | `string` | `console` | `console` or `json`. |
| `logging.output_path` | `string` | `stdout` | Reserved field, not actively used for output redirection yet. |
| `logging.caller` | `bool` | `false` | Reserved field, not active yet. |
| `api.enabled` | `bool` | `false` | Enable built-in REST API server. |
| `api.port` | `u16` | `0` | API listen port (`0` maps to `8080`). |
| `api.host` | `string` | `""` | API listen host (`""` maps to `0.0.0.0`). |
| `api.h5_files_path` | `string` | `""` | Optional static file directory served under `/h5/`. |

## Component Types

`services[].type` supports:

- `listen`
- `forward`
- `filter`
- `load_balancer`
- `ip_router`
- `tcp_tunnel_listen`
- `tcp_tunnel_forward`

## Minimal Example

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

## Related Docs

- [Listen Component](listen_en.md)
- [Forward Component](forward_en.md)
- [Filter Component](filter_en.md)
- [Load Balancer Component](load_balancer_en.md)
- [IP Router Component](ip_router_en.md)
- [TCP Tunnel Listen Component](tcp_tunnel_listen_en.md)
- [TCP Tunnel Forward Component](tcp_tunnel_forward_en.md)
