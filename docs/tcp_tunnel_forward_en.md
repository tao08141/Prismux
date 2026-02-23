# Prismux TCP Tunnel Forward Component

## Overview

The `tcp_tunnel_forward` component actively connects to remote tunnel listeners, encapsulates upstream packets into TCP frames, and forwards decapsulated returns to `detour`.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `tcp_tunnel_forward`. |
| `tag` | Yes | - | Unique component identifier. |
| `forwarders` | Yes | - | Target list, format `ip:port[:count]`. |
| `detour` | No | `[]` | Return traffic targets after decapsulation. |
| `connection_check_time` | No | `0` | Maintenance interval seconds; runtime enforces minimum `1s`. |
| `send_timeout` | No | `500ms` | Queue backpressure send wait (`0` is treated as `500ms`). |
| `no_delay` | No | `true` | TCP `nodelay`. |
| `recv_buffer_size` | No | `0` | Socket receive buffer; runtime enforces at least `2 MiB`. |
| `send_buffer_size` | No | `0` | Socket send buffer; runtime enforces at least `2 MiB`. |
| `auth` | Yes | - | Must be enabled and valid. |

## `forwarders` Format

- `127.0.0.1:5203`: default parallel connection count is `4`
- `127.0.0.1:5203:8`: parallel connection count is `8`

> Current parsing uses `SocketAddr`, so use directly parsable `IP:PORT` (not domain names).

## Example

```yaml
- type: tcp_tunnel_forward
  tag: tunnel_out
  forwarders:
    - 127.0.0.1:5203:4
  connection_check_time: 10
  detour: [client_listen]
  auth:
    enabled: true
    secret: your-secret-key
    enable_encryption: true
```

## Behavior

1. Maintains a connection pool for each forward target.
2. Each new connection sends challenge first; data path starts only after auth.
3. For each outbound packet, picks one authenticated connection per target pool.
4. Inbound tunnel payloads are unwrapped and forwarded to `detour`.
5. Maintenance loop sends heartbeat and replenishes missing connections.

## Notes

- Component initialization fails if `auth.enabled` is not true.
- If all connections are unauthenticated, `is_available` is false.
