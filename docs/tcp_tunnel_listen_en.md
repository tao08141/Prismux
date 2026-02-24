# Prismux TCP Tunnel Listen Component

## Overview

The `tcp_tunnel_listen` component accepts TCP tunnel connections, decapsulates UDP frames, and forwards payloads to `detour`.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `tcp_tunnel_listen`. |
| `tag` | Yes | - | Unique component identifier. |
| `listen_addr` | Yes | - | TCP bind address. |
| `timeout` | No | `30s` | Connection idle timeout; unauthenticated connections are also dropped after auth timeout. |
| `detour` | No | `[]` | Forward targets for decapsulated traffic. |
| `broadcast_mode` | No | `true` | Whether outbound frames broadcast by pool. |
| `send_timeout` | No | `500ms` | Queue backpressure send wait (`0` is treated as `500ms`). |
| `no_delay` | No | `true` | TCP `nodelay`. |
| `recv_buffer_size` | No | `0` | Socket receive buffer; runtime enforces at least `2 MiB`. |
| `send_buffer_size` | No | `0` | Socket send buffer; runtime enforces at least `2 MiB`. |
| `auth` | Yes | - | Must be enabled and valid. |

## Example

```yaml
- type: tcp_tunnel_listen
  tag: tunnel_in
  listen_addr: 0.0.0.0:5203
  detour: [server_forward]
  broadcast_mode: true
  auth:
    enabled: true
    secret: your-secret-key
    enable_encryption: true
```

## Behavior

1. Starts a TCP listener and allocates one send queue per connection.
2. Frames are authenticated and unwrapped:
   - DATA: accepted only after auth succeeds, then forwarded to `detour`.
   - Control frames: challenge/heartbeat/ack are handled internally.
3. Connections are removed automatically:
   - unauthenticated connections are closed after auth timeout;
   - authenticated connections are closed after `timeout` of inactivity.
4. Outbound traffic is wrapped and sent:
   - `broadcast_mode=true`: group by `(forward_id, pool_id)`, pick best-capacity connection per group.
   - `broadcast_mode=false`: route by `conn_id_hint`.

## Notes

- Component initialization fails if `auth.enabled` is not set to true.
- If `detour` is empty, decapsulated traffic will not continue downstream.
