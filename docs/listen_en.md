# Prismux Listen Component

## Overview

The `listen` component binds a UDP port, receives client traffic, and forwards inbound packets to `detour` targets.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `listen`. |
| `tag` | Yes | - | Unique component identifier. |
| `listen_addr` | Yes | - | UDP bind address, for example `0.0.0.0:5202`. |
| `timeout` | No | `0` | Mapping timeout seconds; runtime enforces minimum `1s`. |
| `replace_old_mapping` | No | `false` | If `true`, a new mapping replaces existing mappings from the same source IP. |
| `detour` | No | `[]` | Forward targets for inbound packets. |
| `broadcast_mode` | No | `true` | Whether outbound replies should broadcast to all active mappings. |
| `send_timeout` | No | `0` | Send timeout in milliseconds; runtime enforces minimum `1ms`. |
| `recv_buffer_size` | No | `0` | UDP receive buffer; runtime enforces at least `2 MiB`. |
| `send_buffer_size` | No | `0` | UDP send buffer; runtime enforces at least `2 MiB`. |
| `auth` | No | - | Auth config, see [Auth Protocol](auth_protocol_en.md). |

## Example

```yaml
- type: listen
  tag: client_listen
  listen_addr: 0.0.0.0:5202
  timeout: 120
  replace_old_mapping: true
  detour: [client_forward]
  broadcast_mode: true
  auth:
    enabled: true
    secret: your-secret-key
    enable_encryption: true
    heartbeat_interval: 30
```

## Behavior

1. On startup, it binds `listen_addr` and maintains `src_addr -> conn_id` mappings.
2. Inbound handling:
   - Without `auth`: mapping is inserted/refreshed, then payload is forwarded.
   - With `auth`: challenge/response must pass before DATA frames are accepted.
3. It periodically cleans stale mappings based on `timeout`.
4. Outbound handling:
   - `broadcast_mode=true`: send to all active targets.
   - `broadcast_mode=false`: route by `packet.conn_id`.

## Notes

- If `detour` is empty, inbound packets stop here.
- With `auth` enabled, unauthenticated DATA frames are dropped.
