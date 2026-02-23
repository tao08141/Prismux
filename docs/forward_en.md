# Prismux Forward Component

## Overview

The `forward` component sends packets to one or more UDP targets in parallel and forwards return traffic to `detour`.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `forward`. |
| `tag` | Yes | - | Unique component identifier. |
| `forwarders` | Yes | - | Target address list, for example `["127.0.0.1:5201", "edge.example.com:5201"]`. |
| `detour` | No | `[]` | Return traffic targets. |
| `connection_check_time` | No | `0` | Maintenance interval in seconds; runtime enforces minimum `1s`. |
| `reconnect_interval` | No | `0` | Reserved compatibility field, not used independently in current Rust behavior. |
| `send_keepalive` | No | `true` | When auth is disabled, send empty packets as keepalive. |
| `send_timeout` | No | `0` | Send timeout in milliseconds; runtime enforces minimum `1ms`. |
| `recv_buffer_size` | No | `0` | UDP receive buffer; runtime enforces at least `2 MiB`. |
| `send_buffer_size` | No | `0` | UDP send buffer; runtime enforces at least `2 MiB`. |
| `auth` | No | - | Auth config, see [Auth Protocol](auth_protocol_en.md). |

## Example

```yaml
- type: forward
  tag: client_forward
  forwarders:
    - 127.0.0.1:5201
    - 127.0.0.1:5202
  connection_check_time: 10
  send_keepalive: true
  detour: [client_listen]
  auth:
    enabled: true
    secret: your-secret-key
    enable_encryption: true
```

## Behavior

1. At startup, it creates one UDP connection per `forwarders` entry.
2. For each inbound packet, it sends to all currently available peers.
3. Return packets from peers are forwarded to `detour`.
4. Maintenance has two schedules:
   - Every `connection_check_time`, it resolves each forwarder and reconnects missing/changed peers.
   - With auth enabled, every `auth.heartbeat_interval`, it sends heartbeat and retries challenge for unauthenticated peers.
   - With auth disabled and `send_keepalive=true`, it sends empty keepalive every `connection_check_time`.

## Notes

- `reconnect_interval` is currently a compatibility field; reconnect cadence is effectively `connection_check_time`.
- Hostname targets are supported. DNS is re-resolved in each maintenance cycle.
- With auth enabled, only authenticated peers are used for data forwarding.
