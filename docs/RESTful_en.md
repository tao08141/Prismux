# API Server Documentation (Prismux Rust)

## Overview

Prismux provides a built-in RESTful API server for runtime monitoring and basic actions.

Current implementation includes:

- Component list and per-tag component info
- Runtime connection/state snapshots for `listen`, `forward`, `tcp_tunnel_listen`, `tcp_tunnel_forward`
- Traffic stats for `load_balancer`
- Runtime info and action API for `ip_router` (`geoip_update`)
- Static file serving under `/h5`

## Configuration

```yaml
api:
  enabled: true
  host: 0.0.0.0
  port: 8080
  h5_files_path: ./h5
```

Notes:

- `api.host: ""` falls back to `0.0.0.0`
- `api.port: 0` falls back to `8080`
- If `h5_files_path` is empty, `/h5/*` returns `404`

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/components` | List components in config order (registered only). |
| GET | `/api/components/{tag}` | Get one component info by tag. |
| GET | `/api/listen/{tag}` | Listen runtime connections. |
| GET | `/api/forward/{tag}` | Forward runtime connections. |
| GET | `/api/tcp_tunnel_listen/{tag}` | TCP tunnel listen pools/connections. |
| GET | `/api/tcp_tunnel_forward/{tag}` | TCP tunnel forward pools/connections. |
| GET | `/api/load_balancer/{tag}` | Load balancer traffic stats. |
| GET | `/api/filter/{tag}` | Filter runtime/config info. |
| GET | `/api/ip_router/{tag}` | IP router runtime/config info. |
| POST | `/api/ip_router_action/{tag}?action=geoip_update` | Trigger GeoIP download and hot-swap for one IP router. |
| GET | `/h5` / `/h5/` / `/h5/{file_path}` | Serve static files from `h5_files_path`. |

## Component Info API

### `GET /api/components`

Returns an array. Each item always includes:

- `tag`
- `type`
- `available` (runtime availability from component health check)

Plus type-specific fields.

### `GET /api/components/{tag}`

Returns one object with the same shape as list items.

Example (`listen`):

```json
{
  "tag": "client_listen",
  "type": "listen",
  "listen_addr": "0.0.0.0:5202",
  "timeout": 120,
  "replace_old_mapping": true,
  "detour": ["client_forward"],
  "available": true
}
```

## Runtime Snapshot APIs

### `GET /api/listen/{tag}`

```json
{
  "tag": "client_listen",
  "listen_addr": "0.0.0.0:5202",
  "connections": [
    {
      "address": "192.168.1.10:53001",
      "connection_id": "4f8b2af2a61dcd10",
      "last_active": "2026-02-23T15:10:20Z",
      "is_authenticated": true
    }
  ],
  "count": 1,
  "average_delay_ms": 3.4
}
```

Notes:

- `is_authenticated` and `average_delay_ms` appear only when auth is enabled.

### `GET /api/forward/{tag}`

```json
{
  "tag": "client_forward",
  "connections": [
    {
      "remote_addr": "127.0.0.1:5201",
      "is_connected": true,
      "last_reconnect": "2026-02-23T15:08:01Z",
      "auth_retry_count": 2,
      "heartbeat_miss": 0,
      "last_heartbeat": "2026-02-23T15:10:19Z",
      "is_authenticated": true
    }
  ],
  "count": 1,
  "average_delay_ms": 1.2
}
```

Notes:

- `is_authenticated` and `average_delay_ms` appear only when auth is enabled.
- If a configured target has no active peer yet, `is_connected` is `false` and time fields may be `null`.

### `GET /api/tcp_tunnel_listen/{tag}`

```json
{
  "tag": "tcp_tunnel_listen",
  "listen_addr": "0.0.0.0:9090",
  "pools": [
    {
      "forward_id": "139f1e0ab962a6b1",
      "pool_id": "021e8f2a39f5f2a0",
      "remote_addr": "192.168.1.20:50912",
      "connections": [
        {
          "remote_addr": "192.168.1.20:50912",
          "is_authenticated": true,
          "last_active": "2026-02-23T15:10:19Z",
          "heartbeat_miss": 0,
          "last_heartbeat": "2026-02-23T15:10:19Z"
        }
      ],
      "conn_count": 1
    }
  ],
  "total_connections": 1,
  "average_delay_ms": 2.1
}
```

### `GET /api/tcp_tunnel_forward/{tag}`

```json
{
  "tag": "tcp_tunnel_forward",
  "forward_id": "8af2b05acbc9f10e",
  "pools": [
    {
      "pool_id": "6c08c63a2dd31a17",
      "remote_addr": "192.168.1.30:9090",
      "connections": [
        {
          "connection_id": 7,
          "remote_addr": "192.168.1.30:9090",
          "is_authenticated": true,
          "last_active": "2026-02-23T15:10:19Z",
          "heartbeat_miss": 0,
          "last_heartbeat": "2026-02-23T15:10:19Z"
        }
      ],
      "conn_count": 1,
      "target_count": 4
    }
  ],
  "total_connections": 1,
  "average_delay_ms": 2.0
}
```

### `GET /api/load_balancer/{tag}`

```json
{
  "tag": "lb",
  "bits_per_sec": 8192000,
  "packets_per_sec": 100,
  "total_bytes": 10240000,
  "total_packets": 1000,
  "current_bytes": 1024,
  "current_packets": 10,
  "samples": [{"bytes": 1024, "packets": 10}],
  "window_size": 60
}
```

## Filter and IP Router APIs

### `GET /api/filter/{tag}`

Returns filter configuration/runtime view, including:

- `use_proto_detectors`
- `detour`
- `detour_miss`

### `GET /api/ip_router/{tag}`

Returns:

- `rules`
- `detour_miss`
- `geoip.db_loaded`
- `geoip.geoip_url`
- `geoip.geoip_path`
- `geoip.update_interval_sec`

Geo rules (`geo:XX`) are active when a valid MMDB is loaded.

### `POST /api/ip_router_action/{tag}?action=geoip_update`

Behavior:

- Downloads MMDB from configured `geoip_url`
- Validates and hot-swaps in-memory DB
- Writes a local cache file under temp directory

Success response:

```json
"ok"
```

## H5 Static Files

- `GET /h5` and `GET /h5/` serve `index.html`
- `GET /h5/{file_path}` serves the target file
- Path traversal (`..`, absolute path, drive prefix) is rejected with `400`

## Status Codes

- `200 OK`: success
- `400 Bad Request`: wrong tag/type/params
- `404 Not Found`: component or file not found
- `405 Method Not Allowed`: method not registered for route
- `500 Internal Server Error`: internal errors (for example download/IO failures)
