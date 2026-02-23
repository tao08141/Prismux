# API 服务文档（Prismux Rust）

## 概述

Prismux 提供内置 RESTful API 服务，用于运行时监控和少量控制动作。

当前已实现：

- 组件列表与按标签查询
- `listen`、`forward`、`tcp_tunnel_listen`、`tcp_tunnel_forward` 运行态连接快照
- `load_balancer` 流量统计
- `ip_router` 运行态信息与动作接口（`geoip_update`）
- `/h5` 静态文件服务

## 配置

```yaml
api:
  enabled: true
  host: 0.0.0.0
  port: 8080
  h5_files_path: ./h5
```

说明：

- `api.host: ""` 会回退为 `0.0.0.0`
- `api.port: 0` 会回退为 `8080`
- `h5_files_path` 为空时，`/h5/*` 返回 `404`

## 接口总览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/components` | 获取组件列表（按配置顺序，仅已注册组件）。 |
| GET | `/api/components/{tag}` | 按标签获取组件信息。 |
| GET | `/api/listen/{tag}` | 获取 `listen` 连接快照。 |
| GET | `/api/forward/{tag}` | 获取 `forward` 连接快照。 |
| GET | `/api/tcp_tunnel_listen/{tag}` | 获取 TCP 隧道监听池状态。 |
| GET | `/api/tcp_tunnel_forward/{tag}` | 获取 TCP 隧道转发池状态。 |
| GET | `/api/load_balancer/{tag}` | 获取负载均衡流量统计。 |
| GET | `/api/filter/{tag}` | 获取过滤组件信息。 |
| GET | `/api/ip_router/{tag}` | 获取 IP 路由组件信息。 |
| POST | `/api/ip_router_action/{tag}?action=geoip_update` | 触发指定 `ip_router` 的 GeoIP 下载与热更新。 |
| GET | `/h5` / `/h5/` / `/h5/{file_path}` | 提供静态文件。 |

## 组件信息接口

### `GET /api/components`

返回数组。每个对象至少包含：

- `tag`
- `type`
- `available`（组件运行可用性）

并包含类型相关字段。

### `GET /api/components/{tag}`

返回单个组件对象，结构与列表项一致。

示例（`listen`）：

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

## 运行态快照接口

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

说明：

- 仅在启用认证时返回 `is_authenticated` 和 `average_delay_ms`。

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

说明：

- 仅在启用认证时返回 `is_authenticated` 和 `average_delay_ms`。
- 若某个配置目标尚未建立对端连接，则该项 `is_connected=false`，时间字段可能为 `null`。

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

## Filter 与 IP Router 接口

### `GET /api/filter/{tag}`

返回过滤组件信息，主要包含：

- `use_proto_detectors`
- `detour`
- `detour_miss`

### `GET /api/ip_router/{tag}`

返回：

- `rules`
- `detour_miss`
- `geoip.db_loaded`
- `geoip.geoip_url`
- `geoip.geoip_path`
- `geoip.update_interval_sec`

当 MMDB 成功加载后，`geo:XX` 规则会参与匹配。

### `POST /api/ip_router_action/{tag}?action=geoip_update`

行为：

- 从配置的 `geoip_url` 下载 MMDB
- 校验后热替换内存数据库
- 将文件缓存到系统临时目录

成功返回：

```json
"ok"
```

## H5 静态文件

- `GET /h5` 和 `GET /h5/` 默认返回 `index.html`
- `GET /h5/{file_path}` 返回指定文件
- 路径穿越（`..`、绝对路径、盘符前缀）会被拒绝并返回 `400`

## 状态码

- `200 OK`：成功
- `400 Bad Request`：参数错误或组件类型不匹配
- `404 Not Found`：组件或文件不存在
- `405 Method Not Allowed`：方法不支持
- `500 Internal Server Error`：内部错误（例如下载或 IO 失败）
