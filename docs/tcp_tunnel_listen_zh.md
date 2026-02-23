# Prismux TCP Tunnel Listen 组件

## 概述

`tcp_tunnel_listen` 组件监听 TCP 连接，接收封装后的 UDP 数据帧并转发到 `detour`，用于 UDP over TCP 场景。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `tcp_tunnel_listen`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `listen_addr` | 是 | - | TCP 监听地址。 |
| `detour` | 否 | `[]` | 解封装后数据的转发目标。 |
| `broadcast_mode` | 否 | `true` | 回包时是否按池广播。 |
| `send_timeout` | 否 | `500ms` | 队列拥塞时发送等待超时（`0` 也会按 `500ms`）。 |
| `no_delay` | 否 | `true` | TCP `nodelay`。 |
| `recv_buffer_size` | 否 | `0` | Socket 接收缓冲区；运行时至少 `2 MiB`。 |
| `send_buffer_size` | 否 | `0` | Socket 发送缓冲区；运行时至少 `2 MiB`。 |
| `auth` | 是 | - | 必须开启且配置正确。 |

## 配置示例

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

## 工作机制

1. 启动 TCP 监听，接收连接并为每条连接维护独立发送队列。
2. 读取帧后执行鉴权解包：
   - DATA：认证成功后转发到 `detour`；
   - 控制帧：处理 challenge/heartbeat/ack。
3. 下游回包时先重新封装，再按模式发送：
   - `broadcast_mode=true`：按 `(forward_id, pool_id)` 分组，每组挑选一个队列容量最优连接发送；
   - `broadcast_mode=false`：按 `conn_id_hint` 定向发送。

## 注意事项

- 未开启 `auth.enabled` 会导致组件初始化失败。
- 若 `detour` 为空，解封装后的业务数据不会继续流转。
