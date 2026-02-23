# Prismux TCP Tunnel Forward 组件

## 概述

`tcp_tunnel_forward` 组件主动连接远端 TCP Tunnel 服务端，把上游数据封装后通过 TCP 隧道发送，并把远端回包回注到 `detour`。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `tcp_tunnel_forward`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `forwarders` | 是 | - | 目标列表，格式 `host:port[:count]`。 |
| `detour` | 否 | `[]` | 隧道回包转发目标。 |
| `connection_check_time` | 否 | `0` | 连接维护周期秒数；运行时至少 `1s`。 |
| `send_timeout` | 否 | `500ms` | 队列拥塞时发送等待超时（`0` 也会按 `500ms`）。 |
| `no_delay` | 否 | `true` | TCP `nodelay`。 |
| `recv_buffer_size` | 否 | `0` | Socket 接收缓冲区；运行时至少 `2 MiB`。 |
| `send_buffer_size` | 否 | `0` | Socket 发送缓冲区；运行时至少 `2 MiB`。 |
| `auth` | 是 | - | 必须开启且配置正确。 |

## forwarders 格式

- `127.0.0.1:5203`：默认并发连接数 `4`
- `edge.example.com:5203`：默认并发连接数 `4`
- `edge.example.com:5203:8`：并发连接数 `8`

## 配置示例

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

## 工作机制

1. 每个 `forwarder` 维护一个目标池，并补齐到期望连接数。
2. 每条连接建立后先发起 challenge，认证通过后才进入业务态。
3. 发送路径：每个目标池挑选一个可用连接写入封装帧。
4. 接收路径：解包后把数据转发到 `detour`。
5. 维护逻辑分为两条周期：
   - 按 `connection_check_time` 补齐缺失连接；
   - 按 `auth.heartbeat_interval` 发送心跳，并对未认证连接重试 challenge。

## 注意事项

- 未开启 `auth.enabled` 会导致组件初始化失败。
- 若所有连接未认证成功，组件对外不可用（`is_available = false`）。
- 支持域名目标；连接建立或重连时会重新执行 DNS 解析。
