# Prismux Forward 组件

## 概述

`forward` 组件负责把数据包并行发往一个或多个 UDP 目标，并把返回流量继续转发到 `detour` 指定组件。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `forward`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `forwarders` | 是 | - | 目标地址列表，例如 `["127.0.0.1:5201", "edge.example.com:5201"]`。 |
| `detour` | 否 | `[]` | 回包的转发目标。 |
| `connection_check_time` | 否 | `0` | 连接维护周期（秒）；运行时至少 `1s`。 |
| `reconnect_interval` | 否 | `0` | 预留字段，当前实现未独立使用。 |
| `send_keepalive` | 否 | `true` | 未启用鉴权时，是否周期发送空包保活。 |
| `send_timeout` | 否 | `0` | 发送超时（毫秒）；运行时至少 `1ms`。 |
| `recv_buffer_size` | 否 | `0` | UDP 接收缓冲区；运行时至少 `2 MiB`。 |
| `send_buffer_size` | 否 | `0` | UDP 发送缓冲区；运行时至少 `2 MiB`。 |
| `auth` | 否 | - | 鉴权配置，见 [鉴权协议](auth_protocol_zh.md)。 |

## 配置示例

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

## 工作机制

1. 启动时为每个 `forwarders` 地址创建独立 UDP 连接。
2. 收到上游包后，向所有可用目标并行发送。
3. 收到目标回包后，按 `detour` 继续转发。
4. 维护逻辑分为两条周期：
   - 按 `connection_check_time` 重解析每个 `forwarder`，并对缺失/目标变化的连接进行重建；
   - 开启 `auth` 时按 `auth.heartbeat_interval` 发送心跳，并对未认证 peer 重试 challenge；
   - 未开启 `auth` 且 `send_keepalive=true` 时，按 `connection_check_time` 发送空包保活。

## 注意事项

- `reconnect_interval` 当前是兼容字段，实际重连节奏由 `connection_check_time` 决定。
- 支持域名目标；维护周期内会重新执行 DNS 解析并跟随地址变化重连。
- 开启 `auth` 时，仅认证成功的 peer 会参与业务转发。
