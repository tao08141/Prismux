# Prismux Listen 组件

## 概述

`listen` 组件负责监听 UDP 端口，接收客户端数据，并按 `detour` 转发给下游组件。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `listen`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `listen_addr` | 是 | - | 监听地址，例如 `0.0.0.0:5202`。 |
| `timeout` | 否 | `0` | 连接映射超时秒数；运行时至少按 `1s` 处理。 |
| `replace_old_mapping` | 否 | `false` | 为 `true` 时，同一源 IP 的旧映射会被新映射替换。 |
| `detour` | 否 | `[]` | 入站包的转发目标。 |
| `broadcast_mode` | 否 | `true` | 回包时是否广播到所有活跃映射。 |
| `send_timeout` | 否 | `0` | 发送超时（毫秒）；运行时至少按 `1ms`。 |
| `recv_buffer_size` | 否 | `0` | UDP 接收缓冲区；运行时至少 `2 MiB`。 |
| `send_buffer_size` | 否 | `0` | UDP 发送缓冲区；运行时至少 `2 MiB`。 |
| `auth` | 否 | - | 鉴权配置，见 [鉴权协议](auth_protocol_zh.md)。 |

## 配置示例

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

## 工作机制

1. 启动时绑定 `listen_addr`，并维护 `src_addr -> conn_id` 映射。
2. 入站包处理：
   - 未开启 `auth`：直接建立/刷新映射并转发；
   - 开启 `auth`：先完成 challenge/response，认证通过后才接受 DATA 帧。
3. 组件会周期清理超时映射（基于 `timeout`）。
4. 下游回包处理：
   - `broadcast_mode=true`：发送给所有活跃目标；
   - `broadcast_mode=false`：按 `packet.conn_id` 定向回发。

## 注意事项

- 未配置 `detour` 时，入站包不会继续转发。
- 开启 `auth` 时，未认证源地址的 DATA 帧会被丢弃。
