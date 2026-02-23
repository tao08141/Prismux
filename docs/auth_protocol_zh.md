# Prismux 鉴权协议

## 概述

Prismux 的鉴权模块支持：

- 挑战应答鉴权（HMAC-SHA256）
- 可选数据加密（AES-128-GCM）
- 心跳与 RTT 统计

## 配置项

| 参数 | 默认值 | 说明 |
|---|---|---|
| `enabled` | `false` | 是否启用鉴权。 |
| `secret` | `""` | 共享密钥，启用时必须非空。 |
| `enable_encryption` | `false` | 是否启用 AES-GCM 加密数据帧。 |
| `heartbeat_interval` | `30` | 心跳间隔（秒，最小按 `1s`）。 |
| `auth_timeout` | `30` | challenge 有效期（秒，最小按 `1s`）。 |
| `delay_window_size` | `10` | 延迟滑动窗口大小（最小为 `1`）。 |

## 协议头

- 固定头长度：`8` 字节
- `version`：当前值 `2`
- `msg_type`：消息类型
- `length`：payload 长度

## 消息类型

| 值 | 含义 |
|---|---|
| `1` | `AUTH_CHALLENGE` |
| `2` | `AUTH_RESPONSE` |
| `4` | `HEARTBEAT` |
| `5` | `DATA` |
| `6` | `DISCONNECT` |
| `7` | `HEARTBEAT_ACK` |

## 握手 payload 结构

长度固定 `88` 字节：

- `challenge`：32B
- `forward_id`：8B
- `pool_id`：8B
- `timestamp(ms)`：8B
- `hmac(sha256)`：32B

## 数据帧

### 未加密

- payload = `conn_id(8B)` + `raw_data`

### 加密

- payload = `nonce(12B)` + `ciphertext` + `gcm_tag(16B)`
- 明文结构：`timestamp(8B)` + `conn_id(8B)` + `raw_data`
- 超过 `data_timeout`（当前实现固定约 65 秒）的数据会被拒绝。

## 注意事项

- 双端 `secret`、`enable_encryption` 必须一致。
- `auth.enabled=true` 但 `secret` 为空会导致组件初始化失败。
