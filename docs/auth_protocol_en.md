# Prismux Auth Protocol

## Overview

Prismux auth module provides:

- challenge-response authentication (HMAC-SHA256)
- optional data encryption (AES-128-GCM)
- heartbeat and RTT sampling

## Configuration

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable auth. |
| `secret` | `""` | Shared secret; must be non-empty when auth is enabled. |
| `enable_encryption` | `false` | Enable AES-GCM encryption for data frames. |
| `heartbeat_interval` | `30` | Heartbeat interval in seconds (runtime minimum `1s`). |
| `auth_timeout` | `30` | Challenge timeout in seconds (runtime minimum `1s`). |
| `delay_window_size` | `10` | Delay sliding window size (runtime minimum `1`). |

## Frame Header

- Fixed header length: `8` bytes
- `version`: currently `2`
- `msg_type`: message type
- `length`: payload length

## Message Types

| Value | Name |
|---|---|
| `1` | `AUTH_CHALLENGE` |
| `2` | `AUTH_RESPONSE` |
| `4` | `HEARTBEAT` |
| `5` | `DATA` |
| `6` | `DISCONNECT` |
| `7` | `HEARTBEAT_ACK` |

## Handshake Payload Layout

Fixed `88` bytes:

- `challenge`: 32B
- `forward_id`: 8B
- `pool_id`: 8B
- `timestamp(ms)`: 8B
- `hmac(sha256)`: 32B

## Data Frame Layout

### Without Encryption

- payload = `conn_id(8B)` + `raw_data`

### With Encryption

- payload = `nonce(12B)` + `ciphertext` + `gcm_tag(16B)`
- plaintext = `timestamp(8B)` + `conn_id(8B)` + `raw_data`
- data older than `data_timeout` (currently around 65s) is rejected.

## Notes

- Both ends must use the same `secret` and `enable_encryption`.
- If `auth.enabled=true` and `secret` is empty, component initialization fails.
