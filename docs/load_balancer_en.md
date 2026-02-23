# Prismux Load Balancer Component

## Overview

The `load_balancer` component selects targets using expression-based rules. It supports routing by sequence, packet size, rate, delay, and more.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `load_balancer`. |
| `tag` | Yes | - | Unique component identifier. |
| `detour` | Yes | - | Rule array; each rule contains `rule` and `targets`. |
| `miss` | No | `[]` | Fallback targets if no rule matches. |
| `window_size` | No | `10` | Sliding window sample size for traffic stats. |
| `enable_cache` | No | `false` | Reserved field, not active in current implementation. |

### Rule Item

| Field | Description |
|---|---|
| `rule` | Expression string. |
| `targets` | Target component tags when expression matches. |

## Expression Variables

| Variable | Description |
|---|---|
| `seq` | Packet sequence number (starts from 1). |
| `size` | Current packet size (bytes). |
| `bps` | Smoothed average bits per second. |
| `pps` | Smoothed average packets per second. |
| `available_<tag>` | Currently means the tag exists in router registration. |
| `delay_<tag>` | Average delay reported by the target component (ms). |

## Example

```yaml
- type: load_balancer
  tag: lb
  window_size: 10
  detour:
    - rule: seq % 2 == 0
      targets: [server_a]
    - rule: seq % 2 == 1
      targets: [server_b]
    - rule: delay_server_a < 10 && available_server_a
      targets: [server_a]
  miss: [server_b]
```

## Behavior

1. Rules are evaluated in configured order.
2. Multiple rules may match; packet is cloned and forwarded to all matched target groups.
3. If no rules match:
   - forward to `miss` if configured,
   - otherwise drop.
4. If any rule references `bps`/`pps`, a 1-second sampling loop runs for sliding-window stats.

## Notes

- Expressions are evaluated by `evalexpr`; `bool/int/float` results are all accepted (`!= 0` is true).
- `available_<tag>` is not a health probe in current Rust build.
