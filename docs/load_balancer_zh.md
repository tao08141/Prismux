# Prismux Load Balancer 组件

## 概述

`load_balancer` 组件通过表达式规则动态选择转发目标，支持按序号、包大小、速率、延迟等条件路由。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `load_balancer`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `detour` | 是 | - | 规则数组，每项含 `rule` 与 `targets`。 |
| `miss` | 否 | `[]` | 无规则命中时的回退目标。 |
| `window_size` | 否 | `10` | 流量统计窗口样本数（约等于秒数）。 |
| `enable_cache` | 否 | `false` | 预留字段，当前实现未使用。 |

### 规则项

| 字段 | 说明 |
|---|---|
| `rule` | 表达式字符串。 |
| `targets` | 命中后转发目标数组。 |

## 表达式变量

| 变量 | 说明 |
|---|---|
| `seq` | 包序号（从 1 开始）。 |
| `size` | 当前包大小（字节）。 |
| `bps` | 平滑窗口平均比特率。 |
| `pps` | 平滑窗口平均包率。 |
| `available_<tag>` | 当前仅表示对应 tag 是否注册。 |
| `delay_<tag>` | 对应组件上报的平均延迟（毫秒）。 |

## 配置示例

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

## 工作机制

1. 按配置顺序评估每条规则，命中则收集其 `targets`。
2. 同一包可命中多条规则，组件会把包复制后分别转发到所有命中目标组。
3. 若无规则命中：
   - `miss` 非空时转发到 `miss`；
   - 否则丢包。
4. 当规则中出现 `bps/pps` 时，组件启动 1 秒周期采样线程计算平滑统计值。

## 注意事项

- 表达式由 `evalexpr` 解析，返回 `bool/int/float` 都可作为条件结果（非零视为真）。
- `available_<tag>` 目前不是健康探测，仅判断组件是否存在。
