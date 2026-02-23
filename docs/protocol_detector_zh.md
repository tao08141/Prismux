# Prismux 协议检测器

## 概述

协议检测器定义在根级 `protocol_detectors`，由 `filter` 组件按顺序调用，用于识别 UDP 负载协议类型。

## 配置结构

```yaml
protocol_detectors:
  wg:
    signatures:
      - offset: 0
        bytes: "01000000"
        mask: "FFFFFFFF"
        hex: true
        length:
          min: 92
          max: 92
        contains: ""
    match_logic: OR
    description: WireGuard
    priority: 0
```

## 字段说明

| 字段 | 说明 |
|---|---|
| `signatures` | 签名数组。 |
| `match_logic` | `AND` 或其他（其他值按 OR 处理）。 |
| `description` | 描述信息（当前仅文档用途）。 |
| `priority` | 预留字段，当前检测顺序不使用该值。 |

### signature 字段

| 字段 | 说明 |
|---|---|
| `offset` | 从数据包第几字节开始匹配。 |
| `bytes` | 要匹配的字节序列。 |
| `mask` | 位掩码（和 `bytes` 按位比较）。 |
| `contains` | 子串匹配（字节序列是否出现在包中）。 |
| `hex` | `true` 表示 `bytes/mask/contains` 按 hex 解码。 |
| `length.min` | 最小包长。 |
| `length.max` | 最大包长。 |

## 匹配规则

1. `filter` 按 `use_proto_detectors` 顺序遍历检测器。
2. 每个检测器内部：
   - `match_logic=AND` 时要求全部 signature 命中；
   - 否则命中任一 signature 即可。
3. 命中第一个检测器后立即返回，不再继续检测后续项。

## 注意事项

- `use_proto_detectors` 引用了不存在的检测器时，会被跳过。
- 若某检测器 `signatures` 为空，则该检测器永远不会命中。
