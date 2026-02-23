# Prismux Filter 组件

## 概述

`filter` 组件基于协议检测结果把数据包分流到不同目标，适用于协议识别、分类转发和精细化路由。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `filter`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `use_proto_detectors` | 否 | `[]` | 检测器名称列表，按顺序匹配。 |
| `detour` | 否 | `{}` | 协议名 -> 目标组件数组。 |
| `detour_miss` | 否 | `[]` | 未命中任何协议时的回退目标。 |

## 配置示例

```yaml
- type: filter
  tag: client_filter
  use_proto_detectors: [wg, game]
  detour:
    wg: [wg_forward]
    game: [game_forward]
  detour_miss: [default_forward]
```

## 工作机制

1. 按 `use_proto_detectors` 顺序逐个检测。
2. 命中后会把 `packet.proto` 设置为协议名，并查找 `detour[协议名]` 转发。
3. 若全部未命中，则转发到 `detour_miss`。

## 注意事项

- 检测命中但 `detour` 未配置该协议时，数据包会被丢弃（不会自动走 `detour_miss`）。
- 协议定义写在根级 `protocol_detectors`，详见 [协议检测器](protocol_detector_zh.md)。
