# Prismux IP Router 组件

## 概述

`ip_router` 组件按来源 IP/CIDR 进行规则路由，命中首条规则即转发；未命中时走 `detour_miss`。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `type` | 是 | - | 固定为 `ip_router`。 |
| `tag` | 是 | - | 组件唯一标识。 |
| `rules` | 否 | `[]` | 路由规则数组（首条命中即返回）。 |
| `detour_miss` | 否 | `[]` | 无匹配时回退目标。 |
| `geoip_mmdb` | 否 | `""` | 预留字段，当前版本未使用。 |
| `geoip_url` | 否 | `""` | 预留字段，当前版本未使用。 |
| `geoip_update_interval` | 否 | `""` | 预留字段，当前版本未使用。 |

### 规则项

| 字段 | 说明 |
|---|---|
| `rule` | 支持 `IP`、`CIDR`、`geo:XX` 三种写法。 |
| `targets` | 命中后的目标组件数组。 |

## 配置示例

```yaml
- type: ip_router
  tag: ipr
  detour_miss: [default_forward]
  rules:
    - rule: "127.0.0.1"
      targets: [forward_local]
    - rule: "192.168.1.0/24"
      targets: [forward_lan]
```

## 工作机制

1. 从 `packet.src_addr` 提取来源 IP。
2. 依序匹配规则：
   - `IP`：完全相等；
   - `CIDR`：包含判断；
   - `geo:*`：当前实现不匹配（视为未命中）。
3. 首条命中立即转发并结束。
4. 全部未命中或无法提取来源地址时，按 `detour_miss` 转发。

## 注意事项

- `geo:*` 规则语法可解析，但当前 Rust 版尚未实现 GeoIP 命中逻辑。
- 若 `detour_miss` 为空，未命中包会被丢弃。
