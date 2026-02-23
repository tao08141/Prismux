# Prismux IP Router Component

## Overview

The `ip_router` component routes by source IP/CIDR. First match wins; otherwise it uses `detour_miss`.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `ip_router`. |
| `tag` | Yes | - | Unique component identifier. |
| `rules` | No | `[]` | Routing rule list (first match wins). |
| `detour_miss` | No | `[]` | Fallback targets when no rule matches. |
| `geoip_mmdb` | No | `""` | Local MMDB path. If present, loaded at startup. |
| `geoip_url` | No | `""` | Remote MMDB URL used for manual/API updates and periodic refresh. |
| `geoip_update_interval` | No | `""` | GeoIP refresh interval. Supports seconds (`86400`) or suffix (`1h`, `30m`, `2d`). |

### Rule Item

| Field | Description |
|---|---|
| `rule` | Supports `IP`, `CIDR`, and `geo:XX` formats. |
| `targets` | Target components when matched. |

## Example

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

## Behavior

1. Reads source IP from `packet.src_addr`.
2. Evaluates rules in order:
   - `IP`: exact match,
   - `CIDR`: contains match,
   - `geo:*`: country code match (`geo:US`, `geo:CN`) when GeoIP DB is loaded.
3. On first match, forwards and returns.
4. If no match (or source address missing), forwards via `detour_miss`.

## Notes

- `POST /api/ip_router_action/{tag}?action=geoip_update` triggers GeoIP download and hot-reload.
- If both `geoip_mmdb` and `geoip_url` are set, local DB is loaded first, then URL updates can replace it.
- If `detour_miss` is empty, unmatched packets are dropped.
