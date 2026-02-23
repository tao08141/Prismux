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
| `geoip_mmdb` | No | `""` | Reserved field, not used in current implementation. |
| `geoip_url` | No | `""` | Reserved field, not used in current implementation. |
| `geoip_update_interval` | No | `""` | Reserved field, not used in current implementation. |

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
   - `geo:*`: currently treated as non-match.
3. On first match, forwards and returns.
4. If no match (or source address missing), forwards via `detour_miss`.

## Notes

- `geo:*` syntax is accepted but GeoIP matching is not active in current Rust build.
- If `detour_miss` is empty, unmatched packets are dropped.
