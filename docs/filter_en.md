# Prismux Filter Component

## Overview

The `filter` component routes packets based on protocol detection results. It is used for protocol-aware traffic splitting.

## Parameters

| Field | Required | Default | Description |
|---|---|---|---|
| `type` | Yes | - | Must be `filter`. |
| `tag` | Yes | - | Unique component identifier. |
| `use_proto_detectors` | No | `[]` | Detector names, evaluated in order. |
| `detour` | No | `{}` | Mapping: protocol name -> target components. |
| `detour_miss` | No | `[]` | Fallback targets when no detector matches. |

## Example

```yaml
- type: filter
  tag: client_filter
  use_proto_detectors: [wg, game]
  detour:
    wg: [wg_forward]
    game: [game_forward]
  detour_miss: [default_forward]
```

## Behavior

1. Evaluates detectors in `use_proto_detectors` order.
2. On match, sets `packet.proto` and forwards using `detour[protocol]`.
3. If no detector matches, forwards to `detour_miss`.

## Notes

- If a detector matches but `detour` has no entry for that protocol, the packet is dropped.
- Detector definitions are under root `protocol_detectors`; see [Protocol Detector](protocol_detector_en.md).
