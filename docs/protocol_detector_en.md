# Prismux Protocol Detector

## Overview

Protocol detectors are defined at root `protocol_detectors` and used by the `filter` component in order.

## Structure

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

## Fields

| Field | Description |
|---|---|
| `signatures` | Signature array. |
| `match_logic` | `AND` or others (others are treated as OR). |
| `description` | Text description (documentation purpose only for now). |
| `priority` | Reserved field, not used for runtime evaluation order currently. |

### Signature Fields

| Field | Description |
|---|---|
| `offset` | Byte offset where matching starts. |
| `bytes` | Byte pattern to match. |
| `mask` | Bit mask applied during byte comparison. |
| `contains` | Subsequence search pattern. |
| `hex` | If `true`, `bytes/mask/contains` are hex-decoded first. |
| `length.min` | Minimum packet length. |
| `length.max` | Maximum packet length. |

## Matching Rules

1. `filter` iterates `use_proto_detectors` in order.
2. For each detector:
   - `match_logic=AND`: all signatures must match.
   - otherwise: any signature match is enough.
3. The first matched detector is returned and later detectors are not evaluated.

## Notes

- If `use_proto_detectors` references unknown detector names, those entries are skipped.
- A detector with empty `signatures` never matches.
