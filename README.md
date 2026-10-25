# protobuf-bounds-auditor

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23640498.svg)](https://doi.org/10.5281/zenodo.23640498)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Category: Defensive Static Analysis](https://img.shields.io/badge/Security-Protobuf%20Schema%20Auditor-green.svg)]()

Static security analyzer for Protocol Buffers (`.proto`) network schemas. Designed to identify server-side deserialization hazards (`CWE-1284`, `CWE-400`, `CWE-20`, `CWE-682`) in real-time RPC and simulation command pipelines before they reach production.

---

## Vulnerability Classes Detected

| Rule ID | CWE | Severity | Description |
|---|---|---|---|
| **PB-001** | `CWE-1284` / `CWE-400` | `HIGH` | Unbounded `repeated` fields lacking cardinality limits, enabling array-flooding Denial of Service (e.g., `CVD-2026-CS2-001`). |
| **PB-002** | `CWE-20` / `CWE-682` | `HIGH` | IEEE-754 `float` / `double` wire fields carrying angular or fractional timing values (`yaw_delta`, `pitch_delta`, `when`) susceptible to `NaN` / `Inf` injection and interpolation instability. |
| **PB-003** | `CWE-20` | `MEDIUM` | Uncapped integer tick/offset fields (`prediction_offset_ticks_x256`, `client_tick`) allowing lag-compensation or history window inflation. |

---

## Usage

```bash
python proto_audit.py path/to/schema.proto
python proto_audit.py path/to/protos/ --json
```

### Running Unit Tests

```bash
python -m unittest test_proto_audit.py
```

---

## Related Advisories

- **[CVD-2026-CS2-001: Unbounded Protobuf `subtick_moves` Deserialization & Angular Velocity Validation Failure](https://github.com/ccsimplyspolit/cs-telemetry-internals/blob/main/advisories/valve_server_disclosures/H1_Report_Subtick_Input_Validation.md)**
- **[CVD-2026-CS2-003: Missing Server-Side View-Angle Pitch Clamping & AnimGraph NaN Extrapolation Crash](https://github.com/ccsimplyspolit/cs-telemetry-internals/blob/main/advisories/valve_server_disclosures/H1_Report_Viewangle_Spoof_Crash.md)**
