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
python proto_audit.py path/to/protos/ --sarif > audit.sarif
python proto_audit.py path/to/schema.proto --generate-fuzzer CBaseUserCmdPB > fuzzer_harness.cc
```

### Features in v1.1.0
- **Allman & K&R Brace Normalization:** Supports both single-line (`message Foo {`) and multi-line Allman (`message Foo\n{`) Protocol Buffers definitions (e.g., `ValveSoftware/GameNetworkingSockets` and `onnx/onnx`).
- **SARIF v2.1.0 Export (`--sarif`):** Produces GitHub Code Scanning compatible SARIF reports.
- **Automated `libprotobuf-mutator` Harness Generation (`--generate-fuzzer <MessageName>`):** Emits a ready-to-compile C++ `DEFINE_PROTO_FUZZER` harness enforcing cardinality (`<= 64`) and IEEE-754 finiteness (`std::isfinite`) invariants under Clang `-fsanitize=fuzzer,address,undefined`.

### Running Unit Tests

```bash
python -m unittest test_proto_audit.py
```

---

## Related Advisories

- **[CVD-2026-CS2-001: Unbounded Protobuf `subtick_moves` Deserialization & Angular Velocity Validation Failure](https://github.com/ccsimplyspolit/cs-telemetry-internals/blob/main/advisories/valve_server_disclosures/H1_Report_Subtick_Input_Validation.md)**
- **[CVD-2026-CS2-003: Missing Server-Side View-Angle Pitch Clamping & AnimGraph NaN Extrapolation Crash](https://github.com/ccsimplyspolit/cs-telemetry-internals/blob/main/advisories/valve_server_disclosures/H1_Report_Viewangle_Spoof_Crash.md)**
