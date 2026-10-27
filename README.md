# protobuf-bounds-auditor

[![CI](https://github.com/ccsimplyspolit/protobuf-bounds-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/ccsimplyspolit/protobuf-bounds-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23641037.svg)](https://doi.org/10.5281/zenodo.23641037)
[![Category: Defensive Static Analysis](https://img.shields.io/badge/Security-Protobuf%20Schema%20Auditor-green.svg)](AUDIT_PREP.md)

Static security analyzer for Protocol Buffers (`.proto`) network schemas. Designed to identify server-side deserialization hazards (`CWE-1284`, `CWE-400`, `CWE-20`, `CWE-682`) in real-time RPC and simulation command pipelines before they reach production.

---

## Vulnerability Classes Detected

| Rule ID | CWE | Severity | Description |
|---|---|---|---|
| **PB-001** | `CWE-1284` / `CWE-400` | `HIGH` | Unbounded `repeated` fields lacking cardinality limits, enabling array-flooding Denial of Service. |
| **PB-002** | `CWE-20` / `CWE-682` | `HIGH` | IEEE-754 `float` / `double` wire fields carrying angular or fractional timing values (`yaw_delta`, `pitch_delta`, `when`) susceptible to `NaN` / `Inf` injection and interpolation instability. |
| **PB-003** | `CWE-20` | `MEDIUM` | Uncapped integer tick/offset fields (`prediction_offset_ticks_x256`, `client_tick`) allowing lag-compensation or history window inflation. |

---

## Usage

```bash
python proto_audit.py samples/subtick_usercmd.proto
python proto_audit.py samples/ --json
python proto_audit.py samples/ --sarif > audit.sarif
python proto_audit.py samples/subtick_usercmd.proto --root-message CBaseUserCmdPB --emit-lpm-harness fuzzer_harness.cc
python proto_audit.py samples/subtick_usercmd.proto --generate-fuzzer CBaseUserCmdPB > fuzzer_harness.cc
```

### Features in v1.1.0
- **Allman & K&R Brace Normalization:** Supports both single-line (`message Foo {`) and multi-line Allman (`message Foo\n{`) Protocol Buffers definitions (such as `ValveSoftware/GameNetworkingSockets`).
- **SARIF v2.1.0 Export (`--sarif`) & JSON Output (`--json`):** Produces GitHub Code Scanning compatible SARIF v2.1.0 reports and structured JSON output.
- **Automated `libprotobuf-mutator` Harness Generation (`--emit-lpm-harness` / `--generate-fuzzer <MessageName>`):** Emits a ready-to-compile C++ `DEFINE_PROTO_FUZZER` harness enforcing cardinality (`<= 64`), IEEE-754 finiteness (`std::isfinite`), and window offset invariants under Clang `-fsanitize=fuzzer,address,undefined`.
- **Included Samples & Harnesses:**
  - [`samples/subtick_usercmd.proto`](samples/subtick_usercmd.proto) — Sample simulation command schema demonstrating `PB-001`, `PB-002`, and `PB-003` detection rules.
  - [`examples/gns_lpm_invariant_harness.cc`](examples/gns_lpm_invariant_harness.cc) — Example `libprotobuf-mutator` (`DEFINE_PROTO_FUZZER`) C++ invariant harness for `CMsgSteamDatagramSessionCryptInfo`, `CMsgSteamDatagramLinkLifetimeStats`, and `CMsgSteamDatagramCertificate`.

### Running Unit Tests

```bash
python -m unittest discover -v
```

---

## Audit Preparation & Architecture Package

- **[Audit Preparation & Architecture Package (`AUDIT_PREP.md`)](AUDIT_PREP.md)** — Trail of Bits-style review goals, scope, data-flow diagram, and measured unit test verification (`5/5 PASS`, `98%` statement coverage).
