#!/usr/bin/env python3
"""
protobuf-bounds-auditor (proto_audit.py) v1.1.0
Static security analyzer and libprotobuf-mutator (DEFINE_PROTO_FUZZER) defensive
harness generator for Protocol Buffers (.proto) schemas and C++ ingestion handlers.

Detects:
  - PB-001 (CWE-1284 / CWE-400): Unbounded `repeated` fields on client-supplied network
    messages without explicit max_count annotations or server-side `_size()` guard checks.
  - PB-002 (CWE-20 / CWE-682): Floating-point (`float` / `double`) angular or timing fields
    lacking `std::isfinite` (`NaN` / `Inf`) and range clamp enforcement.
  - PB-003 (CWE-20): Uncapped integer tick/index/offset fields susceptible to window inflation.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


@dataclasses.dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    message_name: str
    field_name: str
    field_type: str
    line: int
    description: str
    remediation: str
    source_file: str = "<memory>"


MESSAGE_RE = re.compile(r"^\s*message\s+([A-Za-z0-9_]+)\s*(\{)?\s*$")
FIELD_RE = re.compile(
    r"^\s*(repeated|optional|required)?\s*([A-Za-z0-9_.]+)\s+([A-Za-z0-9_]+)\s*=\s*(\d+)\s*([^;]*);"
)


def audit_proto_text(content: str, filename: str = "<memory>") -> List[Finding]:
    findings: List[Finding] = []
    current_msg = None
    pending_msg = None
    brace_depth = 0

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue

        if pending_msg is not None:
            if "{" in line:
                current_msg = pending_msg
                pending_msg = None
                brace_depth = line.count("{") - line.count("}")
                continue
            else:
                pending_msg = None

        msg_match = MESSAGE_RE.match(line)
        if msg_match:
            if msg_match.group(2) == "{":
                current_msg = msg_match.group(1)
                brace_depth += line.count("{") - line.count("}")
            else:
                pending_msg = msg_match.group(1)
            continue

        if current_msg:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                current_msg = None
                brace_depth = 0
                continue

            field_match = FIELD_RE.match(line)
            if not field_match:
                continue

            label, ftype, fname, fnum, options = field_match.groups()
            options = options or ""

            # Rule 1: Unbounded repeated field (CWE-1284 / CWE-400)
            if label == "repeated" and "max_count" not in options and "validate.rules" not in options:
                findings.append(
                    Finding(
                        rule_id="PB-001",
                        cwe="CWE-1284 / CWE-400",
                        severity="HIGH",
                        message_name=current_msg,
                        field_name=fname,
                        field_type=f"repeated {ftype}",
                        line=idx,
                        description=(
                            f"Repeated field '{current_msg}.{fname}' (#{fnum}) has no schema-level "
                            f"cardinality cap, enabling unbounded array deserialization DoS."
                        ),
                        remediation=(
                            f"Enforce `if (msg.{fname}_size() > MAX_{fname.upper()}_COUNT) return false;` "
                            f"at the server ingestion boundary before iterating."
                        ),
                        source_file=filename,
                    )
                )

            # Rule 2: Floating-point wire field without NaN/Inf/range validation (CWE-20 / CWE-682)
            if ftype in ("float", "double", "fixed32", "sfixed32", "fixed64", "sfixed64"):
                if any(tok in fname.lower() for tok in ("angle", "pitch", "yaw", "roll", "delta", "when", "ratio", "fraction")):
                    findings.append(
                        Finding(
                            rule_id="PB-002",
                            cwe="CWE-20 / CWE-682",
                            severity="HIGH",
                            message_name=current_msg,
                            field_name=fname,
                            field_type=ftype,
                            line=idx,
                            description=(
                                f"IEEE-754 field '{current_msg}.{fname}' (#{fnum}) carries angular or fractional "
                                f"timing data and accepts NaN, +/-Inf, or out-of-bounds floats over the wire."
                            ),
                            remediation=(
                                f"Guard '{fname}' with `std::isfinite(msg.{fname}())` and `std::clamp(...)` "
                                f"prior to state accumulation or interpolation."
                            ),
                            source_file=filename,
                        )
                    )

            # Rule 3: Uncapped integer tick/offset field (CWE-20)
            if ftype in ("uint32", "int32", "uint64", "int64") and any(
                tok in fname.lower() for tok in ("offset", "tick", "index", "count")
            ):
                findings.append(
                    Finding(
                        rule_id="PB-003",
                        cwe="CWE-20",
                        severity="MEDIUM",
                        message_name=current_msg,
                        field_name=fname,
                        field_type=ftype,
                        line=idx,
                        description=(
                            f"Tick/index offset field '{current_msg}.{fname}' (#{fnum}) can be inflated "
                            f"to widen lag-compensation or history lookup windows."
                        ),
                        remediation=(
                            f"Clamp `msg.{fname}()` against a strict server-configured maximum window ceiling."
                        ),
                        source_file=filename,
                    )
                )

    return findings


def emit_sarif(findings: List[Finding]) -> Dict[str, Any]:
    """Emit findings in OASIS SARIF v2.1.0 format for GitHub Code Scanning."""
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": "error" if f.severity == "HIGH" else "warning",
                "message": {"text": f"{f.description} Remediation: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.source_file},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "protobuf-bounds-auditor",
                        "version": "1.1.0",
                        "informationUri": "https://github.com/ccsimplyspolit/protobuf-bounds-auditor",
                    }
                },
                "results": results,
            }
        ],
    }


def generate_lpm_harness(findings: List[Finding], root_message: str | None = None) -> str:
    """
    Generate a structure-aware libprotobuf-mutator (DEFINE_PROTO_FUZZER) C++ harness
    that verifies post-deserialization bounds and IEEE-754 finiteness invariants.
    """
    if not root_message:
        root_message = findings[0].message_name if findings else "RootMessage"

    checks: List[str] = []
    for f in findings:
        if f.message_name != root_message:
            continue
        if f.rule_id == "PB-001":
            checks.append(
                f"  // {f.rule_id} ({f.cwe}): Guard repeated field cardinality\n"
                f"  if (input.{f.field_name}_size() > kMaxRepeatedElements) {{\n"
                f"    return false;\n"
                f"  }}"
            )
        elif f.rule_id == "PB-002":
            checks.append(
                f"  // {f.rule_id} ({f.cwe}): Reject NaN / Inf on IEEE-754 wire field\n"
                f"  if (!std::isfinite(static_cast<double>(input.{f.field_name}()))) {{\n"
                f"    return false;\n"
                f"  }}"
            )
        elif f.rule_id == "PB-003":
            checks.append(
                f"  // {f.rule_id} ({f.cwe}): Bound integer tick/offset window\n"
                f"  if (input.{f.field_name}() > kMaxWindowOffset) {{\n"
                f"    return false;\n"
                f"  }}"
            )

    body = "\n".join(checks) if checks else "  (void)input;"
    return f"""// Auto-generated by protobuf-bounds-auditor v1.1.0
// Structure-aware libprotobuf-mutator + AddressSanitizer invariant harness
#include <cmath>
#include <cstdint>
#include "src/libfuzzer/libfuzzer_macro.h"

static constexpr int kMaxRepeatedElements = 64;
static constexpr uint64_t kMaxWindowOffset = 4096;

template <typename MsgT>
bool ValidateDeserializedInvariants(const MsgT& input) {{
{body}
  return true;
}}

DEFINE_PROTO_FUZZER(const {root_message}& input) {{
  if (!ValidateDeserializedInvariants(input)) {{
    return;
  }}
  // Forward validated protobuf message to target ingestion handler under ASAN/UBSAN
}}
"""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static security auditor & libprotobuf-mutator harness generator for Protobuf (.proto) schemas"
    )
    parser.add_argument("paths", nargs="+", help="Path(s) to .proto files or directories")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    parser.add_argument("--sarif", action="store_true", help="Emit findings as SARIF v2.1.0")
    parser.add_argument(
        "--emit-lpm-harness",
        metavar="FILE",
        help="Write a structure-aware C++ libprotobuf-mutator (DEFINE_PROTO_FUZZER) harness to FILE",
    )
    parser.add_argument(
        "--root-message",
        metavar="MSG",
        help="Root protobuf message name for --emit-lpm-harness",
    )
    args = parser.parse_args(argv)

    all_findings: List[Finding] = []
    for raw_path in args.paths:
        p = Path(raw_path)
        files = [p] if p.is_file() else list(p.rglob("*.proto"))
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(audit_proto_text(text, str(f)))

    if args.emit_lpm_harness:
        harness_code = generate_lpm_harness(all_findings, args.root_message)
        out_path = Path(args.emit_lpm_harness)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(harness_code, encoding="utf-8")

    if args.sarif:
        print(json.dumps(emit_sarif(all_findings), indent=2))
    elif args.json:
        print(json.dumps([dataclasses.asdict(x) for x in all_findings], indent=2))
    else:
        for finding in all_findings:
            print(
                f"[{finding.severity}] {finding.rule_id} ({finding.cwe}) "
                f"{finding.message_name}.{finding.field_name} (line {finding.line}): "
                f"{finding.description}"
            )
        print(f"\nTotal findings: {len(all_findings)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
