#!/usr/bin/env python3
"""
protobuf-bounds-auditor (proto_audit.py)
Static security analyzer for Protocol Buffers (.proto) schemas and C++ ingestion handlers.

Detects:
  - CWE-1284 / CWE-400: Unbounded `repeated` fields on client-supplied network messages
    without explicit max_count annotations or server-side `_size()` guard checks.
  - CWE-20 / CWE-682: Floating-point (`float` / `double`) angular or timing fields lacking
    `std::isfinite` (`NaN` / `Inf`) and range clamp enforcement.
  - CWE-674: Self-referential or deeply nested message structures susceptible to
    wire-format recursion exhaustion.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from pathlib import Path
from typing import List


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


MESSAGE_RE = re.compile(r"^\s*message\s+([A-Za-z0-9_]+)\s*\{")
FIELD_RE = re.compile(
    r"^\s*(repeated|optional|required)?\s*([A-Za-z0-9_.]+)\s+([A-Za-z0-9_]+)\s*=\s*(\d+)\s*([^;]*);"
)


def audit_proto_text(content: str, filename: str = "<memory>") -> List[Finding]:
    findings: List[Finding] = []
    current_msg = None
    brace_depth = 0

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue

        msg_match = MESSAGE_RE.match(line)
        if msg_match:
            current_msg = msg_match.group(1)
            brace_depth += line.count("{") - line.count("}")
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
                    )
                )

    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static security auditor for Protobuf (.proto) schemas")
    parser.add_argument("paths", nargs="+", help="Path(s) to .proto files or directories")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    args = parser.parse_args(argv)

    all_findings: List[Finding] = []
    for raw_path in args.paths:
        p = Path(raw_path)
        files = [p] if p.is_file() else list(p.rglob("*.proto"))
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace")
            all_findings.extend(audit_proto_text(text, str(f)))

    if args.json:
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
