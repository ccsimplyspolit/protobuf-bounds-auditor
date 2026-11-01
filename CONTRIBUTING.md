# Contributing to `protobuf-bounds-auditor`

Thank you for helping improve `protobuf-bounds-auditor`! Contributions adding high-signal vulnerability detection rules, CWE/SARIF mappings, parser edge-case handling, and test fixtures are welcome.

## Code of Conduct

Participation in this project is governed by our [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). For security defects or parser bypasses, please follow our private disclosure process in [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Development Environment

- **Runtime:** Python `3.10+` (standard library only; zero mandatory third-party runtime dependencies).
- **Clone & Verify:**
  ```bash
  git clone https://github.com/ccsimplyspolit/protobuf-bounds-auditor.git
  cd protobuf-bounds-auditor
  python -m unittest discover -v
  ```

## Adding or Modifying Detection Rules

Currently supported rule families: `PB-001, PB-002, PB-003, PB-004, PB-005`.

When proposing a new rule or refining an existing analyzer check:

1. **Ground in Real Defect Patterns:** Map every rule to exact CWE identifiers and document the concrete vulnerability invariant being enforced.
2. **Minimize False Positives:** Provide both a **vulnerable fixture** (demonstrating true-positive detection) and a **hardened/safe fixture** (verifying zero false positives on properly bounds-checked or sanitized inputs).
3. **Preserve SARIF v2.1.0 Compatibility:** Ensure `ruleId`, severity level, line locations, and remediation guidance serialize cleanly into SARIF v2.1.0 for GitHub Code Scanning.
4. **Run Full Verification Before Submitting:**
   ```bash
   python -m unittest discover -v
   python proto_audit.py samples/ --sarif > audit.sarif
   python proto_audit.py samples/subtick_usercmd.proto --generate-fuzzer CBaseUserCmdPB > fuzzer_harness.cc
   ```

## Pull Request Process

1. Fork the repository and create a focused topic branch (`feat/rule-...` or `fix/...`).
2. Ensure all existing and newly added `unittest` cases pass with `0` warnings or regressions.
3. Complete the checklist in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
