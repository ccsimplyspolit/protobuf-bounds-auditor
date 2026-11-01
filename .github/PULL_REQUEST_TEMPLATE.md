## Summary

Describe the detection rule, parser fix, or documentation update introduced in this Pull Request.

## Related Issue / CWE Mapping

- Closes / Addresses: #
- Affected Rule ID(s) & CWE(s):

## Verification Checklist

- [ ] `python -m unittest discover -v` passes 100% locally.
- [ ] Added unit tests covering both **vulnerable** (true positive) and **hardened** (zero false positive) inputs.
- [ ] Verified `--sarif` output remains valid SARIF v2.1.0 for GitHub Code Scanning.
- [ ] Confirmed zero sensitive, proprietary, or non-sanitized data is included in test fixtures.
