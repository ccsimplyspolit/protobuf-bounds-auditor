import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from proto_audit import (
    audit_proto_text,
    emit_sarif,
    generate_lpm_harness,
    validate_wire_stream,
    main,
)

SAMPLE_SCHEMA = """
syntax = "proto2";

message CSubtickMoveStep {
    optional uint64 button = 1;
    optional bool pressed = 2;
    optional float when = 3;
    optional float yaw_delta = 9;
}

message CBaseUserCmdPB {
    optional int32 client_tick = 2;
    optional uint32 prediction_offset_ticks_x256 = 17;
    repeated CSubtickMoveStep subtick_moves = 18;
    repeated uint32 bounded_ids = 19 [(nanopb).max_count = 16];
    optional CBaseUserCmdPB previous_cmd = 20;
    optional bytes raw_telemetry = 21;
    optional float pitch_delta = 22;
}
"""

ALLMAN_SCHEMA = """
syntax = "proto2";

message CMsgSteamDatagramSessionCryptInfo
{
    repeated int32 ciphers = 5;
    optional float pitch_angle = 6;
    optional uint32 tick_count = 7;
}
"""


class TestProtoAudit(unittest.TestCase):
    def test_detects_all_five_rules(self):
        findings = audit_proto_text(SAMPLE_SCHEMA)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PB-001", rule_ids)
        self.assertIn("PB-002", rule_ids)
        self.assertIn("PB-003", rule_ids)
        self.assertIn("PB-004", rule_ids)
        self.assertIn("PB-005", rule_ids)

        fields = {f.field_name for f in findings}
        self.assertIn("subtick_moves", fields)
        self.assertNotIn("bounded_ids", fields)
        self.assertIn("yaw_delta", fields)
        self.assertIn("prediction_offset_ticks_x256", fields)
        self.assertIn("previous_cmd", fields)
        self.assertIn("raw_telemetry", fields)

    def test_detects_allman_brace_messages(self):
        findings = audit_proto_text(ALLMAN_SCHEMA, "steamnetworkingsockets_messages.proto")
        self.assertEqual(len(findings), 3)
        self.assertEqual({f.rule_id for f in findings}, {"PB-001", "PB-002", "PB-003"})

    def test_emits_valid_sarif_v2_1_0(self):
        findings = audit_proto_text(SAMPLE_SCHEMA, "usercmd.proto")
        sarif = emit_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], "1.2.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(findings))

    def test_generates_lpm_fuzzer_harness_all_rules(self):
        findings = audit_proto_text(SAMPLE_SCHEMA, "usercmd.proto")
        harness = generate_lpm_harness(findings, root_message="CBaseUserCmdPB")
        self.assertIn("DEFINE_PROTO_FUZZER(const CBaseUserCmdPB& input)", harness)
        self.assertIn("input.subtick_moves_size() > kMaxRepeatedElements", harness)
        self.assertIn("!std::isfinite(static_cast<double>(input.pitch_delta()))", harness)
        self.assertIn("input.prediction_offset_ticks_x256() > kMaxWindowOffset", harness)
        self.assertIn("input.has_previous_cmd()", harness)
        self.assertIn("input.raw_telemetry().size() > kMaxBytePayloadLength", harness)

    def test_dynamic_wire_validator_valid_payload(self):
        # Construct valid protobuf wire chunk:
        # Field 1 (Varint, value 150): tag = (1 << 3) | 0 = 0x08, val = 0x96 0x01
        # Field 2 (Length-delimited, string "ok"): tag = (2 << 3) | 2 = 0x12, len = 2, data = b"ok"
        wire_data = bytes([0x08, 0x96, 0x01, 0x12, 0x02, ord('o'), ord('k')])
        report = validate_wire_stream(wire_data, max_depth=16)
        self.assertTrue(report.valid)
        self.assertEqual(report.fields_parsed, 2)
        self.assertEqual(len(report.errors), 0)

    def test_dynamic_wire_validator_detects_recursion_limit_exceeded(self):
        # Create nested length-delimited payload that exceeds max_depth
        # Field 1 (tag 0x0A, length-delimited) containing Field 1 containing Field 1...
        payload = b""
        for _ in range(5):
            payload = bytes([0x0A, len(payload)]) + payload

        # Test with max_depth=2, should detect PB-004 violation
        report = validate_wire_stream(payload, max_depth=2)
        self.assertFalse(report.valid)
        self.assertTrue(any("Recursion limit exceeded" in err for err in report.errors))

    def test_dynamic_wire_validator_detects_out_of_bounds_length(self):
        # Field 1, wire_type 2, claims length 100, but only 2 bytes follow
        corrupt_wire = bytes([0x0A, 100, 0x01, 0x02])
        report = validate_wire_stream(corrupt_wire)
        self.assertFalse(report.valid)
        self.assertTrue(any("exceeds wire bounds" in err for err in report.errors))

    def test_cli_modes_and_wire_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proto_file = Path(tmpdir) / "test.proto"
            bin_file = Path(tmpdir) / "test.bin"
            proto_file.write_text(SAMPLE_SCHEMA, encoding="utf-8")
            bin_file.write_bytes(bytes([0x08, 0x01]))

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([str(proto_file)])
            self.assertEqual(rc, 0)
            self.assertIn("Total findings: 8", buf.getvalue())

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--validate-wire", str(bin_file)])
            self.assertEqual(rc, 0)
            self.assertIn("Wire Validation: VALID", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
