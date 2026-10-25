import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from proto_audit import audit_proto_text, emit_sarif, generate_lpm_harness, main

SAMPLE_SCHEMA = """
syntax = "proto2";

message CSubtickMoveStep {
    optional uint64 button = 1;
    optional bool pressed = 2;
    optional float when = 3;
    optional float pitch_delta = 8;
    optional float yaw_delta = 9;
}

message CBaseUserCmdPB {
    optional int32 client_tick = 2;
    optional uint32 prediction_offset_ticks_x256 = 17;
    repeated CSubtickMoveStep subtick_moves = 18;
    repeated uint32 bounded_ids = 19 [(nanopb).max_count = 16];
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
    def test_detects_unbounded_repeated_and_float_deltas(self):
        findings = audit_proto_text(SAMPLE_SCHEMA)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PB-001", rule_ids)
        self.assertIn("PB-002", rule_ids)
        self.assertIn("PB-003", rule_ids)
        fields = {f.field_name for f in findings}
        self.assertIn("subtick_moves", fields)
        self.assertNotIn("bounded_ids", fields)
        self.assertIn("yaw_delta", fields)
        self.assertIn("prediction_offset_ticks_x256", fields)

    def test_detects_allman_brace_messages(self):
        findings = audit_proto_text(ALLMAN_SCHEMA, "steamnetworkingsockets_messages.proto")
        self.assertEqual(len(findings), 3)
        self.assertEqual({f.rule_id for f in findings}, {"PB-001", "PB-002", "PB-003"})

    def test_emits_valid_sarif_v2_1_0(self):
        findings = audit_proto_text(SAMPLE_SCHEMA, "usercmd.proto")
        sarif = emit_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], "1.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(findings))

    def test_generates_lpm_fuzzer_harness_all_rules(self):
        findings = audit_proto_text(ALLMAN_SCHEMA, "steamnetworkingsockets_messages.proto")
        harness = generate_lpm_harness(findings, root_message="CMsgSteamDatagramSessionCryptInfo")
        self.assertIn("DEFINE_PROTO_FUZZER(const CMsgSteamDatagramSessionCryptInfo& input)", harness)
        self.assertIn("input.ciphers_size() > kMaxRepeatedElements", harness)
        self.assertIn("!std::isfinite(static_cast<double>(input.pitch_angle()))", harness)
        self.assertIn("input.tick_count() > kMaxWindowOffset", harness)

    def test_cli_modes_json_sarif_and_generate_fuzzer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proto_file = Path(tmpdir) / "test.proto"
            harness_file = Path(tmpdir) / "harness.cc"
            proto_file.write_text(ALLMAN_SCHEMA, encoding="utf-8")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([str(proto_file)])
            self.assertEqual(rc, 0)
            self.assertIn("Total findings: 3", buf.getvalue())

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([str(proto_file), "--json"])
            self.assertEqual(rc, 0)
            parsed_json = json.loads(buf.getvalue())
            self.assertEqual(len(parsed_json), 3)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([str(proto_file), "--sarif", "--emit-lpm-harness", str(harness_file)])
            self.assertEqual(rc, 0)
            parsed_sarif = json.loads(buf.getvalue())
            self.assertEqual(parsed_sarif["version"], "2.1.0")
            self.assertTrue(harness_file.exists())

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([str(proto_file), "--generate-fuzzer", "CMsgSteamDatagramSessionCryptInfo"])
            self.assertEqual(rc, 0)
            self.assertIn("DEFINE_PROTO_FUZZER(const CMsgSteamDatagramSessionCryptInfo& input)", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
