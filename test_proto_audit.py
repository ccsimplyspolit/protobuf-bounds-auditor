import unittest
from proto_audit import audit_proto_text

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
        self.assertIn("yaw_delta", fields)
        self.assertIn("prediction_offset_ticks_x256", fields)


if __name__ == "__main__":
    unittest.main()
