import os
import struct
import pytest
from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder
from src.can_ids import CANIntrusionDetectionEngine
from src.rules_engine import RuleSet

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def engine(path=None):
    e = CANIntrusionDetectionEngine(DBCDecoder(os.path.join(BASE, "config", "can_signals.json")))
    e.custom_rules = RuleSet(path)
    return e


def speed_frame(kmh, t):
    return CANFrame(0x244, struct.pack("<HI2s", int(kmh / 0.01), 0, b"\0\0"), 8, timestamp=t)


def test_signal_threshold_rule_applies_live_and_can_be_disabled(tmp_path):
    e = engine(str(tmp_path / "r.json"))
    rule = e.custom_rules.add({"name": "Overspeed", "type": "signal_threshold", "arb_id": "0x244",
                               "signal": "speed_kmh", "op": ">", "value": 120, "severity": "high"})
    assert rule["id"] == "CUST-001" and rule["arb_id"] == 0x244 and rule["severity"] == "HIGH"
    assert not [a for a in e.process_frame(speed_frame(100, 1.0)) if a.rule_id == "CUST-001"]
    hit = [a for a in e.process_frame(speed_frame(125, 2.0)) if a.rule_id == "CUST-001"]
    assert len(hit) == 1 and hit[0].severity == "HIGH" and "speed_kmh" in hit[0].evidence
    e.custom_rules.update("CUST-001", {"enabled": False})
    assert not [a for a in e.process_frame(speed_frame(125, 3.0)) if a.rule_id == "CUST-001"]


def test_rate_payload_delta_and_dlc_rules():
    e = engine()
    e.custom_rules.add({"name": "Rate", "type": "rate", "arb_id": 0x320, "max_count": 3, "window_ms": 100})
    e.custom_rules.add({"name": "Unlock", "type": "payload_match", "arb_id": "0x320", "pattern_hex": "00", "mask_hex": "01"})
    e.custom_rules.add({"name": "Jump", "type": "signal_delta", "signal": "speed_kmh", "max_delta": 20})
    e.custom_rules.add({"name": "Len", "type": "dlc_mismatch", "arb_id": 0x320})
    hits = []
    for i in range(5):
        hits += e.process_frame(CANFrame(0x320, b"\x01\0\0\0", 4, timestamp=1 + i * 0.01))
    assert any(a.rule_name == "Rate" for a in hits)
    assert not any(a.rule_name == "Unlock" for a in hits)             # 0x01 & mask 0x01 != 0
    unlock = e.process_frame(CANFrame(0x320, b"\x00\0\0\0", 4, timestamp=2.0))
    assert any(a.rule_name == "Unlock" for a in unlock)
    e.process_frame(speed_frame(50, 3.0))
    assert any(a.rule_name == "Jump" for a in e.process_frame(speed_frame(90, 3.05)))
    assert any(a.rule_name == "Len" for a in e.process_frame(CANFrame(0x320, b"\x01\0", 2, timestamp=4.0)))


def test_validation_errors_are_readable():
    rs = RuleSet()
    for bad, msg in [({"name": "", "type": "rate"}, "name"),
                     ({"name": "x", "type": "nope"}, "Unknown rule type"),
                     ({"name": "x", "type": "signal_threshold", "signal": "a", "op": "~", "value": 1}, "Operator"),
                     ({"name": "x", "type": "payload_match", "pattern_hex": "ZZ"}, "hex"),
                     ({"name": "x", "type": "rate", "max_count": 0, "window_ms": 10, "arb_id": 1}, "max_count"),
                     ({"name": "x", "type": "rate", "max_count": 2, "window_ms": 10}, "specific CAN ID"),
                     ({"name": "x", "type": "signal_threshold", "signal": "a", "op": ">", "value": 1, "severity": "BAD"}, "Severity")]:
        with pytest.raises(ValueError, match=msg):
            rs.add(bad)
    assert rs.list() == []


def test_rules_persist_across_restart(tmp_path):
    p = str(tmp_path / "r.json")
    a = RuleSet(p)
    a.add({"name": "R1", "type": "signal_threshold", "signal": "rpm", "op": ">", "value": 6000})
    a.add({"name": "R2", "type": "rate", "arb_id": 0x180, "max_count": 5, "window_ms": 50})
    a.delete("CUST-001")
    b = RuleSet(p)
    assert [r["name"] for r in b.list()] == ["R2"]
    assert b.add({"name": "R3", "type": "dlc_mismatch"})["id"] == "CUST-003"
