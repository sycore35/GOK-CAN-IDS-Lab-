"""ISO-TP/UDS reassembly wired into the main CAN IDS engine (Layer 7)."""
import os
import struct
from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder
from src.can_ids import CANIntrusionDetectionEngine

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_engine():
    return CANIntrusionDetectionEngine(DBCDecoder(os.path.join(BASE, "config", "can_signals.json")))


def reflash_frames(aid=0x7E0, t0=2.0):
    # UDS 0x34 RequestDownload, 15 bytes, segmented as FF + 2 CF
    ff = CANFrame(aid, bytes([0x10, 0x0F, 0x34, 0x00, 0x44, 0x00, 0x10, 0x00]), 8, timestamp=t0)
    cf1 = CANFrame(aid, bytes([0x21, 0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC]), 8, timestamp=t0 + 0.001)
    cf2 = CANFrame(aid, bytes([0x22, 0xDD, 0xEE, 0, 0, 0, 0, 0]), 8, timestamp=t0 + 0.002)
    return ff, cf1, cf2


def test_multiframe_0x34_reflash_raises_critical_alarm_at_standstill():
    ids = make_engine()
    out = []
    for f in reflash_frames():
        out += ids.process_frame(f)
    uds = [a for a in out if a.rule_id == "CAN-IDS-07"]
    assert len(uds) == 1
    assert uds[0].severity == "CRITICAL"
    assert "RequestDownload" in uds[0].rule_name
    # the alert is on the completing consecutive frame, in the alert log
    assert uds[0] in list(ids.alerts)
    assert ids.rule_hit_counts["CAN-IDS-07"] == 1


def test_multiframe_in_motion_uses_firewall_text_once():
    ids = make_engine()
    ids.process_frame(CANFrame(0x244, struct.pack("<HI2s", 6000, 100, b"\0\0"), 8, timestamp=1.0))
    out = []
    for f in reflash_frames(t0=1.1):
        out += ids.process_frame(f)
    uds = [a for a in out if a.rule_id == "CAN-IDS-07"]
    assert len(uds) == 1 and "Prohibited" in uds[0].rule_name and uds[0].severity == "CRITICAL"


def test_first_frame_alone_does_not_alarm_but_sequence_error_does():
    ids = make_engine()
    ff, cf1, cf2 = reflash_frames()
    assert [a for a in ids.process_frame(ff) if a.rule_id.startswith("CAN-IDS-07")] == []
    bad = CANFrame(0x7E0, bytes([0x23, 1, 2, 3, 4, 5, 6, 7]), 8, timestamp=2.002)
    out = ids.process_frame(bad)
    assert any(a.rule_id == "CAN-IDS-07C" and "SEQUENCE" in a.rule_name.upper() for a in out)


def test_orphan_consecutive_frame_flagged_and_benign_read_not():
    ids = make_engine()
    orphan = CANFrame(0x7E0, bytes([0x21, 1, 2, 3, 4, 5, 6, 7]), 8, timestamp=1.0)
    assert any(a.rule_id == "CAN-IDS-07C" for a in ids.process_frame(orphan))
    vin_read = CANFrame(0x7E0, bytes([0x03, 0x22, 0xF1, 0x90, 0, 0, 0, 0]), 8, timestamp=2.0)
    assert [a for a in ids.process_frame(vin_read) if a.rule_id.startswith("CAN-IDS-07")] == []


def test_uds_messages_are_logged_for_inspection():
    ids = make_engine()
    for f in reflash_frames():
        ids.process_frame(f)
    log = ids.uds_log
    assert log and log[-1]["service_name"] == "RequestDownload"
    assert log[-1]["risk"] == "CRITICAL" and log[-1]["reassembled"] is True and log[-1]["length"] == 15
