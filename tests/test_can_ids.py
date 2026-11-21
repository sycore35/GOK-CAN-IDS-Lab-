import os
import struct
import time
import pytest
from src.dbc_decoder import DBCDecoder, calc_crc8_sae_j1850
from src.can_frame import CANFrame
from src.can_ids import CANIntrusionDetectionEngine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "can_signals.json")


@pytest.fixture
def ids():
    dbc = DBCDecoder(CONFIG_PATH)
    return CANIntrusionDetectionEngine(dbc)


def test_rule01_unknown_id(ids):
    # Foreign diagnostic ID 0x6F1 not in DBC
    f = CANFrame(0x6F1, b"\x02\x10\x03\x00\x00\x00\x00\x00", 8)
    alerts = ids.process_frame(f)
    assert any(a.rule_id == "CAN-IDS-01" for a in alerts)


def test_rule03_kinematic_jump(ids):
    t0 = 100.0
    # Normal frame at 50 km/h
    raw_50 = int(50.0 / 0.01)
    f1 = CANFrame(0x244, struct.pack("<HI2s", raw_50, 1000, b"\x00\x00"), 8, timestamp=t0)
    alerts1 = ids.process_frame(f1)
    assert not any(a.rule_id == "CAN-IDS-03" for a in alerts1)

    # Frame 0.05s later jumping to 180 km/h (Δv = 130 km/h in 0.05s = 2600 km/h/s, massive violation!)
    t1 = t0 + 0.05
    raw_180 = int(180.0 / 0.01)
    f2 = CANFrame(0x244, struct.pack("<HI2s", raw_180, 1000, b"\x00\x00"), 8, timestamp=t1)
    alerts2 = ids.process_frame(f2)
    assert any(a.rule_id == "CAN-IDS-03" for a in alerts2)


def test_rule04_crc_and_rolling_counter(ids):
    t0 = 200.0
    # Frame with valid counter 1 and valid CRC
    payload1_partial = struct.pack("<HBBBBB", int(20.0 / 0.01), 2, 0, 0, 0, 1)
    crc1 = calc_crc8_sae_j1850(payload1_partial)
    f1 = CANFrame(0x200, payload1_partial + bytes([crc1]), 8, timestamp=t0)
    alerts1 = ids.process_frame(f1)
    assert not any(a.rule_id == "CAN-IDS-04" for a in alerts1)

    # Frame with corrupted CRC (0xFF)
    t1 = t0 + 0.02
    payload2_partial = struct.pack("<HBBBBB", int(20.0 / 0.01), 2, 0, 0, 0, 2)
    f2 = CANFrame(0x200, payload2_partial + bytes([0xFF]), 8, timestamp=t1)
    alerts2 = ids.process_frame(f2)
    assert any(a.rule_id == "CAN-IDS-04" and "CRC-8" in a.rule_name for a in alerts2)


def test_rule05_bus_load(ids):
    f = CANFrame(0x180, b"\x00" * 8, 8)
    # Bus load at 82% (threshold is 75%)
    alerts = ids.process_frame(f, current_bus_load_pct=82.0)
    assert any(a.rule_id == "CAN-IDS-05" for a in alerts)


def test_threshold_tuning(ids):
    ids.tune_thresholds({"max_accel_kmh_per_sec": 3000.0})
    assert ids.max_accel_kmh_s == 3000.0


def test_rule04_rolling_counter_skip(ids):
    t0 = 300.0
    payload1 = struct.pack("<HBBBBB", int(20.0 / 0.01), 2, 0, 0, 0, 1)
    f1 = CANFrame(0x200, payload1 + bytes([calc_crc8_sae_j1850(payload1)]), 8, timestamp=t0)
    ids.process_frame(f1)

    # Send counter=5 instead of expected 2 (counter jump / message drop)
    t1 = t0 + 0.02
    payload_jump = struct.pack("<HBBBBB", int(20.0 / 0.01), 2, 0, 0, 0, 5)
    f2 = CANFrame(0x200, payload_jump + bytes([calc_crc8_sae_j1850(payload_jump)]), 8, timestamp=t1)
    alerts = ids.process_frame(f2)
    assert any(a.rule_id == "CAN-IDS-04" and "Rolling Counter" in a.rule_name for a in alerts)


def test_rule06_rapid_payload_replay(ids):
    t0 = 400.0
    payload = struct.pack("<HI2s", int(80.0 / 0.01), 1000, b"\x00\x00")
    f1 = CANFrame(0x244, payload, 8, timestamp=t0)
    ids.process_frame(f1)

    # Re-inject identical payload just 2ms later (replay window threshold is 15ms)
    t1 = t0 + 0.002
    f2 = CANFrame(0x244, payload, 8, timestamp=t1)
    alerts = ids.process_frame(f2)
    assert any(a.rule_id == "CAN-IDS-06" for a in alerts)


def test_bus_load_boundary_thresholds(ids):
    f = CANFrame(0x180, b"\x00" * 8, 8)
    # Exactly below threshold: 74.9%
    alerts_below = ids.process_frame(f, current_bus_load_pct=74.9)
    assert not any(a.rule_id == "CAN-IDS-05" for a in alerts_below)

    # Exactly at threshold: 75.0%
    alerts_at = ids.process_frame(f, current_bus_load_pct=75.0)
    assert any(a.rule_id == "CAN-IDS-05" for a in alerts_at)

    # Above threshold: 75.1%
    alerts_above = ids.process_frame(f, current_bus_load_pct=75.1)
    assert any(a.rule_id == "CAN-IDS-05" for a in alerts_above)


def test_architectural_crc_distinction():
    """
    Architectural Proof:
    CAN link-layer wire bits (ISO 11898-1) include transceiver 15-bit CRC and stuff bits.
    In contrast, application-layer SAE J1850 is strictly an 8-bit checksum within the 8-byte payload.
    """
    # 8-byte frame
    payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    frame = CANFrame(0x200, payload, 8)

    # Wire bits must reflect full physical frame overhead (~128 bits)
    assert frame.calc_wire_bits() >= 111

    # Application CRC is 1 byte (0..255) computed purely on payload slice
    app_crc = calc_crc8_sae_j1850(payload[:7])
    assert 0 <= app_crc <= 255


def test_message_profile_specific_crc_and_counter_isolation(ids):
    """
    Verifies that CAN-IDS-04 (Application CRC-8 & Rolling Counter) applies strictly
    to message 0x200 (Brake_Safety_Control) profile and does NOT falsely flag
    other telemetry frames (0x180, 0x244, 0x0C4, 0x320) that have different payload definitions.
    """
    # 1. Non-brake message (0x180 Engine_Telemetry) with arbitrary bytes: MUST NOT trigger CAN-IDS-04
    f_engine = CANFrame(0x180, b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0", 8, timestamp=100.0)
    alerts_engine = ids.process_frame(f_engine)
    assert not any(a.rule_id == "CAN-IDS-04" for a in alerts_engine)

    # 2. Safety-critical brake message (0x200 Brake_Safety_Control) with invalid CRC: MUST trigger CAN-IDS-04
    payload_bad_crc = struct.pack("<HBBBBB", int(35.0 / 0.01), 2, 0, 0, 0, 1) + b"\x00"  # Invalid CRC 0x00
    f_brake_bad = CANFrame(0x200, payload_bad_crc, 8, timestamp=101.0)
    alerts_brake_bad = ids.process_frame(f_brake_bad)
    assert any(a.rule_id == "CAN-IDS-04" and "CRC-8" in a.rule_name for a in alerts_brake_bad)

    # 3. Brake message with valid CRC and counter: MUST pass without CAN-IDS-04 alert
    payload_clean = struct.pack("<HBBBBB", int(35.0 / 0.01), 2, 0, 0, 0, 2)
    valid_crc = calc_crc8_sae_j1850(payload_clean)
    f_brake_good = CANFrame(0x200, payload_clean + bytes([valid_crc]), 8, timestamp=101.02)
    alerts_brake_good = ids.process_frame(f_brake_good)
    assert not any(a.rule_id == "CAN-IDS-04" for a in alerts_brake_good)


def test_engine_operates_with_vector_dbc_file():
    """Verifies CANIntrusionDetectionEngine initializes and operates seamlessly with Vector ASCII .dbc."""
    import os
    from src.dbc_decoder import DBCDecoder
    dbc_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "can_signals.dbc")
    dbc_decoder = DBCDecoder(dbc_file)
    assert dbc_decoder.format_type == "VECTOR_ASCII_DBC"

    engine = CANIntrusionDetectionEngine(dbc_decoder)
    # Feed valid speed frame
    payload = struct.pack("<HI2s", int(90.0 / 0.01), 5000, b"\x00\x00")
    f = CANFrame(0x244, payload, 8, timestamp=500.0)
    alerts = engine.process_frame(f)
    assert len(alerts) == 0  # No intrusion on legitimate frame


