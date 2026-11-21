"""SocketCAN, candump, SecOC, UDS firewall, CAN-FD/J1939 ve VAL_ testleri."""
import os
import struct
import pytest
from fastapi.testclient import TestClient

from src.can_frame import CANFrame
from src.can_bus import VirtualCANBus, SocketCANTransport, export_candump_log, import_candump_log
from src.dbc_decoder import DBCDecoder
from src.can_ids import CANIntrusionDetectionEngine, CANAlert, compute_secoc_mac
from src.api import app


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def sample_dbc():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "can_signals.json")
    return DBCDecoder(config_path)


def test_socketcan_transport_and_candump_logs():
    """Verifies SocketCANTransport fallback and candump -L import/export."""
    transport = SocketCANTransport(interface="vcan0", nominal_bitrate_kbps=500)
    stats = transport.get_stats()
    assert "socketcan_active" in stats
    assert "fallback_mode" in stats
    assert stats["fallback_mode"] in ("VIRTUAL_IN_MEMORY", "KERNEL_SOCKETCAN")

    # Send frames through transport
    f1 = CANFrame(0x180, b"\x00\x10\x20\x30\x40\x50\x60\x70", 8, timestamp=100.123456)
    f2 = CANFrame(0x244, b"\x01\x02\x03\x04\x05\x06\x07\x08", 8, timestamp=100.150000)
    transport.send(f1)
    transport.send(f2)

    assert transport.total_frames_sent >= 2

    # Export to candump -L format
    candump_text = export_candump_log([f1, f2], interface="vcan0")
    assert "(100.123456) vcan0 180#0010203040506070" in candump_text
    assert "(100.150000) vcan0 244#0102030405060708" in candump_text

    # Re-import candump text
    imported = import_candump_log(candump_text)
    assert len(imported) == 2
    assert imported[0].arbitration_id == 0x180
    assert imported[0].data == b"\x00\x10\x20\x30\x40\x50\x60\x70"
    assert imported[1].arbitration_id == 0x244


def test_secoc_rule04b_verification(sample_dbc):
    """Verifies AUTOSAR SecOC truncated MAC and freshness on 0x0C4."""
    engine = CANIntrusionDetectionEngine(sample_dbc)
    secret_key = b"AUTOSAR_SECOC_KEY_SECRET_32B_!!!"
    engine.secoc_key = secret_key

    # Generate valid SecOC steering frame (10ms):
    # Byte 0..3: physical payload (steering angle & rate)
    # Byte 4: Freshness counter (e.g. 1)
    # Byte 5..7: 24-bit truncated MAC
    freshness = 1
    raw_payload = struct.pack("<HH", 5000, 500)
    mac = compute_secoc_mac(secret_key, 0x0C4, raw_payload, freshness)
    valid_data = raw_payload + bytes([freshness]) + mac

    frame_valid = CANFrame(0x0C4, valid_data, 8, timestamp=10.0)
    alerts = engine.process_frame(frame_valid, bus_load_pct=10.0)
    secoc_alerts = [a for a in alerts if a.rule_id == "CAN-IDS-04B"]
    assert len(secoc_alerts) == 0, "Valid SecOC frame must not trigger alert"

    # Corrupt the MAC bytes with valid sequential freshness (freshness=2)
    corrupted_data = raw_payload + bytes([2]) + b"\xDE\xAD\xBE"
    frame_corrupt = CANFrame(0x0C4, corrupted_data, 8, timestamp=10.010)
    alerts_corrupt = engine.process_frame(frame_corrupt, bus_load_pct=10.0)
    secoc_corrupt = [a for a in alerts_corrupt if a.rule_id == "CAN-IDS-04B"]
    assert len(secoc_corrupt) == 1
    alert = secoc_corrupt[0]
    assert alert.severity == "CRITICAL"
    assert alert.qev_event_id == "QEV_SECOC_VERIFICATION_FAIL"
    assert "R155" in alert.unece_r155_code
    assert "AUTOSAR SecOC" in alert.rule_name


def test_uds_diagnostic_firewall_rule07(sample_dbc):
    """Verifies UDS Diagnostic Firewall blocks critical commands in motion."""
    engine = CANIntrusionDetectionEngine(sample_dbc)

    # Establish vehicle moving state (Speed = 60 km/h)
    speed_raw = int(60.0 / 0.01)
    speed_payload = struct.pack("<HI2s", speed_raw & 0xFFFF, 12000, b"\x00\x00")
    engine.process_frame(CANFrame(0x244, speed_payload, 8, timestamp=1.0), bus_load_pct=20.0)
    assert engine.last_vehicle_speed_kmh == 60.0

    # In motion: Diagnostic request for Programming Session (0x10 0x02) on 0x7DF
    f_prog = CANFrame(0x7DF, b"\x02\x10\x02\x00\x00\x00\x00\x00", 8, timestamp=1.010)
    alerts_prog = engine.process_frame(f_prog, bus_load_pct=20.0)
    uds_alerts = [a for a in alerts_prog if a.rule_id == "CAN-IDS-07"]
    assert len(uds_alerts) == 1
    assert "UDS" in uds_alerts[0].rule_name
    assert "R155" in uds_alerts[0].unece_r155_code

    # In motion: ECUReset (0x11) on ECU 0x7E0
    f_reset = CANFrame(0x7E0, b"\x02\x11\x01\x00\x00\x00\x00\x00", 8, timestamp=1.020)
    alerts_reset = engine.process_frame(f_reset, bus_load_pct=20.0)
    uds_resets = [a for a in alerts_reset if a.rule_id == "CAN-IDS-07"]
    assert len(uds_resets) == 1

    # SecurityAccess Brute-Force: 3 consecutive NRC 0x35 (InvalidKey)
    nrc_frame = CANFrame(0x7E8, b"\x03\x7F\x27\x35\x00\x00\x00\x00", 8, timestamp=1.030)
    engine.process_frame(nrc_frame, bus_load_pct=20.0)
    engine.process_frame(nrc_frame, bus_load_pct=20.0)
    alerts_nrc = engine.process_frame(nrc_frame, bus_load_pct=20.0)
    brute_alerts = [a for a in alerts_nrc if a.rule_id == "CAN-IDS-07B"]
    assert len(brute_alerts) == 1
    assert "R155" in brute_alerts[0].unece_r155_code


def test_isotp_pci_header_parsing():
    """Verifies ISO-TP PCI header parsing."""
    # Single Frame (PCI 0x0, DLC 3)
    f_sf = CANFrame(0x7DF, b"\x03\x22\xF1\x90\x00\x00\x00\x00", 8)
    sf_pci = f_sf.parse_isotp_pci()
    assert sf_pci is not None
    assert sf_pci["type"] in ("SF", "SINGLE_FRAME")
    assert sf_pci["data_len"] == 3

    # First Frame (PCI 0x1, total length 50 bytes = 0x032)
    f_ff = CANFrame(0x7E8, b"\x10\x32\x62\xF1\x90\xAA\xBB\xCC", 8)
    ff_pci = f_ff.parse_isotp_pci()
    assert ff_pci is not None
    assert ff_pci["type"] in ("FF", "FIRST_FRAME")
    assert ff_pci["data_len"] == 0x032

    # Consecutive Frame (PCI 0x2, seq 1)
    f_cf = CANFrame(0x7E8, b"\x21\x11\x22\x33\x44\x55\x66\x77", 8)
    cf_pci = f_cf.parse_isotp_pci()
    assert cf_pci is not None
    assert cf_pci["type"] in ("CF", "CONSECUTIVE_FRAME")
    assert cf_pci["seq_num"] == 1

    # Flow Control (PCI 0x3, flow status 0, block size 8, sep time 10)
    f_fc = CANFrame(0x7E0, b"\x30\x08\x0A\x00\x00\x00\x00\x00", 8)
    fc_pci = f_fc.parse_isotp_pci()
    assert fc_pci is not None
    assert fc_pci["type"] in ("FC", "FLOW_CONTROL")

    assert fc_pci["flow_status"] == 0
    assert fc_pci["block_size"] == 8
    assert fc_pci["sep_time"] == 10


def test_can_fd_frame_properties():
    """Verifies CAN-FD attributes and wire bits calculation."""
    payload_64 = bytes(range(64))
    fd_frame = CANFrame(0x123, payload_64, dlc=15, is_fd=True, brs=True)
    assert fd_frame.is_fd is True
    assert fd_frame.brs is True
    assert len(fd_frame.data) == 64
    wire_bits = fd_frame.calc_wire_bits()
    # CAN-FD has 67 header/crc bits + 512 payload bits + stuffing margin = ~600+ bits
    assert wire_bits >= 579


def test_j1939_pgn_parsing():
    """Verifies SAE J1939 29-bit PGN, priority, and source address parsing."""
    # Electronic Engine Controller 1 (EEC1): Priority 3, PGN 61444 (0xF004), SA 0 (Engine)
    # CAN ID: (3 << 26) | (0xF004 << 8) | 0 = 0x0CF00400
    can_id = 0x0CF00400
    frame_j1939 = CANFrame(can_id, b"\x00\x00\x00\x00\x00\x00\x00\x00", 8, is_extended_id=True)
    j1939 = frame_j1939.j1939_fields
    assert j1939 is not None
    assert j1939["priority"] == 3
    assert j1939["pgn"] == 61444
    assert j1939["pgn_hex"] == "0x00F004"
    assert j1939["source_address"] == 0


def test_val_table_and_dbc_integrity(tmp_path):
    """Verifies Vector DBC VAL_ parsing, enum resolution, and integrity checks."""
    dbc_content = """
VERSION ""
NS_ :
BS_:
BU_: ECU_BODY ECU_GW

BO_ 800 Body_Status: 4 ECU_BODY
 SG_ doors_locked : 0|1@1+ (1,0) [0|1] "" ECU_GW
 SG_ turn_signal : 1|2@1+ (1,0) [0|3] "" ECU_GW

VAL_ 800 turn_signal 0 "OFF" 1 "LEFT" 2 "RIGHT" 3 "HAZARD" ;
VAL_ 800 doors_locked 0 "UNLOCKED" 1 "LOCKED" ;
"""
    dbc_file = tmp_path / "test_body.dbc"
    dbc_file.write_text(dbc_content, encoding="utf-8")

    decoder = DBCDecoder(str(dbc_file))
    assert 800 in decoder.val_tables
    assert decoder.val_tables[800]["turn_signal"][1] == "LEFT"

    # Test decoding with enum_desc resolution
    f_turn = CANFrame(800, bytes([0x03, 0x00, 0x00, 0x00]), 4) # doors_locked=1, turn_signal=1 (0b011)
    decoded = decoder.decode_frame(f_turn)
    assert decoded["signals"]["doors_locked"]["enum_desc"] == "LOCKED"
    assert decoded["signals"]["turn_signal"]["enum_desc"] == "LEFT"

    # Test validate_dbc_integrity()
    integrity = decoder.validate_dbc_integrity()
    assert integrity["valid"] is True
    assert integrity["messages_checked"] == 1
    assert integrity["issues_count"] == 0

    # Test overlapping signal detection
    overlapping_dbc = """
BO_ 100 Bad_Msg: 2 ECU
 SG_ sig1 : 0|8@1+ (1,0) [0|255] "" ECU
 SG_ sig2 : 4|8@1+ (1,0) [0|255] "" ECU
"""
    bad_file = tmp_path / "bad.dbc"
    bad_file.write_text(overlapping_dbc, encoding="utf-8")
    bad_decoder = DBCDecoder(str(bad_file))
    bad_integrity = bad_decoder.validate_dbc_integrity()
    assert bad_integrity["valid"] is False
    assert bad_integrity["issues_count"] > 0
    assert "Signal overlap" in bad_integrity["issues"][0]


def test_candump_api_endpoints(test_client):
    """Verifies candump export and replay-log REST endpoints."""
    # Test export incident contains candump_log
    resp = test_client.get("/api/export/incident")
    assert resp.status_code == 200
    data = resp.json()
    assert "candump_log" in data

    # Test replay-log endpoint
    raw_candump = "(1234.567890) vcan0 180#0102030405060708\n(1234.577890) vcan0 200#AABBCCDDEEFF0011\n"
    replay_resp = test_client.post("/api/frames/replay-log", json={"log": raw_candump})
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["status"] == "REPLAY_COMPLETED"
    assert replay_data["frames_replayed"] == 2
