import os
import struct
import pytest
from src.dbc_decoder import DBCDecoder, calc_crc8_sae_j1850
from src.can_frame import CANFrame

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "can_signals.json")


def test_sae_j1850_crc():
    test_data = b"\x00\x01\x02\x03\x04"
    crc = calc_crc8_sae_j1850(test_data)
    assert isinstance(crc, int)
    assert 0 <= crc <= 255
    # Determinism
    assert calc_crc8_sae_j1850(test_data) == crc
    # Invalidation on change
    assert calc_crc8_sae_j1850(b"\x00\x01\x02\x03\x05") != crc


def test_dbc_decode_speed():
    decoder = DBCDecoder(CONFIG_PATH)
    assert decoder.is_known_id(0x244)
    assert not decoder.is_known_id(0x999)

    # Pack 75.50 km/h -> raw = 7550 (0x1D7E)
    raw_spd = int(75.50 / 0.01)
    raw_odo = int(12345.0 / 0.1)
    payload = struct.pack("<HI2s", raw_spd, raw_odo, b"\x00\x00")
    frame = CANFrame(0x244, payload, 8)

    res = decoder.decode_frame(frame)
    assert res["decoded"] is True
    assert res["name"] == "Vehicle_Speed_Status"
    signals = res["signals"]
    assert abs(signals["speed_kmh"]["value"] - 75.50) < 0.1
    assert abs(signals["odometer_km"]["value"] - 12345.0) < 0.5


def test_standard_vector_dbc_file_parsing():
    """Validates parsing standard Vector ASCII .dbc syntax (BO_ and SG_ definitions)."""
    dbc_path = os.path.join(BASE_DIR, "config", "can_signals.dbc")
    assert os.path.exists(dbc_path), "can_signals.dbc must exist"

    decoder = DBCDecoder(dbc_path)
    assert decoder.format_type == "VECTOR_ASCII_DBC"
    assert decoder.is_known_id(384)  # 0x180 Engine_Telemetry
    assert decoder.is_known_id(580)  # 0x244 Vehicle_Speed_Status
    assert decoder.is_known_id(512)  # 0x200 Brake_Safety_Control
    assert decoder.is_known_id(196)  # 0x0C4 Steering_Sensor
    assert decoder.is_known_id(800)  # 0x320 Body_Status

    # Verify message 512 signals: brake_pressure_bar, gear_position, rolling_counter, crc8_checksum
    brake_def = decoder.get_message_def(512)
    assert brake_def["name"] == "Brake_Safety_Control"
    sig_names = [s["name"] for s in brake_def["signals"]]
    assert "brake_pressure_bar" in sig_names
    assert "rolling_counter" in sig_names
    assert "crc8_checksum" in sig_names


def test_standard_dbc_vs_json_parity():
    """Proves exact parity between Vector ASCII .dbc and synthetic .json decoders."""
    dbc_path = os.path.join(BASE_DIR, "config", "can_signals.dbc")
    json_path = os.path.join(BASE_DIR, "config", "can_signals.json")

    dec_dbc = DBCDecoder(dbc_path)
    dec_json = DBCDecoder(json_path)

    assert dec_dbc.format_type == "VECTOR_ASCII_DBC"
    assert dec_json.format_type == "SYNTHETIC_JSON_SCHEMA"

    # Frame 0x180: Engine RPM = 3000 (raw = 12000), Temp = 85 (raw = 125)
    payload = struct.pack("<HBB4s", 12000, 125, 50, b"\x00\x00\x00\x00")
    frame = CANFrame(0x180, payload, 8)

    res_dbc = dec_dbc.decode_frame(frame)
    res_json = dec_json.decode_frame(frame)

    assert res_dbc["name"] == res_json["name"] == "Engine_Telemetry"
    assert res_dbc["signals"]["rpm"]["value"] == res_json["signals"]["rpm"]["value"] == 3000.0
    assert res_dbc["signals"]["engine_temp"]["value"] == res_json["signals"]["engine_temp"]["value"] == 85.0


def test_little_endian_vs_big_endian(tmp_path):
    """Verifies correct decoding for both little-endian (Intel @1) and big-endian (Motorola @0)."""
    test_dbc = tmp_path / "endian_test.dbc"
    test_dbc.write_text(
        "BO_ 100 Endian_Msg: 8 Test_ECU\n"
        " SG_ little_sig : 0|16@1+ (1.0,0) [0|65535] \"\" Test_ECU\n"
        " SG_ big_sig : 23|16@0+ (1.0,0) [0|65535] \"\" Test_ECU\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(test_dbc))
    # Bytes: 0x34, 0x12 -> little endian = 0x1234 (4660)
    # Bytes: 0x12, 0x34 -> big endian = 0x1234 (4660); Motorola start bit is the MSB (bit 23 = byte 2 bit 7)
    payload = bytes([0x34, 0x12, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00])
    frame = CANFrame(100, payload, 8)
    res = decoder.decode_frame(frame)

    assert res["decoded"] is True
    assert res["signals"]["little_sig"]["raw"] == 0x1234
    assert res["signals"]["big_sig"]["raw"] == 0x1234
    assert res["signals"]["little_sig"]["value"] == 4660.0
    assert res["signals"]["big_sig"]["value"] == 4660.0


def test_signed_vs_unsigned_signals(tmp_path):
    """Verifies signed two's complement (@1-) vs unsigned (@1+) decoding."""
    test_dbc = tmp_path / "sign_test.dbc"
    test_dbc.write_text(
        "BO_ 200 Sign_Msg: 8 Test_ECU\n"
        " SG_ unsigned_16 : 0|16@1+ (1.0,0) [0|65535] \"\" Test_ECU\n"
        " SG_ signed_16 : 16|16@1- (0.1,0) [-3276.8|3276.7] \"deg\" Test_ECU\n"
        " SG_ signed_8 : 32|8@1- (1.0,0) [-128|127] \"C\" Test_ECU\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(test_dbc))
    # unsigned_16 = 0xFFFF (65535)
    # signed_16 = 0xFFFF (-1 in two's complement -> physical: -0.1)
    # signed_8 = 0xFE (-2 in two's complement -> physical: -2.0)
    payload = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00])
    frame = CANFrame(200, payload, 8)
    res = decoder.decode_frame(frame)

    assert res["decoded"] is True
    assert res["signals"]["unsigned_16"]["raw"] == 65535
    assert res["signals"]["unsigned_16"]["value"] == 65535.0
    assert res["signals"]["signed_16"]["raw"] == -1
    assert res["signals"]["signed_16"]["value"] == -0.1
    assert res["signals"]["signed_8"]["raw"] == -2
    assert res["signals"]["signed_8"]["value"] == -2.0


def test_factor_offset_and_min_max_bounds(tmp_path):
    """Verifies factor/offset computation and in_range bounds checking."""
    test_dbc = tmp_path / "bounds_test.dbc"
    test_dbc.write_text(
        "BO_ 300 Bounds_Msg: 4 Test_ECU\n"
        " SG_ sensor_val : 0|16@1+ (0.5,-100.0) [-100.0|100.0] \"psi\" Test_ECU\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(test_dbc))

    # Raw = 200 -> physical = 200 * 0.5 - 100 = 0.0 (in range)
    frame_in = CANFrame(300, struct.pack("<H2s", 200, b"\x00\x00"), 4)
    res_in = decoder.decode_frame(frame_in)
    assert res_in["signals"]["sensor_val"]["value"] == 0.0
    assert res_in["signals"]["sensor_val"]["in_range"] is True

    # Raw = 500 -> physical = 500 * 0.5 - 100 = 150.0 (exceeds max 100.0)
    frame_out = CANFrame(300, struct.pack("<H2s", 500, b"\x00\x00"), 4)
    res_out = decoder.decode_frame(frame_out)
    assert res_out["signals"]["sensor_val"]["value"] == 150.0
    assert res_out["signals"]["sensor_val"]["in_range"] is False


def test_multiplexor_indicator_parsing(tmp_path):
    """Verifies parsing of DBC files containing multiplexer indicator syntax (M, m0, m1)."""
    test_dbc = tmp_path / "mux_test.dbc"
    test_dbc.write_text(
        "BO_ 400 Mux_Msg: 8 Test_ECU\n"
        " SG_ mode_selector M : 0|8@1+ (1,0) [0|3] \"mode\" Test_ECU\n"
        " SG_ voltage_mode0 m0 : 8|16@1+ (0.1,0) [0|500] \"V\" Test_ECU\n"
        " SG_ current_mode1 m1 : 8|16@1+ (0.01,0) [0|100] \"A\" Test_ECU\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(test_dbc))
    msg_def = decoder.get_message_def(400)
    assert msg_def is not None
    signals = {s["name"]: s for s in msg_def["signals"]}

    assert signals["mode_selector"]["mux"] == "M"
    assert signals["voltage_mode0"]["mux"] == "m0"
    assert signals["current_mode1"]["mux"] == "m1"


def test_extended_29bit_can_id_parsing(tmp_path):
    """Verifies support for standard 11-bit vs Vector extended 29-bit CAN IDs (bit 31 set)."""
    # Extended ID 0x18F00503 (418383107). In DBC, bit 31 set: 418383107 | 0x80000000 = 2565350659
    ext_raw = 418383107 | 0x80000000
    test_dbc = tmp_path / "ext_id_test.dbc"
    test_dbc.write_text(
        f"BO_ {ext_raw} Extended_Telemetry: 8 Test_ECU\n"
        " SG_ battery_soc : 0|8@1+ (0.5,0) [0|100] \"%\" Test_ECU\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(test_dbc))
    # Frame on bus uses standard 29-bit arbitration ID 0x18F00503 (418383107)
    assert decoder.is_known_id(418383107)
    assert decoder.is_known_id(ext_raw)

    msg_def = decoder.get_message_def(418383107)
    assert msg_def["name"] == "Extended_Telemetry"
    assert msg_def["is_extended"] is True
    assert msg_def["id_dec"] == 418383107

    frame = CANFrame(418383107, bytes([80, 0, 0, 0, 0, 0, 0, 0]), 8, is_extended_id=True)
    res = decoder.decode_frame(frame)
    assert res["decoded"] is True
    assert res["signals"]["battery_soc"]["value"] == 40.0


def test_dlc_and_signal_length_truncation():
    """Verifies safe handling when frame data is shorter than DBC signal definition."""
    decoder = DBCDecoder(os.path.join(BASE_DIR, "config", "can_signals.dbc"))
    # Vehicle_Speed_Status expects 8 bytes (speed at byte 0-1, odo at byte 2-5)
    # Pass truncated 2-byte payload
    short_frame = CANFrame(580, bytes([0x7E, 0x1D]), 2)
    res = decoder.decode_frame(short_frame)

    assert res["decoded"] is True
    assert res["signals"]["speed_kmh"]["valid"] is True
    # Odometer starts at byte 2, so it should be marked invalid without crashing
    assert res["signals"]["odometer_km"]["valid"] is False


def test_malformed_syntax_and_comments_resilience(tmp_path):
    """Verifies parser does not crash on empty lines, comments, or unexpected tokens."""
    malformed_dbc = tmp_path / "malformed.dbc"
    malformed_dbc.write_text(
        "VERSION \"\"\n"
        "// C++ style comment line\n"
        "# Shell style comment line\n"
        "CM_ BO_ 100 \"Comment about message\";\n"
        "VAL_ 100 turn_signal 0 \"OFF\" 1 \"LEFT\" 2 \"RIGHT\";\n"
        "\n"  # blank line
        "INVALID_HEADER_TOKEN ignored\n"
        "BO_ 100 Valid_Msg: 8 Node1\n"
        " SG_ valid_sig : 0|8@1+ (1,0) [0|255] \"\" Node2\n"
        " SG_ corrupted line with missing fields\n",
        encoding="utf-8"
    )

    decoder = DBCDecoder(str(malformed_dbc))
    assert decoder.is_known_id(100)
    msg_def = decoder.get_message_def(100)
    assert len(msg_def["signals"]) == 1
    assert msg_def["signals"][0]["name"] == "valid_sig"


def test_sae_j1850_crc_scoping_isolation():
    """Verifies that SAE J1850 CRC-8 is strictly scoped to message 0x200 and not universal."""
    decoder = DBCDecoder(os.path.join(BASE_DIR, "config", "can_signals.dbc"))

    brake_def = decoder.get_message_def(512)  # 0x200
    engine_def = decoder.get_message_def(384)  # 0x180
    speed_def = decoder.get_message_def(580)   # 0x244

    # 0x200 Brake_Safety_Control explicitly defines application CRC and counter
    brake_sigs = [s["name"] for s in brake_def["signals"]]
    assert "crc8_checksum" in brake_sigs
    assert "rolling_counter" in brake_sigs

    # Non-safety telemetry messages do NOT mandate J1850 CRC-8
    assert "crc8_checksum" not in [s["name"] for s in engine_def["signals"]]
    assert "crc8_checksum" not in [s["name"] for s in speed_def["signals"]]

