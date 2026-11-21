"""DBC editor: CRUD, validation, text round trip, decoder + IDS integration, persistence."""
import os
import struct
import pytest
from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder, extract_raw
from src.dbc_editor import DBCEditor
from src.can_ids import CANIntrusionDetectionEngine

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(BASE, "config", "can_signals.json")


@pytest.fixture
def ed(tmp_path):
    return DBCEditor(DBCDecoder(CFG), persist_path=str(tmp_path / "live.json"))


NEW_MSG = {"id_dec": 0x300, "name": "Test_Msg", "dlc": 8, "cycle_time_ms": 100, "transmitter": "ECU_X",
           "signals": [{"name": "temp_c", "start_bit": 0, "length": 12, "endian": "little", "scale": 0.1,
                       "offset": -40, "unit": "C", "min": -40, "max": 200}]}


def test_added_message_is_decoded_and_whitelisted(ed):
    ids = CANIntrusionDetectionEngine(ed.decoder)
    assert any(a.rule_id == "CAN-IDS-01" for a in ids.process_frame(CANFrame(0x300, b"\0" * 8, timestamp=1.0)))
    ed.add_message(NEW_MSG)
    raw = int((25.5 + 40) / 0.1)
    payload = raw.to_bytes(2, "little") + b"\0" * 6
    res = ed.decoder.decode_frame(CANFrame(0x300, payload))
    assert res["name"] == "Test_Msg" and res["signals"]["temp_c"]["value"] == 25.5
    assert not any(a.rule_id == "CAN-IDS-01" for a in ids.process_frame(CANFrame(0x300, payload, timestamp=2.0)))


def test_signal_edit_changes_decoded_value(ed):
    f = CANFrame(0x244, struct.pack("<HI2s", 5000, 0, b"\0\0"))
    assert ed.decoder.decode_frame(f)["signals"]["speed_kmh"]["value"] == 50.0
    ed.update_signal(0x244, "speed_kmh", {"scale": 0.02})
    assert ed.decoder.decode_frame(f)["signals"]["speed_kmh"]["value"] == 100.0


def test_validation_rejects_overlap_bounds_and_duplicates(ed):
    ed.add_message(NEW_MSG)
    with pytest.raises(ValueError, match="overlaps"):
        ed.add_signal(0x300, {"name": "x", "start_bit": 8, "length": 8})
    with pytest.raises(ValueError, match="exceeds"):
        ed.add_signal(0x300, {"name": "y", "start_bit": 60, "length": 8})
    with pytest.raises(ValueError, match="Duplicate CAN ID"):
        ed.add_message({**NEW_MSG, "name": "Other"})
    with pytest.raises(ValueError, match="factor"):
        ed.update_signal(0x300, "temp_c", {"scale": 0})
    # failed edits leave the database untouched
    assert len(ed.get_message(0x300)["signals"]) == 1


def test_motorola_signal_decode_and_encode_roundtrip(ed):
    ed.add_message({"id_dec": 0x301, "name": "Big", "dlc": 8, "signals": [
        {"name": "v", "start_bit": 7, "length": 12, "endian": "big", "scale": 1, "offset": 0, "min": 0, "max": 4095}]})
    payload = ed.decoder.encode_message("Big", {"v": 0xABC})
    assert payload[0] == 0xAB and payload[1] >> 4 == 0xC          # MSB-first, standard Motorola layout
    assert ed.decoder.decode_frame(CANFrame(0x301, payload))["signals"]["v"]["raw"] == 0xABC
    assert extract_raw(bytes([0x12, 0x34]), 7, 16, "big") == 0x1234


def test_dbc_text_export_import_roundtrip(ed):
    ed.add_message(NEW_MSG)
    text = ed.export_text()
    assert "BO_ 768 Test_Msg: 8 ECU_X" in text and "SG_ temp_c : 0|12@1+ (0.1,-40)" in text
    assert 'BA_ "GenMsgCycleTime" BO_ 768 100;' in text
    ed2 = DBCEditor(DBCDecoder(CFG))
    summary = ed2.import_text(text)
    assert summary["messages"] == 8
    m = ed2.get_message(0x300)
    assert m["cycle_time_ms"] == 100 and m["signals"][0]["scale"] == 0.1 and m["signals"][0]["offset"] == -40
    assert ed2.export_text() == text


def test_import_rejects_garbage_and_keeps_database(ed):
    with pytest.raises(ValueError):
        ed.import_text("this is not a dbc file")
    assert len(ed.snapshot()["messages"]) == 7


def test_persistence_roundtrip(ed, tmp_path):
    ed.add_message(NEW_MSG)
    cfg = DBCEditor.load_persisted(str(tmp_path / "live.json"))
    d2 = DBCDecoder.from_config(cfg)
    assert d2.is_known_id(0x300) and d2.get_message_def(0x300)["cycle_time_ms"] == 100


def test_delete_message_and_signal(ed):
    ed.delete_signal(0x180, "engine_temp")
    assert "engine_temp" not in ed.decoder.decode_frame(CANFrame(0x180, b"\0" * 8))["signals"]
    ed.delete_message(0x320)
    assert not ed.decoder.is_known_id(0x320)
