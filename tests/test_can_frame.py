import pytest
from src.can_frame import CANFrame


def test_standard_frame_creation():
    frame = CANFrame(0x180, b"\x01\x02\x03\x04", dlc=4)
    assert frame.arbitration_id == 0x180
    assert frame.hex_id == "0x180"
    assert frame.dlc == 4
    assert frame.hex_data == "01 02 03 04"
    assert not frame.is_extended_id


def test_extended_frame_masking():
    frame = CANFrame(0x18DAF110, b"\x00" * 8, is_extended_id=True)
    assert frame.arbitration_id == 0x18DAF110
    assert frame.hex_id == "0x18DAF110"
    assert frame.is_extended_id


def test_wire_bits_calculation():
    f_empty = CANFrame(0x200, b"", dlc=0)
    bits_0 = f_empty.calc_wire_bits()
    assert bits_0 > 45 # Base overhead with stuff factor

    f_full = CANFrame(0x200, b"\xFF" * 8, dlc=8)
    bits_8 = f_full.calc_wire_bits()
    assert bits_8 > bits_0
    assert bits_8 > 100 # Standard 8-byte CAN frame is ~111..130 bits
