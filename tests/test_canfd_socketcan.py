import sys
import pytest
from src.can_frame import CANFrame
from src.canfd import (CANFDFrame, dlc_to_len, len_to_dlc, next_valid_length, estimate_frame_time, FD_VALID_LENGTHS)
from src.socketcan_backend import SocketCANBackend


def test_fd_dlc_mapping_is_exact():
    assert [dlc_to_len(d) for d in range(16)] == [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]
    for ln in FD_VALID_LENGTHS:
        assert dlc_to_len(len_to_dlc(ln)) == ln
    with pytest.raises(ValueError):
        len_to_dlc(9)
    with pytest.raises(ValueError):
        dlc_to_len(16)
    assert next_valid_length(9) == 12 and next_valid_length(49) == 64 and next_valid_length(0) == 0


def test_fd_frame_strict_and_padded():
    f = CANFDFrame(0x400, bytes(64), brs=True)
    assert f.dlc == 15 and len(f.data) == 64
    with pytest.raises(ValueError):
        CANFDFrame(0x400, bytes(10))                  # 10 is not a legal FD length
    with pytest.raises(ValueError):
        CANFDFrame.padded(0x400, bytes(65))
    p = CANFDFrame.padded(0x400, b"\x01\x02\x03" * 5, pad=0xAA)   # 15 -> 16
    assert len(p.data) == 16 and p.data[-1] == 0xAA and p.dlc == 10
    with pytest.raises(ValueError):
        CANFDFrame(0x800, b"")                        # 12-bit id on standard frame


def test_brs_speeds_up_data_phase_and_fd_beats_classic_for_64_bytes():
    slow = estimate_frame_time(64, brs=False)
    fast = estimate_frame_time(64, brs=True)
    assert fast < slow * 0.6
    d = CANFDFrame(0x400, bytes(64), brs=True).describe()
    assert d["classic_equivalent_frames"] == 8 and d["speedup_vs_classic"] > 2.0


def test_conversion_to_bus_frame_is_distinct_fd_type():
    fd = CANFDFrame(0x123, bytes(range(24)), brs=True, source="ADAS")
    cf = fd.to_can_frame()
    assert isinstance(cf, CANFrame) and cf.is_fd and cf.brs and cf.dlc == 12 and len(cf.data) == 24
    assert cf.source == "ADAS"
    assert CANFrame(0x123, bytes(8)).is_fd is False  # classic path is unaffected


def test_socketcan_reports_unavailable_on_macos_and_falls_back():
    b = SocketCANBackend(platform="darwin")
    st = b.status()
    assert st["available"] is False and st["fallback"] == "simulator" and "Linux-only" in st["reason"]
    assert b.mirror(CANFrame(0x100, b"\0")) is False


def test_socketcan_linux_without_python_can():
    def boom():
        raise ImportError("no module named can")
    st = SocketCANBackend(platform="linux", loader=boom).status()
    assert not st["available"] and "python-can" in st["reason"] and st["python_can_installed"] is False


def test_socketcan_linux_with_fake_python_can_mirrors_frames():
    sent = []

    class FakeBus:
        def __init__(self, **kw): self.kw = kw
        def send(self, m): sent.append(m)
        def shutdown(self): pass

    class FakeCan:
        Bus = FakeBus
        class Message:
            def __init__(self, **kw): self.__dict__.update(kw)
    b = SocketCANBackend(platform="linux", loader=lambda: FakeCan)
    assert b.status()["available"] and b.status()["backend"] == "python-can/socketcan"
    assert b.mirror(CANFrame(0x244, b"\x01\x02")) is True
    assert sent[0].arbitration_id == 0x244 and sent[0].data == b"\x01\x02"


def test_socketcan_linux_missing_interface_gives_setup_hint():
    class FakeCan:
        class Bus:
            def __init__(self, **kw): raise OSError("No such device")
    st = SocketCANBackend(platform="linux", loader=lambda: FakeCan).status()
    assert not st["available"] and "vcan" in st["setup_hint"] and "No such device" in st["reason"]


def test_real_host_probe_never_raises():
    st = SocketCANBackend().status()
    assert "available" in st
    if sys.platform == "darwin":
        assert st["available"] is False
