"""SocketCAN receive path: frames from a real/virtual interface reach the IDS pipeline."""
import collections

from src.can_frame import CANFrame
from src.socketcan_backend import SocketCANBackend


class _Msg:
    def __init__(self, arbitration_id, data, is_extended_id=False, is_fd=False, bitrate_switch=False, timestamp=0.0,
                 is_remote_frame=False, is_error_frame=False):
        self.arbitration_id, self.data, self.is_extended_id = arbitration_id, bytearray(data), is_extended_id
        self.is_fd, self.bitrate_switch, self.timestamp = is_fd, bitrate_switch, timestamp
        self.is_remote_frame, self.is_error_frame = is_remote_frame, is_error_frame


class _FakeCan:
    Message = _Msg

    def __init__(self):
        self.rx = collections.deque()
        self.sent = []
        outer = self

        class Bus:
            def __init__(self, interface, channel):
                self.channel = channel

            def recv(self, timeout=None):
                return outer.rx.popleft() if outer.rx else None

            def send(self, msg):
                outer.sent.append(msg)

            def shutdown(self):
                pass
        self.Bus = Bus


def _backend():
    fake = _FakeCan()
    return SocketCANBackend(channel="vcan0", platform="linux", loader=lambda: fake), fake


def test_poll_converts_messages_to_tagged_frames():
    b, fake = _backend()
    assert b.available
    fake.rx.extend([_Msg(0x244, b"\x10\x27\0\0\0\0\0\0"), _Msg(0x18FEF100, b"\x01\x02", is_extended_id=True)])
    frames = b.poll()
    assert [f.arbitration_id for f in frames] == [0x244, 0x18FEF100]
    assert frames[0].data == b"\x10\x27\0\0\0\0\0\0" and frames[0].dlc == 8
    assert frames[1].is_extended_id and frames[1].dlc == 2
    assert all(f.source == "SOCKETCAN:vcan0" for f in frames)
    assert b.status()["frames_received"] == 2 and b.poll() == []


def test_poll_skips_error_frames_and_respects_limit_and_toggle():
    b, fake = _backend()
    fake.rx.extend([_Msg(0x100, b"", is_error_frame=True)] + [_Msg(0x100 + i, b"\x00") for i in range(10)])
    assert len(b.poll(max_frames=4)) == 4
    b.set_rx(False)
    assert b.poll() == [] and b.status()["rx_enabled"] is False
    b.set_rx(True)
    assert len(b.poll()) == 6


def test_poll_is_noop_when_unavailable():
    b = SocketCANBackend(platform="darwin")
    assert b.poll() == [] and b.status()["frames_received"] == 0


def test_received_frames_are_not_mirrored_back():
    b, fake = _backend()
    assert b.mirror(CANFrame(0x244, bytes(8), source="ECU_Brake")) is True
    assert b.mirror(CANFrame(0x244, bytes(8), source="SOCKETCAN:vcan0")) is False
    assert len(fake.sent) == 1


def test_external_frame_reaches_ids_through_the_bench():
    """A frame read from SocketCAN with an ID unknown to the DBC must raise CAN-IDS-01, like any bus frame."""
    import copy
    from src.bench import VirtualTestBench
    from src.can_ids import CANIntrusionDetectionEngine
    from src.dbc_decoder import DBCDecoder
    from src.coverage import _config

    dbc = DBCDecoder.from_config(copy.deepcopy(_config()))
    bench = VirtualTestBench(dbc, CANIntrusionDetectionEngine(dbc), None, seed=1)
    bench.advance(0.5)
    b, fake = _backend()
    fake.rx.append(_Msg(0x6F1, b"\x02\x10\x03\0\0\0\0\0"))
    for f in b.poll():
        assert bench.inject(f)
    recs = bench.advance(0.05)
    ext = [r for r in recs if r.d.frame.source == "SOCKETCAN:vcan0"]
    assert ext, "external frame was not delivered on the simulated bus"
    assert any(a.rule_id == "CAN-IDS-01" for r in ext for a in r.ids_alerts)


def test_rx_toggle_endpoint():
    from fastapi.testclient import TestClient
    from src.api import app
    with TestClient(app) as c:
        st = c.post("/api/socketcan/rx", json={"enabled": False}).json()
        assert st["rx_enabled"] is False and "frames_received" in st
        assert c.get("/api/socketcan/status").json()["rx_enabled"] is False
        assert c.post("/api/socketcan/rx", json={"enabled": True}).json()["rx_enabled"] is True
        assert c.post("/api/socketcan/rx", json={}).status_code == 422
