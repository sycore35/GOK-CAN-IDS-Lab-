import pytest
from src.can_frame import CANFrame
from src.sim_bus import SimBus


def F(i, n=8):
    return CANFrame(i, bytes(n), n)


def test_lowest_id_wins_arbitration_and_loser_is_counted():
    bus = SimBus()
    bus.attach("A"); bus.attach("B"); bus.attach("C")
    bus.enqueue("A", F(0x300), 0.0)
    bus.enqueue("B", F(0x100), 0.0)
    bus.enqueue("C", F(0x200), 0.0)
    out = bus.advance(0.01)
    assert [d.frame.arbitration_id for d in out] == [0x100, 0x200, 0x300]
    assert [d.arb_losses for d in out] == [0, 1, 2]
    assert bus.total_arb_losses == 3
    # transmissions are serialized: each starts when the previous ended
    assert out[1].start_t == pytest.approx(out[0].end_t)
    assert out[2].start_t == pytest.approx(out[1].end_t)


def test_frame_timing_matches_bitrate():
    bus = SimBus(bitrate_bps=500_000)
    f = F(0x100)
    bus.enqueue("A", f, 0.0)
    (d,) = bus.advance(0.01)
    assert d.end_t == pytest.approx(f.calc_wire_bits() / 500_000)
    assert d.frame.timestamp == d.end_t


def test_bus_load_reflects_traffic_and_saturates_under_flood():
    bus = SimBus()
    bus.attach("A", mailbox_size=100)
    # 100 fps of 8-byte frames ~ 100*131/500000 = 2.6%
    for k in range(50):
        bus.enqueue("A", F(0x100), k * 0.01)
    bus.advance(0.5)
    assert 2.0 < bus.load_pct < 3.5
    bus2 = SimBus()
    bus2.attach("X", mailbox_size=10_000)
    for k in range(3000):
        bus2.enqueue("X", F(0x000), 0.0)
    bus2.advance(0.5)
    assert bus2.load_pct > 95.0


def test_flood_starves_lower_priority_traffic_and_overflows_mailbox():
    bus = SimBus()
    bus.attach("ENG", mailbox_size=4)
    bus.attach("ATK", mailbox_size=10_000)
    for k in range(2000):
        bus.enqueue("ATK", F(0x000), 0.0)
    delivered_eng = 0
    for k in range(20):                       # engine wants to send every 10 ms for 200 ms
        bus.enqueue("ENG", F(0x180), k * 0.01)
        delivered_eng += sum(1 for d in bus.advance((k + 1) * 0.01) if d.node == "ENG")
    assert delivered_eng == 0                 # starvation: flood always wins arbitration
    assert bus.node_stats["ENG"]["dropped"] > 0 and bus.node_stats["ENG"]["arb_losses"] > 0


def test_queue_latency_grows_when_bus_is_busy():
    bus = SimBus()
    bus.attach("A", mailbox_size=100)
    for i in range(10):
        bus.enqueue("A", F(0x100 + i), 0.0)
    out = bus.advance(0.1)
    lat = [d.latency_s for d in out]
    assert lat == sorted(lat) and lat[-1] > 8 * lat[0] * 0.9


def test_fd_frame_with_brs_is_faster_than_without():
    bus = SimBus()
    a = CANFrame(0x100, bytes(64), 15, is_fd=True, brs=True)
    b = CANFrame(0x101, bytes(64), 15, is_fd=True, brs=False)
    assert bus.frame_duration(a) < 0.6 * bus.frame_duration(b)


def test_frames_after_horizon_wait_for_next_advance():
    bus = SimBus()
    bus.enqueue("A", F(0x100), 0.05)
    assert bus.advance(0.01) == []
    assert len(bus.advance(0.1)) == 1
