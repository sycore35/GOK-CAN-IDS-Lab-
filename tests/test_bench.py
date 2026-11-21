"""End-to-end behaviour of the virtual test bench: ECUs, coupled dynamics, arbitration, attacks, detectors."""
import os
import pytest
from src.bench import VirtualTestBench
from src.behavior import VehicleBehaviorAnalyzer
from src.can_ids import CANIntrusionDetectionEngine
from src.dbc_decoder import DBCDecoder
from src.vehicle_dynamics import speed_from_rpm_gear

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make(seed=1):
    dbc = DBCDecoder(os.path.join(BASE, "config", "can_signals.json"))
    return VirtualTestBench(dbc, CANIntrusionDetectionEngine(dbc), VehicleBehaviorAnalyzer(), seed=seed)


def collect(b, secs, step=0.1):
    out = []
    for _ in range(int(secs / step)):
        out += b.advance(step)
    return out


def alerts(recs):
    return [a for r in recs for a in r.ids_alerts], [a for r in recs for a in r.vba_alerts]


def test_all_ecus_transmit_on_schedule_and_no_false_alarms_in_normal_drive():
    b = make()
    recs = collect(b, 30.0)
    ids, vba = alerts(recs)
    assert ids == [] and vba == [], [a.rule_id for a in ids][:5]
    counts = {}
    for r in recs:
        counts[r.d.frame.arbitration_id] = counts.get(r.d.frame.arbitration_id, 0) + 1
    # 30 s at nominal cycle times (±3%)
    for aid, cycle in {0x0C4: 0.010, 0x180: 0.020, 0x200: 0.020, 0x244: 0.050, 0x2A0: 0.050, 0x320: 0.100, 0x3C0: 0.100}.items():
        assert counts[aid] == pytest.approx(30.0 / cycle, rel=0.03), hex(aid)
    assert 3 < b.bus.load_pct < 20


def test_vehicle_dynamics_visible_on_the_bus_are_coupled():
    b = make()
    recs = collect(b, 25.0)
    last = {}
    for r in recs:
        dec = b.dbc.decode_frame(r.d.frame)
        for k, s in dec["signals"].items():
            last[k] = s["value"]
    assert last["speed_kmh"] > 30
    # decoded rpm/gear/speed from CAN frames agree through the gear ratio (±10%)
    assert speed_from_rpm_gear(last["rpm"], int(last["gear_actual"])) == pytest.approx(last["speed_kmh"], rel=0.12)
    assert last["displayed_speed"] == pytest.approx(last["speed_kmh"], abs=6)   # cluster shows what the bus says


def test_speed_spoof_detected_by_kinematic_layer_and_cluster_is_fooled():
    b = make()
    collect(b, 10.0)
    b.start_attack("speed_spoof", duration=3.0)
    recs = collect(b, 3.5, 0.05)
    ids, _ = alerts(recs)
    assert any(a.rule_id == "CAN-IDS-03" for a in ids)
    st = b.attack_summary(b.attacks["speed_spoof"]) if "speed_spoof" in b.attacks else b.finished[-1]
    assert st["detected"] and st["effects"]["max_cluster_speed_error_kmh"] > 50
    assert st["injected_frames"] > 30 and st["detection_delay_ms"] < 500


def test_flooding_saturates_bus_starves_ecus_and_is_detected():
    b = make()
    collect(b, 5.0)
    before = b.bus.stats()["dropped_frames"]
    b.start_attack("flooding", duration=2.0)
    recs = collect(b, 2.0, 0.05)
    ids, _ = alerts(recs)
    assert b.bus.peak_load_pct > 90
    assert any(a.rule_id == "CAN-IDS-05" for a in ids)
    legit = [r for r in recs if r.d.frame.source.startswith("ECU_") and r.d.frame.timestamp > 5.3]
    flood = [r for r in recs if r.attack]
    assert len(flood) > 3000 and len(legit) < 40          # arbitration lets the 0x000 flood win
    assert b.bus.stats()["dropped_frames"] > before


def test_replay_attack_produces_counter_and_duplicate_evidence():
    b = make()
    collect(b, 4.0)
    b.start_attack("replay", {"record_s": 1.0}, duration=5.0)
    recs = collect(b, 5.0)
    ids, _ = alerts(recs)
    rules = {a.rule_id for a in ids}
    assert "CAN-IDS-04" in rules or "CAN-IDS-06" in rules
    assert any(r.attack and r.d.frame.arbitration_id == 0x200 for r in recs)


def test_uds_reflash_multiframe_detected_through_the_bench():
    b = make()
    collect(b, 2.0)
    b.start_attack("uds_reflash", duration=2.5)
    recs = collect(b, 2.5)
    ids, _ = alerts(recs)
    crit = [a for a in ids if a.rule_id == "CAN-IDS-07" and a.severity == "CRITICAL"]
    assert len(crit) >= 2 and "RequestDownload" in crit[0].rule_name
    assert any(u["service_name"] == "RequestDownload" for u in b.ids.uds_log)


def test_brake_spoof_with_zero_throttle_is_caught_by_behaviour_analysis():
    b = make()
    collect(b, 1.0)                                    # car is accelerating from standstill
    b.start_attack("brake_spoof", duration=5.0)
    recs = collect(b, 6.0)
    _, vba = alerts(recs)
    assert any(a["rule_id"] == "VBA-01" for a in vba), [a["rule_id"] for a in vba]


def test_speed_masquerade_evades_all_ids_layers_but_behaviour_analysis_catches_it():
    b = make()
    collect(b, 12.0)
    b.start_attack("speed_spoof_stealth", duration=9.0)
    recs = collect(b, 10.0)
    ids, vba = alerts(recs)
    during = [a for a in ids if a.timestamp < 12.0 + 9.0]       # the hand-back to the real ABS at the end is visible, by design
    assert not any(a.rule_id in ("CAN-IDS-02", "CAN-IDS-03", "CAN-IDS-06") for a in during)
    assert any(a["rule_id"] == "VBA-02" for a in vba), [a["rule_id"] for a in vba]
    assert 0x244 not in b.ecus["ECU_Brake"].muted_ids       # genuine ABS restored after the attack


def test_fuzzing_is_seeded_and_flagged_by_whitelist():
    def run(seed):
        b = make(seed)
        collect(b, 2.0)
        b.start_attack("fuzzing", duration=2.0)
        recs = collect(b, 2.0)
        return [(r.d.frame.arbitration_id, r.d.frame.data) for r in recs if r.attack], alerts(recs)[0]
    f1, a1 = run(5)
    f2, _ = run(5)
    f3, _ = run(6)
    assert f1 == f2 and f1 != f3 and len(f1) > 200
    assert any(a.rule_id == "CAN-IDS-01" for a in a1)


def test_silenced_ecu_stops_transmitting_and_manual_driver_controls_apply():
    b = make()
    collect(b, 1.0)
    b.ecus["ECU_Engine"].online = False
    recs = collect(b, 1.0)
    assert not any(r.d.frame.arbitration_id == 0x180 for r in recs)
    b.set_driver(mode="manual", throttle_pct=0.0, brake_pct=0.0)
    collect(b, 2.0)
    assert b.physics.throttle_pct < 5


def test_attack_expires_and_summary_is_kept():
    b = make()
    b.start_attack("unauthorized_id", duration=0.5)
    collect(b, 2.0)
    assert "unauthorized_id" not in b.attacks and b.finished[-1]["id"] == "unauthorized_id"
    assert b.finished[-1]["detected"] and "CAN-IDS-01" in b.finished[-1]["alerts_by_rule"]
