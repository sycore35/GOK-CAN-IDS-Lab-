import json
import os

import pytest

from src.can_frame import CANFrame
from src.coverage import record_attack
from src.ecus import BrakeECU
from src.gateway_model import A2B, B2A, DROP, FORWARD, GatewayModel, classify_domain
from src.vehicle_dynamics import VehiclePhysics
import random

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(BASE, "firmware", "gokguard", "tests", "vectors.json")


def fr(can_id, data, dlc=None, ext=False, src="ATTACKER:test", ts=1.0):
    return CANFrame(can_id, data, len(data) if dlc is None else dlc, is_extended_id=ext, timestamp=ts, source=src)


def ev(g, f, t=1.0, direction=A2B):
    return g.evaluate(f, direction, t)


def brake_frame(counter, bar=10.0, bad_crc=False):
    b = BrakeECU("ECU_Brake", VehiclePhysics(), random.Random(1))
    return fr(0x200, b.build_brake_payload(bar, 2, counter, crc=0xDE if bad_crc else None))


def test_legitimate_a_domain_traffic_passes():
    g = GatewayModel()
    for i in range(30):
        assert ev(g, fr(0x320, b"\x01\0\0\0"), 1.0 + i * 0.1) == (FORWARD, None)
        assert ev(g, fr(0x3C0, (3600).to_bytes(2, "little") + b"\0\0"), 1.05 + i * 0.1) == (FORWARD, None)
    assert g.stats["blocked"] == 0 and g.stats["passed"] == 60


@pytest.mark.parametrize("frame,rule", [
    (fr(0x555, b"\1\2"), "GW-01"),                              # not in DBC
    (fr(0x320, b"\1\0\0\0", ext=True), "GW-01"),                # extended id
    (fr(0x244, bytes(8)), "GW-01"),                             # DBC id, B-origin only
    (fr(0x7E8, b"\x03\x7f\x27\x35"), "GW-01"),                  # diagnostic response id from A
    (fr(0x320, bytes(8)), "GW-02"),                             # wrong DLC
    (fr(0x3C0, (30001).to_bytes(2, "little") + b"\0\0"), "GW-04"),
    (fr(0x7E0, b"\x02\x10\x03"), "GW-06"),
    (fr(0x6F1, b"\x02\x10\x03"), "GW-06"),
    (fr(0x7E0, b"\x02\x27\x01"), "GW-07"),
    (fr(0x7E0, b"\x10\x0f\x34\0\x44\0\x10\0"), "GW-07"),      # service in an ISO-TP first frame
    (fr(0x7DF, b"\x02\x11\x01"), "GW-07"),
    (fr(0x0C4, b"\x88\x13" + bytes(6)), "GW-10"),
    (fr(0x180, bytes([0xA0, 0x0F, 130, 20, 0, 0, 0, 0])), "GW-10"),
])
def test_each_rule_blocks(frame, rule):
    assert ev(GatewayModel(), frame) == (DROP, rule)


def test_gw03_token_bucket_refills_exactly():
    g = GatewayModel()
    f = fr(0x320, b"\1\0\0\0")
    res = [ev(g, f, 1.0 + i * 0.001)[0] for i in range(8)]
    assert res.count(FORWARD) == 4                              # burst depth 4
    assert ev(g, f, 1.057) == (FORWARD, None)                   # ~50 ms at 20 fps = one token
    assert ev(g, f, 1.0571) == (DROP, "GW-03")


def test_gw05_counter_and_crc_match_the_ecu_algorithm():
    g = GatewayModel()
    assert ev(g, brake_frame(1, bad_crc=True), 1.00) == (DROP, "GW-05")          # bad CRC
    assert ev(g, brake_frame(1), 1.02) == (DROP, "GW-10")                         # valid CRC (src/ecus.py), then critical id
    assert ev(g, brake_frame(2), 1.04) == (DROP, "GW-10")
    assert ev(g, brake_frame(2), 1.06) == (DROP, "GW-05")                         # repeated counter
    assert ev(g, brake_frame(5), 1.08) == (DROP, "GW-05")                         # jump
    assert ev(g, brake_frame(6), 1.10) == (DROP, "GW-10")                         # resynchronised
    assert ev(g, brake_frame(0), 1.12) == (DROP, "GW-05")                         # 6 -> 0 is wrong
    assert ev(g, brake_frame(7), 1.14) == (DROP, "GW-05")                         # 0 expected 1... counter state follows last frame


def test_gw08_flood_and_event_coalescing():
    g = GatewayModel()
    f = fr(0x000, b"\xAA" * 8)
    rules = [ev(g, f, 1.0 + i * 0.00025)[1] for i in range(2000)]
    assert rules.count("GW-08") > 1800 and set(rules) == {"GW-01", "GW-08"}
    assert g.stats["events_suppressed"] > 1000
    assert len(g.state()["events"]) <= 50


def test_workshop_key_and_tamper_modes():
    g = GatewayModel()
    uds = fr(0x7E0, b"\x02\x27\x01")
    assert g.mode == "normal" and ev(g, uds) == (DROP, "GW-07")
    g.set_switches(workshop_key=True)
    assert g.mode == "workshop" and ev(g, uds, 2.0) == (FORWARD, None)
    assert ev(g, fr(0x0C4, b"\x88\x13" + bytes(6)), 2.1) == (DROP, "GW-10")        # the key never opens safety critical ids
    g.set_switches(tamper=True)
    assert g.mode == "locked"
    assert ev(g, uds, 3.0) == (DROP, "GW-09")
    assert ev(g, fr(0x320, b"\1\0\0\0"), 3.1) == (DROP, "GW-09")
    assert ev(g, fr(0x244, bytes(8), src="ECU_Brake"), 3.2, B2A) == (FORWARD, None)   # B -> A still flows
    assert any(e["ev"] == "LOCKDOWN" and e["rule"] == "GW-09" for e in g.state()["events"])
    g.set_switches(tamper=False)
    assert g.mode == "locked"                     # latched, exactly like the firmware
    assert g.clear_lockdown() is True and g.mode == "workshop"
    g.set_switches(tamper=True)
    assert g.clear_lockdown() is False and g.mode == "locked"   # refused while the lid is open


def test_invalid_direction_fails_closed():
    assert GatewayModel().evaluate(fr(0x320, b"\1\0\0\0"), "X>Y", 1.0) == (DROP, "GW-01")


def test_event_line_format():
    g = GatewayModel()
    ev(g, fr(0x3C0, (30001).to_bytes(2, "little") + b"\0\0"), 12.3456)
    e = g.state()["events"][-1]
    assert {"t", "ev", "rule", "dir", "id", "dlc", "data"} <= set(e)
    assert (e["t"], e["ev"], e["rule"], e["dir"], e["id"], e["dlc"], e["data"]) == (12.345, "BLOCK", "GW-04", "A>B", "0x3C0", 4, "31750000")
    json.dumps(e)


def test_domain_classification():
    assert classify_domain("ECU_Brake") == "B"
    assert classify_domain("ATTACKER:speed_spoof") == "A"
    assert classify_domain("ATTACKER:speed_spoof_stealth") == "B"      # silenced ABS => compromised node inside B
    assert classify_domain("TESTER") == "A" and classify_domain("") == "A"


def test_observe_is_passive_and_counts_b_domain():
    g = GatewayModel()
    assert g.observe(fr(0x244, bytes(8), src="ECU_Brake")) is None
    assert g.stats["b_internal"] == 1 and g.stats["blocked"] == 0
    assert g.observe(fr(0x244, bytes(8), src="ATTACKER:speed_spoof"))[1] == "GW-01"
    assert g.observe(fr(0x244, bytes(8), src="ATTACKER:speed_spoof_stealth")) is None


def test_benign_bus_has_zero_false_positives():
    rec = record_attack("fuzzing", None, seed=1, detect=False)
    g = GatewayModel()
    for f in rec["benign"]:
        assert g.observe(f) is None                       # all ECU_* traffic: B domain, never blocked
    assert g.stats["blocked"] == 0 and g.stats["b_internal"] == len(rec["benign"])


def test_hardware_events_are_tagged():
    g = GatewayModel()
    n = g.add_hardware_events([{"t": 1.0, "ev": "BLOCK", "rule": "GW-04", "id": "0x244"}, "junk"])
    assert n == 1
    s = g.state()
    assert s["events"][-1]["source"] == "hardware" and s["stats"]["by_rule"] == {"GW-04": 1} and s["stats"]["hardware_events"] == 1


# ------------------------------------------------------------------ vectors (python side of the C parity)
@pytest.fixture(scope="module")
def vectors():
    with open(VECTORS) as fh:
        return json.load(fh)


def test_vectors_are_fresh():
    from tools.gen_guard_vectors import main
    assert main(["--check"]) == 0


def test_vectors_replay_in_python_model(vectors):
    for c in vectors["cases"]:
        g = GatewayModel()
        g.set_switches(workshop_key=c["workshop_key"], tamper=c["tamper"])
        for f in c["frames"]:
            got = g.evaluate_raw(f["id"], bool(f["ext"]), f["dlc"], bytes.fromhex(f["data"]), f["dir"], f["t_us"])
            assert got == (f["decision"], f["rule"]), (c["name"], f)


ATTACK_RULES = {   # independent expectation: which rules must stop each attack (set of rules that may appear)
    "speed_spoof": {"GW-01"}, "spoof_id": {"GW-10"}, "replay": {"GW-01", "GW-05", "GW-10"},
    "flooding": {"GW-01", "GW-08"}, "fuzzing": {"GW-01", "GW-02", "GW-06", "GW-07"}, "counter_crc_desync": {"GW-05"},
    "unauthorized_id": {"GW-06"}, "uds_diagnostic_attack": {"GW-01", "GW-06", "GW-07"}, "uds_reflash": {"GW-06", "GW-07"},
    "brake_spoof": {"GW-05", "GW-10"},
}


def test_attack_vectors_are_blocked_by_expected_rules(vectors):
    seen = set()
    for c in vectors["cases"]:
        if c["kind"] != "attack" or c["workshop_key"] or c["tamper"]:
            continue
        a = c["attack"]
        if a == "headlight_can_injection_unlock":
            assert c["summary"]["blocked"] == 0                # honest: looks like a legitimate body frame
            continue
        assert c["summary"]["blocked"] == c["summary"]["total"] > 0, a
        assert set(c["summary"]["rules"]) <= ATTACK_RULES[a], (a, c["summary"])
        seen.add(a)
    assert seen == set(ATTACK_RULES)
    assert [u["attack"] for u in vectors["unevaluated"]] == ["speed_spoof_stealth"]


def test_benign_vectors_all_forward_and_every_rule_covered(vectors):
    byname = {c["name"]: c for c in vectors["cases"]}
    for n in ("benign_a_domain", "benign_b_to_a", "uds_with_workshop_key", "attack_with_workshop_key:uds_reflash"):
        assert all(f["decision"] == FORWARD for f in byname[n]["frames"]), n
    rules = {f["rule"] for c in vectors["cases"] for f in c["frames"] if f["rule"]}
    assert rules == {f"GW-{i:02d}" for i in range(1, 11)}
    for c in vectors["cases"]:                                  # each probe produces exactly the rules it was written for
        if c["kind"] == "probe" and c["expect_rules"]:
            assert set(c["expect_rules"]) <= {f["rule"] for f in c["frames"]}, c["name"]
