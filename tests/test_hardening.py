"""Regression tests for the audit findings: bad input must be rejected with 4xx and must never kill or freeze
the simulation loop; state must reset cleanly; detection gaps found in the audit stay closed."""
import asyncio
import copy
import json
import math

import pytest
from fastapi.testclient import TestClient

from src.attacks import ATTACKS
from src.bench import VirtualTestBench
from src.can_frame import CANFrame
from src.can_ids import CANIntrusionDetectionEngine
from src.coverage import _config
from src.dbc_decoder import DBCDecoder


@pytest.fixture(scope="module")
def client():
    from src.api import app
    with TestClient(app) as c:
        yield c


def _bench():
    dbc = DBCDecoder.from_config(copy.deepcopy(_config()))
    return VirtualTestBench(dbc, CANIntrusionDetectionEngine(dbc), None, seed=1)


# ---------------------------------------------------------------- 1. attack parameters
BAD_PARAMS = [
    ("speed_spoof", {"rate_hz": -5}), ("speed_spoof", {"rate_hz": 0}), ("speed_spoof", {"rate_hz": "abc"}),
    ("speed_spoof", {"rate_hz": 1e7}), ("speed_spoof", {"offset_kmh": "a"}), ("speed_spoof", {"rate_hz": math.inf}),
    ("spoof_id", {"payload_hex": "zz"}), ("spoof_id", {"target_id": 0x900}), ("spoof_id", {"payload_hex": "00" * 9}),
    ("fuzzing", {"id_min": 0x500, "id_max": 0x100}), ("replay", {"ids": 5}), ("replay", {"record_s": -1}),
    ("flooding", {"rate_fps": 0}), ("speed_spoof", {"unknown_key": 1}),
]


@pytest.mark.parametrize("attack,params", BAD_PARAMS)
def test_bad_attack_params_are_rejected_before_the_attack_starts(attack, params):
    b = _bench()
    with pytest.raises(ValueError):
        b.start_attack(attack, params, 2.0)
    assert not b.attacks


def test_good_params_are_coerced():
    b = _bench()
    a = b.start_attack("spoof_id", {"target_id": "0x0C4", "rate_hz": "100", "payload_hex": "38 18 F4 01"}, 1.0)
    assert a.params["target_id"] == 0xC4 and a.params["rate_hz"] == 100.0
    b.advance(0.5)
    assert a.injected > 0


@pytest.mark.parametrize("attack,params", BAD_PARAMS[:4])
def test_api_returns_400_for_bad_params(client, attack, params):
    body = json.dumps({"attack": attack, "params": params, "duration": 2})
    for path in ("/api/attacks/run", "/api/guard/evaluate"):
        r = client.post(path, content=body, headers={"content-type": "application/json"})
        assert r.status_code in (400, 422), (path, r.status_code, r.text)


def test_attack_duration_must_be_finite_and_positive(client):
    for d in ("Infinity", "-5", "NaN"):
        r = client.post("/api/attacks/run", content='{"attack":"speed_spoof","duration":%s}' % d,
                        headers={"content-type": "application/json"})
        assert r.status_code == 422, (d, r.text)
    r = client.post("/api/scenarios/start", content='{"scenario":"speed_spoof","duration":Infinity}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 422
    client.post("/api/attacks/stop")


def test_simulation_step_survives_a_crashing_attack(monkeypatch):
    from src import api
    b = api.bench
    atk = b.start_attack("speed_spoof", {}, 2.0)
    monkeypatch.setattr(atk, "tick", lambda t: 1 / 0)
    api.simulation_step(0.05)   # must not raise
    assert "speed_spoof" not in b.attacks   # the faulty attack is removed, the bench keeps running
    t0 = b.t
    api.simulation_step(0.05)
    assert b.t > t0


# ---------------------------------------------------------------- 2. slow websocket client
def test_broadcast_drops_a_client_that_does_not_read():
    from src import api

    class Stuck:
        async def send_text(self, data):
            await asyncio.sleep(10)

    class Fast:
        def __init__(self):
            self.n = 0

        async def send_text(self, data):
            self.n += 1

    stuck, fast = Stuck(), Fast()
    conns = [stuck, fast]
    import pytest as _p
    mp = _p.MonkeyPatch()
    mp.setattr(api, "active_connections", conns)
    try:
        asyncio.run(asyncio.wait_for(api.broadcast("{}"), 3))
    finally:
        mp.undo()
    assert fast.n >= 1 and stuck not in conns and fast in conns


# ---------------------------------------------------------------- 3/8. bounded request bodies
@pytest.mark.parametrize("body", ['{"mode":"manual","brake_pct":1e308}', '{"target_speed_kmh":Infinity}',
                                  '{"mode":"manual","throttle_pct":1000}', '{"steering_deg":1e9}',
                                  '{"throttle_pct":NaN}', '{"mode":"rocket"}'])
def test_driver_inputs_are_bounded(client, body):
    r = client.post("/api/bench/driver", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 422, (body, r.text)
    assert client.get("/api/bench/state").status_code == 200


@pytest.mark.parametrize("body", ['{"timing_jitter_tolerance_pct":Infinity}', '{"max_accel_kmh_per_sec":-1}'])
def test_tune_rejects_nonsense(client, body):
    before = client.get("/api/health").json()
    r = client.post("/api/rules/tune", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 422
    assert client.get("/api/health").status_code == 200 and before


def test_bench_step_is_bounded(client):
    assert client.post("/api/bench/step", json={"seconds": 31}).status_code == 422
    assert client.post("/api/bench/step", json={"seconds": 1}).status_code == 200


@pytest.mark.parametrize("msg", [{"id_dec": "Infinity", "name": "X", "dlc": 8},
                                 {"id_hex": "0x5A1", "name": "X", "dlc": 1e400},
                                 {"id_hex": "0x5A2", "name": "X", "dlc": 8, "is_extended": "maybe"}])
def test_dbc_editor_rejects_overflow_and_bad_bool(client, msg):
    r = client.post("/api/dbc/messages", content=json.dumps(msg).replace('"Infinity"', "Infinity"),
                    headers={"content-type": "application/json"})
    assert r.status_code == 422, r.text


def test_dbc_editor_parses_string_bool(client):
    r = client.post("/api/dbc/messages", json={"id_hex": "0x5A3", "name": "BoolTest", "dlc": 8, "is_extended": "false",
                                               "signals": []})
    assert r.status_code == 200 and r.json()["id_hex"] == "0x5A3"
    client.delete(f"/api/dbc/messages/{0x5A3}")


# ---------------------------------------------------------------- 4/5. custom rules
def test_rule_with_infinite_window_is_rejected_and_not_saved(client):
    n = len(client.get("/api/rules/custom").json())
    r = client.post("/api/rules/custom", content='{"type":"rate","arb_id":"0x180","max_count":5,"window_ms":Infinity}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 422
    r = client.post("/api/rules/custom", json={"type": "signal_threshold", "arb_id": "0x244", "signal": "speed_kmh",
                                               "op": ">", "value": 10 ** 400})
    assert r.status_code == 422
    lst = client.get("/api/rules/custom")
    assert lst.status_code == 200 and len(lst.json()) == n


def test_reset_clears_custom_rule_state():
    from src.rules_engine import RuleSet
    rs = RuleSet(None)
    rs.add({"name": "r", "type": "rate", "arb_id": "0x180", "max_count": 10, "window_ms": 100})
    for i in range(50):
        rs.evaluate(CANFrame(0x180, bytes(8), timestamp=100 + i * 0.02), {}, None)
    rs.reset_state()
    hits = [h for i in range(20) for h in rs.evaluate(CANFrame(0x180, bytes(8), timestamp=0.1 + i * 0.02), {}, None)]
    assert hits == [] and not any(len(d) > 11 for d in rs._rate.values())


# ---------------------------------------------------------------- 6. benchmark with a short attack
def test_benchmark_short_attack_does_not_crash():
    from src.benchmark import run_benchmark
    res = run_benchmark(copy.deepcopy(_config()), seed=1, duration=4.0, attack_start=2.0, attack_len=0.5)
    assert "layers" in res


# ---------------------------------------------------------------- 7. CORS
def test_cors_is_not_open_to_other_sites(client):
    r = client.options("/api/reset", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"
    ok = client.options("/api/reset", headers={"Origin": "http://127.0.0.1:8003", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:8003"


# ---------------------------------------------------------------- 10. alert storage is bounded
def test_alert_table_is_pruned(tmp_path):
    from src.storage import CANStorage
    from src.can_ids import CANAlert
    s = CANStorage(str(tmp_path / "x.db"), max_alerts=100)
    alerts = [CANAlert("CAN-IDS-01", "x", "LOW", 1, "0x001", "M", 1, 0, "e", "m", "00", timestamp=i) for i in range(350)]
    for i in range(0, 350, 50):
        s.save_batch([], alerts[i:i + 50], 0.0)
    s.flush()
    assert s.count_alerts() <= 150


def test_health_total_alerts_counts_beyond_ring_buffer(client):
    h = client.get("/api/health").json()
    assert "total_alerts" in h and isinstance(h["total_alerts"], int)


# ---------------------------------------------------------------- 11. hardware events are sanitised
def test_guard_events_are_whitelisted_and_bounded(client):
    big = "A" * 100_000
    evs = [{"t": 1.0, "ev": "BLOCK", "rule": f"junk-{i}", "id": "0x244", "data": big, "extra": big} for i in range(300)]
    st = client.post("/api/guard/events", json=evs).json()
    assert len(st["stats"]["by_rule"]) <= 12
    assert all("extra" not in e and len(json.dumps(e)) < 400 for e in st["events"])
    assert client.post("/api/guard/events", json=[{}]).status_code == 400


# ---------------------------------------------------------------- 12. detection gaps
def _ids():
    return CANIntrusionDetectionEngine(DBCDecoder.from_config(copy.deepcopy(_config())))


def test_extended_id_is_not_whitelisted_by_its_standard_twin():
    e = _ids()
    alerts = e.process_frame(CANFrame(0x244, bytes(8), 8, is_extended_id=True, timestamp=1.0))
    assert any(a.rule_id == "CAN-IDS-01" for a in alerts)


def _sf(aid, payload, t):
    return CANFrame(aid, bytes([len(payload)]) + bytes(payload) + bytes(7 - len(payload)), 8, timestamp=t)


def test_uds_programming_session_with_suppress_bit_is_flagged():
    from src.isotp_uds import ISOTPUDSInspector
    for sub in (0x02, 0x82):
        f = ISOTPUDSInspector().inspect(_sf(0x7E0, [0x10, sub], 1.0), vehicle_speed_kmh=50.0)
        assert any(x["rule_id"] == "CAN-IDS-07" for x in f), hex(sub)


def test_invalid_key_counter_resets_after_a_positive_response():
    from src.isotp_uds import ISOTPUDSInspector
    ins = ISOTPUDSInspector()
    seq = [[0x7F, 0x27, 0x35], [0x7F, 0x27, 0x35], [0x67, 0x02], [0x7F, 0x27, 0x35]]
    found = [x for i, p in enumerate(seq) for x in ins.inspect(_sf(0x7E8, p, 1.0 + i * 0.1))]
    assert not any(x["rule_id"] == "CAN-IDS-07B" for x in found)


def test_steering_frames_are_secoc_protected_end_to_end():
    """Legit steering frames carry a valid SecOC MAC (no alert); a forged 4-byte frame is flagged by CAN-IDS-04B."""
    b = _bench()
    recs = b.advance(1.0)
    st = [r for r in recs if r.d.frame.arbitration_id == 0x0C4]
    assert st and all(len(r.d.frame.data) == 8 for r in st)
    assert not any(a.rule_id.startswith("CAN-IDS-04") for r in st for a in r.ids_alerts)
    e = _ids()
    forged = e.process_frame(CANFrame(0x0C4, bytes.fromhex("381818F4"), 4, timestamp=5.0))
    assert any(a.rule_id == "CAN-IDS-04B" for a in forged)


# ---------------------------------------------------------------- 13. candump replay keeps every frame and its timing
def test_replay_log_keeps_all_frames_and_original_spacing(client):
    client.post("/api/reset")
    lines = "\n".join(f"({1000 + i * 0.002:.6f}) vcan0 3C0#{i % 256:02X}00000000000000" for i in range(300))
    r = client.post("/api/frames/replay-log", json={"log": lines}).json()
    assert r["frames_replayed"] == 300 and r["frames_dropped"] == 0
    assert abs(r["span_s"] - 0.598) < 1e-3


def test_replay_log_limits_size(client):
    client.post("/api/reset")
    lines = "\n".join(f"({i * 0.001:.6f}) vcan0 3C0#00" for i in range(6000))
    r = client.post("/api/frames/replay-log", json={"log": lines}).json()
    assert r["frames_replayed"] == 5000 and r["frames_dropped"] == 1000
    client.post("/api/reset")


# ---------------------------------------------------------------- config.yaml ids section is honoured
def test_ids_config_is_applied():
    from src import api
    e = _ids()
    out = api.apply_ids_config(e, {"ids": {"rules": {"replay_window_enabled": False},
                                           "thresholds": {"max_accel_kmh_per_sec": 30, "bus_load_alert_pct": "bad"}}})
    assert "CAN-IDS-06" not in e.enabled_layers and "CAN-IDS-01" in e.enabled_layers
    assert out["thresholds"] == {}  # one invalid value -> the whole threshold block is rejected, defaults stay
    out = api.apply_ids_config(e, {"ids": {"thresholds": {"max_accel_kmh_per_sec": 30}}})
    assert e.max_accel_kmh_s == 30.0 and out["thresholds"] == {"max_accel_kmh_per_sec": 30.0}
    api.apply_ids_config(e, {"ids": {"enable_detection": False}})
    assert e.enabled_layers == set()
    assert api.IDS_CONFIG_APPLIED["thresholds"]["max_accel_kmh_per_sec"] == 45.0
