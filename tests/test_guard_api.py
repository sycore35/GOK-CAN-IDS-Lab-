import pytest
from fastapi.testclient import TestClient

from src import api
from src.api import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_gateway():
    api.gateway.reset(keep_switches=False)
    yield
    api.gateway.reset(keep_switches=False)
    api.bench.stop_attacks()


def test_coverage_endpoints():
    assert client.get("/api/coverage").json()["status"] in ("idle", "done")
    r = client.post("/api/coverage/run")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "done" and d["duration_ms"] < 3000
    assert d["summary"]["scenarios"] == 12 and d["summary"]["detected"] == 12 and d["summary"]["gateway_blocked"] == 10
    assert len(d["matrix"]["tactics"]) == 6
    assert client.get("/api/coverage").json()["summary"] == d["summary"]


def test_guard_state_shape():
    s = client.get("/api/guard/state").json()
    assert s["mode"] == "normal" and s["workshop_key"] is False and s["tamper"] is False
    assert set(s["stats"]) >= {"passed", "blocked", "by_rule"} and s["events"] == []


def test_guard_mode_switches():
    assert client.post("/api/guard/mode", json={"workshop_key": True}).json()["mode"] == "workshop"
    s = client.post("/api/guard/mode", json={"tamper": True}).json()
    assert s["mode"] == "locked" and s["workshop_key"] is True and s["tamper"] is True
    assert client.post("/api/guard/mode", json={"clear_lockdown": True}).status_code == 409   # lid still open
    s = client.post("/api/guard/mode", json={"workshop_key": False, "tamper": False}).json()
    assert s["mode"] == "locked" and s["locked"] is True
    s = client.post("/api/guard/mode", json={"clear_lockdown": True}).json()
    assert s["mode"] == "normal"
    assert client.post("/api/guard/mode", json={"tamper": "maybe"}).status_code == 422


def test_live_bus_attack_is_evaluated_passively():
    api.bench.stop_attacks()
    api.bench.reset()                                      # no leftovers from other tests in the bus mailboxes
    api.bench.start_attack("spoof_id", None, duration=1.0)
    n_before = api.bench.bus.total_frames
    api.process_records(api.bench.advance(0.5))
    s = client.get("/api/guard/state").json()
    assert s["stats"]["blocked"] > 0 and s["stats"]["by_rule"].get("GW-10", 0) > 0
    assert s["stats"]["b_internal"] > 0                     # ECU_* traffic only counted
    assert all(e["rule"] == "GW-10" and e["dir"] == "A>B" for e in s["events"])
    assert len(s["events"]) <= 50 and api.bench.bus.total_frames > n_before   # bus kept running, untouched


def test_hardware_events_accepted_single_and_list():
    one = {"t": 1.5, "ev": "BLOCK", "rule": "GW-10", "dir": "A>B", "id": "0x0C4", "dlc": 4, "data": "88130000"}
    r = client.post("/api/guard/events", json=one)
    assert r.status_code == 200 and r.json()["accepted"] == 1
    r = client.post("/api/guard/events", json=[one, {**one, "rule": "GW-04"}])
    assert r.json()["accepted"] == 2
    s = client.get("/api/guard/state").json()
    assert [e["source"] for e in s["events"]] == ["hardware"] * 3 and s["stats"]["by_rule"] == {"GW-10": 2, "GW-04": 1}
    assert client.post("/api/guard/events", json=[1, 2]).status_code == 400
    assert client.post("/api/guard/events", content="not json").status_code == 400


def test_evaluate_endpoint():
    d = client.post("/api/guard/evaluate", json={"attack": "speed_spoof"}).json()
    assert d["blocked"] == d["total"] > 0 and d["rules"] == ["GW-01"] and "engeller" in d["verdict_tr"]
    d = client.post("/api/guard/evaluate", json={"attack": "speed_spoof_stealth"}).json()
    assert d["blocked"] == 0 and d["total"] == 0 and "engelleyemezdi" in d["verdict_tr"]
    d = client.post("/api/guard/evaluate", json={"attack": "flooding", "params": {"rate_fps": 1500}}).json()
    assert "GW-08" in d["rules"]
    assert client.post("/api/guard/evaluate", json={"attack": "nope"}).status_code == 400


def test_existing_endpoints_still_work():
    assert client.get("/api/attacks").status_code == 200 and len(client.get("/api/attacks").json()) == 12
    assert client.get("/api/bench/state").status_code == 200
    client.post("/api/reset")
    assert client.get("/api/guard/state").json()["stats"]["blocked"] == 0
