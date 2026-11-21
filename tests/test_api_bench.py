"""API-level vertical slices for every module (real app code, manual stepping instead of the wall-clock loop)."""
import time
import pytest
from fastapi.testclient import TestClient
from src.api import app

c = TestClient(app)


@pytest.fixture(autouse=True)
def fresh():
    c.post("/api/reset")
    c.post("/api/attacks/stop")
    yield


def step(s):
    r = c.post("/api/bench/step", json={"seconds": s})
    assert r.status_code == 200
    return r.json()


def test_bench_state_lists_five_plus_ecus_and_dynamics_move():
    step(12)
    st = c.get("/api/bench/state").json()
    names = {e["name"] for e in st["ecus"]}
    assert {"ECU_Engine", "ECU_Brake", "ECU_Steering", "ECU_Transmission", "ECU_Cluster"} <= names
    assert st["telemetry"]["speed_kmh"] > 10 and st["telemetry"]["rpm"] > 900
    assert 0 < st["bus"]["load_pct"] < 30 and st["bus"]["total_frames"] > 1000
    assert len(c.get("/api/bus/trace?limit=20").json()) == 20


def test_attack_lab_flow_reports_detection_and_effects():
    step(8)
    cat = {a["id"] for a in c.get("/api/attacks").json()}
    assert {"speed_spoof", "replay", "flooding", "fuzzing", "spoof_id", "uds_reflash"} <= cat
    assert c.post("/api/attacks/run", json={"attack": "nope"}).status_code == 400
    r = c.post("/api/attacks/run", json={"attack": "speed_spoof", "duration": 2.0})
    assert r.status_code == 200
    out = step(2.5)
    assert any(a["rule_id"] == "CAN-IDS-03" for a in out["new_alerts"])
    s = c.get("/api/attacks/status").json()
    cur = (s["active"] + s["recent"])[-1]
    assert cur["detected"] and cur["effects"]["max_cluster_speed_error_kmh"] > 50
    stored = c.get("/api/alerts?limit=200").json()
    assert any(a["rule_id"] == "CAN-IDS-03" for a in stored)


def test_flood_attack_via_api_saturates_bus():
    step(3)
    c.post("/api/attacks/run", json={"attack": "flooding", "duration": 1.5, "params": {"rate_fps": 5000}})
    step(1.5)
    assert c.get("/api/bus/stats").json()["peak_load_pct"] > 90


def test_legacy_scenario_endpoint_still_drives_the_new_engine():
    assert c.post("/api/scenarios/start", json={"scenario": "uds_diagnostic_attack", "duration": 1.0}).status_code == 200
    out = step(1.2)
    assert any(a["rule_id"] == "CAN-IDS-07B" for a in out["new_alerts"])
    assert c.post("/api/scenarios/start", json={"scenario": "unauthorized_uds", "duration": 1.0}).status_code == 200


def test_uds_reflash_visible_in_alerts_and_uds_log():
    step(1)
    c.post("/api/attacks/run", json={"attack": "uds_reflash", "duration": 1.5})
    out = step(1.6)
    assert any(a["rule_id"] == "CAN-IDS-07" and a["severity"] == "CRITICAL" for a in out["new_alerts"])
    assert any(u["service_name"] == "RequestDownload" and u["reassembled"] for u in c.get("/api/uds/log").json())


def test_behavior_endpoint_flags_brake_spoof():
    step(1)
    c.post("/api/attacks/run", json={"attack": "brake_spoof", "duration": 5.0})
    out = step(6)
    assert any(a["rule_id"] == "VBA-01" for a in out["new_alerts"])
    b = c.get("/api/behavior").json()
    assert b["rule_hits"].get("VBA-01", 0) >= 1


def test_dbc_editor_api_crud_export_import_decode():
    r = c.post("/api/dbc/messages", json={"id_dec": 0x333, "name": "Api_Msg", "dlc": 4, "cycle_time_ms": 50,
                                          "signals": [{"name": "v", "start_bit": 0, "length": 8, "scale": 2, "offset": 1, "unit": "u"}]})
    assert r.status_code == 200
    assert c.post("/api/dbc/messages", json={"id_dec": 0x333, "name": "Dup", "dlc": 4}).status_code == 422
    d = c.post("/api/dbc/decode", json={"id": 0x333, "data_hex": "0A 00 00 00"}).json()
    assert d["signals"]["v"]["value"] == 21.0
    c.put("/api/dbc/messages/819/signals/v", json={"scale": 3})
    assert c.post("/api/dbc/decode", json={"id": 0x333, "data_hex": "0A"}).json()["signals"]["v"]["value"] == 31.0
    txt = c.get("/api/dbc/export").text
    assert "BO_ 819 Api_Msg: 4" in txt
    assert c.post("/api/dbc/import", json={"text": "garbage"}).status_code == 422
    assert c.delete("/api/dbc/messages/819").status_code == 200
    assert c.delete("/api/dbc/messages/819").status_code == 404
    assert c.get("/api/dbc").json()["integrity"]["valid"] is True


def test_rule_designer_api_applies_live():
    r = c.post("/api/rules/custom", json={"name": "Hi RPM", "type": "signal_threshold", "signal": "rpm", "op": ">",
                                          "value": 100, "severity": "LOW", "arb_id": "0x180"})
    assert r.status_code == 200
    rid = r.json()["id"]
    out = step(1)
    assert any(a["rule_id"] == rid for a in out["new_alerts"])
    assert c.post("/api/rules/custom", json={"name": "bad", "type": "x"}).status_code == 422
    t = c.post("/api/rules/custom/test", json={"rule": {"name": "t", "type": "payload_match", "pattern_hex": "FF"},
                                               "id": 1, "data_hex": "FF 00"}).json()
    assert t["match"] is True
    c.put(f"/api/rules/custom/{rid}", json={"enabled": False})
    out = step(1)
    assert not any(a["rule_id"] == rid for a in out["new_alerts"])
    assert c.delete(f"/api/rules/custom/{rid}").status_code == 200
    assert c.delete(f"/api/rules/custom/{rid}").status_code == 404


def test_layer_toggle_api_disables_detection():
    assert c.post("/api/rules/layers/CAN-IDS-01?enabled=false").status_code == 200
    c.post("/api/attacks/run", json={"attack": "unauthorized_id", "duration": 1.0})
    out = step(1.2)
    assert not any(a["rule_id"] == "CAN-IDS-01" for a in out["new_alerts"])
    c.post("/api/rules/layers/CAN-IDS-01?enabled=true")
    assert c.post("/api/rules/layers/BOGUS").status_code == 404


def test_socketcan_status_and_canfd_api():
    st = c.get("/api/socketcan/status").json()
    import sys
    if sys.platform == "darwin":
        assert st["available"] is False and st["fallback"] == "simulator"
    r = c.post("/api/canfd/encode", json={"id": 0x400, "data_hex": "AA" * 50, "brs": True}).json()
    assert r["payload_len"] == 64 and r["dlc_code"] == 15 and r["padded_bytes"] == 14
    assert c.post("/api/canfd/encode", json={"id": 1, "data_hex": "AA" * 10, "pad": False}).status_code == 422
    sent = c.post("/api/canfd/encode", json={"id": 0x400, "data_hex": "AA" * 24, "send": True}).json()
    assert sent["queued"] is True
    step(0.1)
    assert any(t["is_fd"] and t["dlc"] == 12 for t in c.get("/api/bus/trace?limit=400").json())


def test_benchmark_api_runs_in_background_and_returns_results():
    assert c.post("/api/benchmark/run", json={"duration": 1.0}).status_code == 422
    assert c.post("/api/benchmark/run", json={"duration": 6.0, "attack_start": 2.0, "attack_len": 2.5}).status_code == 200
    for _ in range(120):
        st = c.get("/api/benchmark/status").json()
        if st["status"] != "running":
            break
        time.sleep(0.5)
    assert st["status"] == "done", st
    assert st["result"]["layers"]["CAN-IDS-01"]["fpr"] == 0.0


def test_driver_control_and_ecu_silence():
    assert c.post("/api/bench/driver", json={"mode": "bad"}).status_code in (400, 422)
    c.post("/api/bench/driver", json={"mode": "manual", "throttle_pct": 0, "brake_pct": 0})
    assert c.post("/api/bench/ecu/ECU_Nope/online").status_code == 404
    c.post("/api/bench/ecu/ECU_Engine/online?online=false")
    step(0.5)
    assert not any(t["arbitration_id"] == 0x180 and t["timestamp"] > 0.2 for t in c.get("/api/bus/trace?limit=400").json())
    c.post("/api/bench/ecu/ECU_Engine/online?online=true")
    c.post("/api/bench/driver", json={"mode": "auto"})
