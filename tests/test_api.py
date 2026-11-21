import pytest
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["port"] == 8003
    assert "total_frames_sent" in data


def test_api_telemetry():
    response = client.get("/api/telemetry")
    assert response.status_code == 200
    data = response.json()
    assert "speed_kmh" in data
    assert "engine_rpm" in data


def test_api_scenario_start_and_stop():
    res_start = client.post("/api/scenarios/start", json={"scenario": "speed_spoof", "duration": 2.0})
    assert res_start.status_code == 200
    assert res_start.json()["scenario"] == "speed_spoof"

    res_stop = client.post("/api/scenarios/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["active_scenario"] == "normal"


def test_api_rules_tune():
    res = client.post("/api/rules/tune", json={"max_accel_kmh_per_sec": 55.0})
    assert res.status_code == 200
    assert res.json()["status"] == "THRESHOLDS_UPDATED"


def test_api_export_incident():
    res = client.get("/api/export/incident")
    assert res.status_code == 200
    bundle = res.json()
    assert bundle["bundle_type"] == "AUTOMOTIVE_CAN_INCIDENT_BUNDLE"


def test_api_error_handling_and_validation():
    # Invalid scenario name
    bad_scen = client.post("/api/scenarios/start", json={"scenario": "unsupported_can_exploit"})
    assert bad_scen.status_code == 400
    assert "Invalid scenario" in bad_scen.json()["detail"]

    # Missing required body
    missing_body = client.post("/api/scenarios/start", json={})
    assert missing_body.status_code == 422

    # Out of range query bounds
    neg_limit = client.get("/api/alerts?limit=-1")
    assert neg_limit.status_code == 422

    overflow_limit = client.get("/api/alerts?limit=5000")
    assert overflow_limit.status_code == 422


def test_api_empty_data_query():
    # Reset lab and verify get_alerts and get_frames return valid empty list
    client.post("/api/reset")
    res_alerts = client.get("/api/alerts?limit=10")
    assert res_alerts.status_code == 200
    assert isinstance(res_alerts.json(), list)

    res_frames = client.get("/api/frames?limit=10")
    assert res_frames.status_code == 200
    assert isinstance(res_frames.json(), list)


def test_ui_static_serving_and_tr_en_dictionaries():
    # Verify index.html loads with 200 and has title
    res_idx = client.get("/")
    assert res_idx.status_code == 200
    assert "GÖK CAN-IDS" in res_idx.text

    # Verify static app.js has TR and EN translations
    res_js = client.get("/app.js")
    assert res_js.status_code == 200
    js_text = res_js.text
    assert "const I18N = {" in js_text
    assert "tr: {" in js_text
    assert "en: {" in js_text
    # Check specific keys exist in both languages
    assert "speedometer" in js_text
    assert "tachometer" in js_text
    assert "HIZ GÖSTERGESİ" in js_text
    assert "SPEEDOMETER" in js_text



def test_ui_assets_revalidate():
    from fastapi.testclient import TestClient
    from src.api import app
    with TestClient(app) as c:
        r = c.get("/style.css")
        assert r.status_code == 200
        assert r.headers.get("cache-control") == "no-cache"
