import json

import pytest

from src import coverage
from src.attacks import ATTACKS


@pytest.fixture(scope="module")
def report():
    return coverage.run_coverage(seed=1)


def test_schema_and_duration(report):
    assert report["status"] == "done" and report["duration_ms"] < 3000
    assert report["summary"]["scenarios"] == 12 == len(report["results"])
    assert {"id", "name", "category", "tactic", "expected", "triggered", "missed", "detected", "first_detect_ms",
            "gateway", "note_tr"} <= set(report["results"][0])
    assert {"blocked", "total", "rules"} <= set(report["results"][0]["gateway"])
    assert {r["id"] for r in report["results"]} == set(ATTACKS)
    json.dumps(report)


def test_every_attack_is_detected_by_something(report):
    assert report["summary"]["detected"] == 12
    for r in report["results"]:
        assert r["triggered"], r["id"]
        assert r["first_detect_ms"] is not None and r["first_detect_ms"] >= 0
        assert not set(r["missed"]) & set(r["triggered"])


def test_stealth_is_caught_only_by_physics(report):
    r = {x["id"]: x for x in report["results"]}["speed_spoof_stealth"]
    assert r["expected"] == ["VBA-02"] and "VBA-02" in r["triggered"]
    assert r["first_detect_ms"] > 500                           # it ramps slowly: not an instant per-frame hit
    assert r["gateway"]["total"] == 0 and r["gateway"]["origin"] == "B" and r["gateway"]["verdict"] == "cannot"


def test_gateway_outcomes_are_honest(report):
    r = {x["id"]: x for x in report["results"]}
    for aid in ("speed_spoof", "spoof_id", "replay", "flooding", "counter_crc_desync", "unauthorized_id", "uds_reflash",
                "brake_spoof", "uds_diagnostic_attack", "fuzzing"):
        g = r[aid]["gateway"]
        assert g["total"] > 0 and g["blocked"] == g["total"] and g["rules"], aid
    assert r["speed_spoof"]["gateway"]["rules"] == ["GW-01"]
    assert r["spoof_id"]["gateway"]["rules"] == ["GW-10"]
    assert "GW-08" in r["flooding"]["gateway"]["rules"]
    assert r["counter_crc_desync"]["gateway"]["rules"] == ["GW-05"]
    # a plausible-looking body frame cannot be told from a legitimate one by the gateway
    assert r["headlight_can_injection_unlock"]["gateway"]["blocked"] == 0 and r["headlight_can_injection_unlock"]["gateway"]["total"] > 0
    s = report["summary"]
    assert (s["gateway_blocked"], s["gateway_partial"], s["gateway_cannot"]) == (10, 0, 2)
    assert s["either"] == 12


def test_matrix_covers_all_scenarios_once(report):
    tac = report["matrix"]["tactics"]
    assert [t["name_tr"] for t in tac] == ["Keşif", "İlk erişim", "Yürütme/Enjeksiyon", "Kalıcılık", "Atlatma", "Etki"]
    cells = [c for t in tac for c in t["cells"]]
    assert sorted(c["id"] for c in cells) == sorted(ATTACKS)
    assert {c["status"] for c in cells} <= {"detected", "partial", "missed"}
    byid = {c["id"]: c["status"] for c in cells}
    assert byid["replay"] == "partial" and byid["speed_spoof"] == "detected"        # replay: CAN-IDS-06 stayed silent


def test_note_tr_is_one_turkish_sentence(report):
    for r in report["results"]:
        assert isinstance(r["note_tr"], str) and 20 < len(r["note_tr"]) < 400 and "GÖK-GW1" in r["note_tr"]
        assert "\n" not in r["note_tr"]


def test_deterministic(report):
    again = coverage.run_coverage(seed=1)
    for r in (report, again):
        r.pop("duration_ms")
    assert report == again


def test_last_report_roundtrip(report):
    assert coverage.last_report()["status"] == "done"


def test_gateway_summary_params_and_unknown():
    g = coverage.gateway_summary("speed_spoof")
    assert g["verdict"] == "blocks" and g["blocked"] == g["total"] > 0 and "verdict_tr" in g
    s = coverage.gateway_summary("speed_spoof_stealth")
    assert s["verdict"] == "cannot" and s["total"] == 0
    # low-rate body injection stays under the per-ID limit; a hammering one hits GW-03
    low = coverage.gateway_summary("headlight_can_injection_unlock")
    hard = coverage.gateway_summary("headlight_can_injection_unlock", {"rate_hz": 100.0})
    assert low["blocked"] == 0 and "GW-03" in hard["rules"] and hard["verdict"] == "partial"
    with pytest.raises(KeyError):
        coverage.gateway_summary("nope")
