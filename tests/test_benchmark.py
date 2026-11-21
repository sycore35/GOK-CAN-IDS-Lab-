import os, json
from src.benchmark import run_benchmark
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = json.load(open(os.path.join(BASE, "config", "can_signals.json")))


def test_benchmark_measures_each_layer_separately():
    r = run_benchmark(CFG, seed=3, duration=7.0, attack_start=2.0, attack_len=3.0)
    L = r["layers"]
    assert {"CAN-IDS-01", "CAN-IDS-02", "CAN-IDS-03", "CAN-IDS-04", "CAN-IDS-05", "CAN-IDS-06", "CAN-IDS-07", "ALL", "BASELINE", "BEHAVIOR"} <= set(L)
    # every layer has zero false positives on clean traffic
    assert all(L[k]["fpr"] == 0.0 for k in L if k.startswith("CAN-IDS"))
    # each layer detects its own scenario, and not an unrelated one
    assert L["CAN-IDS-01"]["per_scenario"]["unauthorized_id"]["tpr"] == 1.0
    assert L["CAN-IDS-03"]["per_scenario"]["speed_spoof"]["detected"]
    assert L["CAN-IDS-03"]["per_scenario"]["unauthorized_id"]["detected"] is False
    assert L["CAN-IDS-05"]["per_scenario"]["flooding"]["detected"]
    assert L["CAN-IDS-07"]["per_scenario"]["uds_reflash"]["tpr"] > 0
    assert L["CAN-IDS-04"]["per_scenario"]["counter_crc_desync"]["tpr"] > 0.5
    # masquerade evades all frame layers but not behaviour analysis
    assert L["ALL"]["per_scenario"]["speed_spoof_stealth"]["tpr"] < 0.2
    assert L["BEHAVIOR"]["per_scenario"]["speed_spoof_stealth"]["detected"]
    assert L["BEHAVIOR"]["false_alarms_benign"] == 0
    assert L["CAN-IDS-02"]["latency_us"]["median"] > 0
