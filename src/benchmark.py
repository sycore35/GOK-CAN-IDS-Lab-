"""Detection benchmark: measures each IDS layer separately (TPR, FPR, detection delay, per-frame latency)
on labeled, seeded simulator scenarios. Ground truth = frames whose source is ATTACKER:*.
"""
import copy
import statistics
import time
from typing import Any, Callable, Dict, List, Optional

from src.attacks import ATTACKS
from src.behavior import VehicleBehaviorAnalyzer
from src.bench import VirtualTestBench
from src.can_ids import CANIntrusionDetectionEngine, LAYER_IDS, LAYER_NAMES
from src.dbc_decoder import DBCDecoder

SCENARIOS = ["benign", "speed_spoof", "speed_spoof_stealth", "replay", "flooding", "fuzzing",
             "counter_crc_desync", "unauthorized_id", "uds_reflash", "headlight_can_injection_unlock", "brake_spoof"]
SCENARIO_PARAMS = {"flooding": {"rate_fps": 3000}, "replay": {"record_s": 1.0},
                   "speed_spoof_stealth": {"ramp_kmh_per_s": 15.0}}


def record_scenario(config: Dict[str, Any], scenario: str, seed: int, duration: float, a_start: float, a_len: float):
    dbc = DBCDecoder.from_config(copy.deepcopy(config))
    b = VirtualTestBench(dbc, ids=None, behavior=None, seed=seed)
    recs, started = [], False
    while b.t < duration - 1e-9:
        if scenario != "benign" and not started and b.t >= a_start:
            b.start_attack(scenario, SCENARIO_PARAMS.get(scenario), duration=a_len)
            started = True
        recs += b.advance(0.05)
    return [(r.d.frame, r.attack, r.d.bus_load_pct) for r in recs]


def _pct(xs: List[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def run_benchmark(config: Dict[str, Any], seed: int = 1, duration: float = 8.0, attack_start: float = 2.0,
                  attack_len: float = 4.0, progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    scenarios = {}
    for sc in SCENARIOS:
        if progress:
            progress(f"recording {sc}")
        scenarios[sc] = record_scenario(config, sc, seed, duration, attack_start, attack_len)
    detectors = [(l, {l}) for l in LAYER_IDS] + [("ALL", set(LAYER_IDS)), ("BASELINE", set())]
    layers: Dict[str, Any] = {}
    for key, enabled in detectors:
        if progress:
            progress(f"measuring {key}")
        lat: List[float] = []
        per: Dict[str, Any] = {}
        benign_fp = benign_n = coll_fp = coll_n = 0
        for sc, recs in scenarios.items():
            ids = CANIntrusionDetectionEngine(DBCDecoder.from_config(copy.deepcopy(config)))
            ids.enabled_layers = set(enabled)
            tp = n_atk = 0
            first_atk_t = first_det_t = None
            detected = False
            for f, atk, load in recs:
                t0 = time.perf_counter_ns()
                al = ids.process_frame(f, load)
                lat.append((time.perf_counter_ns() - t0) / 1000.0)
                hit = bool(al) if key in ("ALL",) else any(a.rule_id.startswith(key) for a in al)
                if key == "BASELINE":
                    hit = False
                if atk:
                    n_atk += 1
                    first_atk_t = f.timestamp if first_atk_t is None else first_atk_t
                    if hit:
                        tp += 1
                        first_det_t = f.timestamp if first_det_t is None else first_det_t
                elif sc == "benign":
                    benign_n += 1
                    benign_fp += hit
                elif first_atk_t is not None:
                    coll_n += 1
                    coll_fp += hit
                if hit and first_atk_t is not None:
                    detected = True
            if sc != "benign":
                per[sc] = {"attack_frames": n_atk, "tpr": round(tp / n_atk, 4) if n_atk else None, "detected": detected,
                           "delay_ms": None if first_det_t is None else round((first_det_t - first_atk_t) * 1000, 1)}
        prim = SCENARIOS[1:] if key == "ALL" else [s for s in SCENARIOS[1:] if key in ATTACKS[s].expected_layers]
        layers[key] = {
            "name": LAYER_NAMES.get(key, key if key != "BASELINE" else "No layers (decode only)"),
            "per_scenario": per, "primary_scenarios": prim,
            "fpr": round(benign_fp / benign_n, 5) if benign_n else 0.0, "benign_frames": benign_n,
            "collateral_fpr": round(coll_fp / coll_n, 5) if coll_n else 0.0,
            "scenarios_detected": sum(1 for v in per.values() if v["detected"]), "scenarios_total": len(per),
            "latency_us": {"median": round(statistics.median(lat), 2), "p95": round(_pct(lat, 0.95), 2),
                           "mean": round(statistics.fmean(lat), 2), "samples": len(lat)},
        }
        if prim:
            tot = sum(per[s]["attack_frames"] for s in prim)
            layers[key]["tpr_primary"] = round(sum((per[s]["tpr"] or 0.0) * per[s]["attack_frames"] for s in prim) / tot, 4) if tot else None
        else:
            layers[key]["tpr_primary"] = None
    # behaviour analysis (scenario-level only: its alerts are not tied to a single frame)
    beh: Dict[str, Any] = {}
    benign_alerts = 0
    for sc, recs in scenarios.items():
        dbc = DBCDecoder.from_config(copy.deepcopy(config))
        va = VehicleBehaviorAnalyzer()
        times = []
        for f, atk, _ in recs:
            for a in va.update(dbc.decode_frame(f), f.timestamp):
                times.append(a["timestamp"])
        if sc == "benign":
            benign_alerts = len(times)
        else:
            atk_t = next((f.timestamp for f, atk, _ in recs if atk), None)
            after = [t for t in times if atk_t is not None and t >= atk_t]
            beh[sc] = {"detected": bool(after), "delay_ms": round((after[0] - atk_t) * 1000, 1) if after else None}
    layers["BEHAVIOR"] = {"name": "Vehicle behaviour analysis (physics)", "per_scenario": beh,
                          "false_alarms_benign": benign_alerts,
                          "scenarios_detected": sum(1 for v in beh.values() if v["detected"]), "scenarios_total": len(beh)}
    return {"seed": seed, "duration_s": duration, "attack_start_s": attack_start, "attack_len_s": attack_len,
            "scenarios": SCENARIOS, "frames": {k: len(v) for k, v in scenarios.items()},
            "layers": layers, "generated_at": time.time(),
            "notes": ["TPR/FPR are frame-level against ATTACKER-labelled frames in the simulator (not real-vehicle data).",
                      "Latency is wall-clock per process_frame on this host, with only the named layer enabled; BASELINE is decode + bookkeeping only.",
                      "collateral_fpr: alerts on legitimate frames while an attack is running (e.g. bus-load alarms during flooding)."]}
