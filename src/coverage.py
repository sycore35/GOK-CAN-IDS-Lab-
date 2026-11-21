"""Detection + gateway coverage: every attack runs alone on a fresh, seeded bench; we record which IDS / behaviour
rules fire, how fast, and what the GÖK-GW1 gateway model (src/gateway_model.py) would have done with the same frames.
Deterministic (seeded), ~1.5 s for all 12 attacks."""
import copy
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from src.attacks import ATTACKS
from src.behavior import VehicleBehaviorAnalyzer
from src.bench import VirtualTestBench
from src.can_ids import CANIntrusionDetectionEngine
from src.dbc_decoder import DBCDecoder
from src.gateway_model import A2B, ATTACK_ORIGIN, GatewayModel, classify_domain

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A_START, A_LEN, TOTAL = 1.0, 2.0, 3.5
DEFAULT_PARAMS = {"flooding": {"rate_fps": 3000}, "replay": {"record_s": 1.0}, "speed_spoof_stealth": {"ramp_kmh_per_s": 15.0}}
# attacks whose design target is the physics analysis, not a frame layer
EXPECTED_OVERRIDE = {"speed_spoof_stealth": ("VBA-02",)}

NAME_TR = {
    "speed_spoof": "Hız sahteciliği (0x244)", "speed_spoof_stealth": "Gizli hız taklidi (ABS susturuldu)",
    "spoof_id": "Keyfi kimlik taklidi", "replay": "Kayıt ve tekrar oynatma", "flooding": "Bus seli (DoS, ID 0x000)",
    "fuzzing": "CAN fuzzing", "counter_crc_desync": "Fren sayaç/CRC bozma (0x200)",
    "unauthorized_id": "Yabancı tanılama kimliği (0x6F1)", "uds_diagnostic_attack": "UDS oturumu + anahtar kaba kuvveti",
    "uds_reflash": "UDS ile yazılım yükleme (0x34)", "headlight_can_injection_unlock": "Gövde enjeksiyonu: kapı kilidi açma",
    "brake_spoof": "Sahte fren basıncı + gaz kesme",
}
# approximate mapping (not an official framework): the six tactics of the lab
TACTICS = [("recon", "Keşif"), ("initial_access", "İlk erişim"), ("execution", "Yürütme/Enjeksiyon"),
           ("persistence", "Kalıcılık"), ("evasion", "Atlatma"), ("impact", "Etki")]
TACTIC_OF = {
    "fuzzing": "recon", "unauthorized_id": "recon", "uds_diagnostic_attack": "initial_access",
    "speed_spoof": "execution", "spoof_id": "execution", "headlight_can_injection_unlock": "execution",
    "uds_reflash": "persistence", "speed_spoof_stealth": "evasion", "replay": "evasion", "counter_crc_desync": "evasion",
    "flooding": "impact", "brake_spoof": "impact",
}
_BASE_RE = re.compile(r"^(CAN-IDS-\d+|VBA-\d+)")

_config_cache: Optional[Dict[str, Any]] = None
LAST: Dict[str, Any] = {"status": "idle"}


def _config() -> Dict[str, Any]:
    global _config_cache
    if _config_cache is None:
        with open(os.path.join(BASE, "config", "can_signals.json"), encoding="utf-8") as fh:
            _config_cache = json.load(fh)
    return _config_cache


def _base_rule(rule_id: str) -> str:
    m = _BASE_RE.match(rule_id)
    return m.group(1) if m else rule_id


def record_attack(attack_id: str, params: Optional[Dict[str, Any]] = None, seed: int = 1, detect: bool = True,
                  a_start: float = A_START, a_len: float = A_LEN, total: float = TOTAL) -> Dict[str, Any]:
    """Isolated run of one attack. Returns the attacker frames (delivery order), IDS/behaviour alerts after the attack
    start, and the attack start time."""
    dbc = DBCDecoder.from_config(copy.deepcopy(_config()))
    bench = VirtualTestBench(dbc, CANIntrusionDetectionEngine(dbc) if detect else None,
                             VehicleBehaviorAnalyzer() if detect else None, seed=seed)
    p = {**DEFAULT_PARAMS.get(attack_id, {}), **(params or {})}
    started = False
    attacker, alerts, benign = [], [], []
    while bench.t < total - 1e-9:
        if not started and bench.t >= a_start - 1e-9:
            bench.start_attack(attack_id, p, duration=a_len)
            started = True
        for rec in bench.advance(0.05):
            f = rec.d.frame
            if rec.attack:
                attacker.append(f)
            elif len(benign) < 400:
                benign.append(f)
            for a in rec.ids_alerts:
                alerts.append((f.timestamp, a.rule_id))
            for a in rec.vba_alerts:
                alerts.append((f.timestamp, a["rule_id"]))
    return {"attacker": attacker, "benign": benign, "alerts": [(t, r) for t, r in alerts if t >= a_start],
            "t0": a_start, "params": p}


def gateway_run(attack_id: str, frames: List[Any], workshop_key: bool = False, tamper: bool = False) -> Dict[str, Any]:
    """Feeds the attacker frames of one run to a fresh gateway model (A>B)."""
    origin = ATTACK_ORIGIN.get(attack_id, "A")
    gw = GatewayModel()
    gw.set_switches(workshop_key=workshop_key, tamper=tamper)
    blocked = total = 0
    rules: Dict[str, int] = {}
    if origin == "A":
        for f in frames:
            total += 1
            dec, rule = gw.evaluate(f, A2B, f.timestamp)
            if dec != "FORWARD":
                blocked += 1
                rules[rule] = rules.get(rule, 0) + 1
    return {"blocked": blocked, "total": total, "rules": sorted(rules), "rule_counts": rules, "origin": origin,
            "seen_frames": len(frames)}


def _verdict_tr(g: Dict[str, Any]) -> str:
    if g["origin"] == "B":
        return ("GÖK-GW1 sahada engelleyemezdi: saldırgan korunan (B) domainin içinde, trafik kartın üzerinden geçmiyor; "
                "bus'ı izleyen IDS/fizik analizi dışında koruma yok.")
    if g["total"] == 0:
        return "GÖK-GW1 için saldırı çerçevesi oluşmadı."
    if g["blocked"] == g["total"]:
        return f"GÖK-GW1 sahada engellerdi: {g['blocked']}/{g['total']} çerçeve ({', '.join(g['rules'])})."
    if g["blocked"] == 0:
        return ("GÖK-GW1 sahada engelleyemezdi: çerçeveler politikaya uygun görünüyor "
                "(kimlik, uzunluk, aralık ve hız kurallarından geçiyor); bu tür saldırıyı yalnız bus'ı izleyen IDS ayırt edebilir.")
    return (f"GÖK-GW1 kısmen engellerdi: {g['blocked']}/{g['total']} çerçeve ({', '.join(g['rules'])}); "
            f"geri kalanı politikaya uygun görünüyor.")


def gateway_summary(attack_id: str, params: Optional[Dict[str, Any]] = None, seed: int = 1) -> Dict[str, Any]:
    """Gateway-only isolated run (no IDS): used by POST /api/guard/evaluate."""
    rec = record_attack(attack_id, params, seed, detect=False)
    g = gateway_run(attack_id, rec["attacker"])
    g["verdict"] = "blocks" if g["origin"] == "A" and g["total"] and g["blocked"] == g["total"] else (
        "partial" if g["origin"] == "A" and g["blocked"] else "cannot")
    g["verdict_tr"] = _verdict_tr(g)
    g["attack"] = attack_id
    return g


def _note_tr(detected: bool, triggered: List[str], missed: List[str], first_ms: Optional[float], g: Dict[str, Any]) -> str:
    if detected:
        head = f"IDS {', '.join(triggered[:3])} ile {first_ms:g} ms içinde yakaladı"
        if missed:
            head += f" (beklenen {', '.join(missed)} sessiz kaldı)"
    else:
        head = "IDS hiçbir kural tetiklemedi"
    return head + "; " + _verdict_tr(g)


def run_coverage(seed: int = 1) -> Dict[str, Any]:
    t_run = time.perf_counter()
    results: List[Dict[str, Any]] = []
    for aid, cls in ATTACKS.items():
        rec = record_attack(aid, None, seed)
        expected = [_base_rule(x) for x in (EXPECTED_OVERRIDE.get(aid) or cls.expected_layers)]
        times: Dict[str, float] = {}
        for t, r in rec["alerts"]:
            times.setdefault(_base_rule(r), t)
        triggered = sorted(times)
        missed = [e for e in expected if e not in times]
        detected = bool(set(expected) & set(times)) if expected else bool(times)
        first_ms = round((min(times.values()) - rec["t0"]) * 1000, 1) if times else None
        g = gateway_run(aid, rec["attacker"])
        g["verdict"] = ("cannot" if g["origin"] == "B" else "blocks" if g["total"] and g["blocked"] == g["total"]
                        else "partial" if g["blocked"] else "cannot")
        g["verdict_tr"] = _verdict_tr(g)
        results.append({
            "id": aid, "name": NAME_TR.get(aid, cls.name), "name_en": cls.name, "category": cls.category,
            "tactic": TACTIC_OF.get(aid, "execution"), "expected": expected, "triggered": triggered, "missed": missed,
            "detected": detected, "first_detect_ms": first_ms,
            "gateway": {"blocked": g["blocked"], "total": g["total"], "rules": g["rules"], "origin": g["origin"],
                        "verdict": g["verdict"], "verdict_tr": g["verdict_tr"]},
            "note_tr": _note_tr(detected, triggered, missed, first_ms, g),
        })
    tactics = []
    for tid, tname in TACTICS:
        cells = [{"id": r["id"], "name": r["name"],
                  "status": "missed" if not r["detected"] else ("partial" if r["missed"] else "detected")}
                 for r in results if r["tactic"] == tid]
        tactics.append({"id": tid, "name_tr": tname, "cells": cells})
    summary = {"scenarios": len(results), "detected": sum(r["detected"] for r in results),
               "gateway_blocked": sum(1 for r in results if r["gateway"]["verdict"] == "blocks"),
               "gateway_partial": sum(1 for r in results if r["gateway"]["verdict"] == "partial"),
               "gateway_cannot": sum(1 for r in results if r["gateway"]["verdict"] == "cannot"),
               "either": sum(1 for r in results if r["detected"] or r["gateway"]["verdict"] != "cannot")}
    report = {"status": "done", "duration_ms": round((time.perf_counter() - t_run) * 1000, 1), "seed": seed,
              "summary": summary, "results": results, "matrix": {"tactics": tactics},
              "disclaimer_tr": "Taktik eşlemesi yaklaşıktır, resmî bir çerçeve değildir; sonuçlar simülatör verisidir."}
    global LAST
    LAST = report          # atomic swap: a concurrent GET never sees a half-cleared dict
    return report


def last_report() -> Dict[str, Any]:
    return dict(LAST)
