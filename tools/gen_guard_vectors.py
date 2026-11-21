#!/usr/bin/env python3
"""Gateway parity vectors.

Runs every simulator attack (and benign traffic, and hand-made probes for each GW rule) through the Python gateway
model (src/gateway_model.py) and writes the frames with their expected decisions to
``firmware/gokguard/tests/vectors.json`` and, for the C test, ``firmware/gokguard/tests/vectors_generated.h``.
The C firmware replays the same frames and must reach the same decision + rule for every frame (parity).

    python tools/gen_guard_vectors.py            # write both files
    python tools/gen_guard_vectors.py --check    # exit 1 if they are stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.attacks import ATTACKS  # noqa: E402
from src.coverage import record_attack  # noqa: E402
from src.dbc_decoder import calc_crc8_sae_j1850  # noqa: E402
from src.gateway_model import A2B, B2A, GatewayModel  # noqa: E402

OUT_DIR = ROOT / "firmware" / "gokguard" / "tests"
CAP = 150            # frames per case kept in the vectors
BASE_US = 1_000_000


def _fr(t_us: int, can_id: int, data: bytes, dlc: int = -1, ext: bool = False, direction: str = A2B) -> Dict[str, Any]:
    dlc = len(data) if dlc < 0 else dlc
    return {"t_us": t_us, "dir": direction, "id": can_id, "ext": int(ext), "dlc": dlc,
            "data": bytes(data[:8]).ljust(8, b"\0").hex()}


def _brake(bar_raw: int, gear: int, counter: int, bad_crc: bool = False) -> bytes:
    part = bar_raw.to_bytes(2, "little") + bytes([gear, 0, 0, 0, counter & 0x0F])
    crc = calc_crc8_sae_j1850(part)
    return part + bytes([crc ^ 0x55 if bad_crc else crc])


def _probes() -> List[Dict[str, Any]]:
    P: List[Dict[str, Any]] = []

    def case(name, frames, key=False, tamper=False, expect=()):
        P.append({"name": name, "kind": "probe", "attack": None, "workshop_key": key, "tamper": tamper,
                  "frames": frames, "expect_rules": list(expect)})

    t = BASE_US
    case("gw01_unknown_and_direction", [_fr(t, 0x555, b"\x01\x02"), _fr(t + 10_000, 0x320, b"\1\0\0\0", ext=True),
                                         _fr(t + 20_000, 0x244, bytes(8)), _fr(t + 30_000, 0x7E8, b"\x03\x7f\x27\x35"),
                                         _fr(t + 40_000, 0x2A0, bytes(4))], expect=["GW-01"])
    case("gw02_dlc", [_fr(t, 0x320, bytes(8)), _fr(t + 10_000, 0x3C0, bytes(3)), _fr(t + 20_000, 0x320, b"\1\0\0\0", dlc=9)],
         expect=["GW-02"])
    case("gw03_per_id_rate", [_fr(t + i * 5_000, 0x320, b"\1\0\0\0") for i in range(40)], expect=["GW-03"])
    case("gw04_range", [_fr(t, 0x3C0, (30001).to_bytes(2, "little") + b"\0\0"), _fr(t + 10_000, 0x3C0, (30000).to_bytes(2, "little") + b"\0\0"),
                        _fr(t + 200_000, 0x320, b"\1\0\0\0")], expect=["GW-04"])
    case("gw05_counter_crc", [_fr(t, 0x200, _brake(1000, 2, 1, bad_crc=True)), _fr(t + 20_000, 0x200, _brake(1000, 2, 1)),
                              _fr(t + 40_000, 0x200, _brake(1000, 2, 2)), _fr(t + 60_000, 0x200, _brake(1000, 2, 5)),
                              _fr(t + 80_000, 0x200, _brake(1000, 2, 5)), _fr(t + 100_000, 0x200, _brake(1000, 2, 6))],
         expect=["GW-05", "GW-10"])
    uds = [(0x7E0, b"\x02\x10\x03"), (0x7E0, b"\x02\x27\x01"), (0x7E0, b"\x10\x0f\x34\x00\x44\x00\x10\x00"),
           (0x7E0, b"\x21\x00\x00\xff\xff\xaa\xbb\xcc"), (0x7E0, b"\x05\x2e\xf1\x90\x01\x02"), (0x7DF, b"\x02\x11\x01"),
           (0x6F1, b"\x02\x3e\x00"), (0x7E7, b"\x03\x22\xf1\x90"), (0x7E0, b"\x02\x31\x01"), (0x7E0, b"\x01\x10"),
           (0x7E0, b"\x03\x34\x00\x00"), (0x7E0, b"")]
    case("gw06_gw07_uds_no_key", [_fr(t + i * 10_000, i_, d) for i, (i_, d) in enumerate(uds)], expect=["GW-06", "GW-07"])
    case("uds_with_workshop_key", [_fr(t + i * 10_000, i_, d) for i, (i_, d) in enumerate(uds)], key=True)
    case("gw08_flood", [_fr(t + i * 250, 0x320, b"\1\0\0\0") for i in range(CAP)], expect=["GW-08"])
    case("gw09_tamper_lock", [_fr(t, 0x320, b"\1\0\0\0"), _fr(t + 10_000, 0x7E0, b"\x02\x10\x03"),
                              _fr(t + 20_000, 0x244, bytes(8), direction=B2A), _fr(t + 30_000, 0x180, bytes(8), direction=B2A)],
         key=True, tamper=True, expect=["GW-09"])
    case("gw10_critical_ids", [_fr(t, 0x0C4, (5000).to_bytes(2, "little") + bytes(6)),
                               _fr(t + 10_000, 0x180, (4000).to_bytes(2, "little") + bytes([130, 20, 0, 0, 0, 0])),
                               _fr(t + 20_000, 0x200, _brake(1000, 2, 1)), _fr(t + 40_000, 0x200, _brake(1000, 2, 2))],
         expect=["GW-10"])
    # legitimate A-domain traffic: must all pass (false positives = 0)
    legit = []
    for i in range(60):
        legit.append(_fr(t + i * 100_000, 0x320, b"\1\0\0\0"))
        legit.append(_fr(t + i * 100_000 + 50_000, 0x3C0, (3600).to_bytes(2, "little") + b"\0\0"))
    case("benign_a_domain", legit)
    return P


def build() -> Dict[str, Any]:
    cases: List[Dict[str, Any]] = []
    unevaluated: List[Dict[str, Any]] = []
    for aid in ATTACKS:
        rec = record_attack(aid, None, seed=1, detect=False)
        fr = rec["attacker"]
        if aid == "speed_spoof_stealth":   # attacker lives in domain B: the gateway never sees these frames
            unevaluated.append({"attack": aid, "origin": "B", "frames": len(fr),
                                "reason_tr": "Saldırgan korunan (B) domaininde; trafik GÖK-GW1 üzerinden geçmez."})
            continue
        t0 = fr[0].timestamp
        frames = [_fr(BASE_US + int(round((f.timestamp - t0) * 1e6)), f.arbitration_id, f.data, f.dlc, f.is_extended_id)
                  for f in fr[:CAP]]
        cases.append({"name": f"attack:{aid}", "kind": "attack", "attack": aid, "workshop_key": False, "tamper": False,
                      "frames": frames})
        if aid in ("uds_diagnostic_attack", "uds_reflash"):
            cases.append({"name": f"attack_with_workshop_key:{aid}", "kind": "attack", "attack": aid, "workshop_key": True,
                          "tamper": False, "frames": [dict(f) for f in frames]})
        if aid == "headlight_can_injection_unlock":
            cases.append({"name": f"attack_while_tampered:{aid}", "kind": "attack", "attack": aid, "workshop_key": False,
                          "tamper": True, "frames": [dict(f) for f in frames]})
    ben = record_attack("fuzzing", None, seed=1, detect=False)["benign"]    # ECU_* traffic recorded before/around the attack
    b0 = ben[0].timestamp
    cases.append({"name": "benign_b_to_a", "kind": "benign", "attack": None, "workshop_key": False, "tamper": False,
                  "frames": [_fr(BASE_US + int(round((f.timestamp - b0) * 1e6)), f.arbitration_id, f.data, f.dlc, direction=B2A)
                             for f in ben[:CAP]]})
    cases.extend(_probes())
    for c in cases:                        # expected decisions come from the Python model (the reference)
        gw = GatewayModel()
        gw.set_switches(workshop_key=c["workshop_key"], tamper=c["tamper"])
        for f in c["frames"]:
            dec, rule = gw.evaluate_raw(f["id"], bool(f["ext"]), f["dlc"], bytes.fromhex(f["data"]), f["dir"], f["t_us"])
            f["decision"], f["rule"] = dec, rule
        fr_a = [f for f in c["frames"] if f["dir"] == A2B]
        blocked = sum(1 for f in fr_a if f["decision"] == "DROP")
        c["summary"] = {"total": len(fr_a), "blocked": blocked, "rules": sorted({f["rule"] for f in fr_a if f["rule"]})}
    return {"version": 1, "cap_per_case": CAP, "cases": cases, "unevaluated": unevaluated}


def render_header(vec: Dict[str, Any]) -> str:
    rules = {f"GW-{i:02d}": i for i in range(1, 11)}
    frames: List[str] = []
    cases: List[str] = []
    for c in vec["cases"]:
        first = len(frames)
        for f in c["frames"]:
            d = bytes.fromhex(f["data"])
            frames.append(f"    {{ {f['t_us']}u, {0 if f['dir'] == A2B else 1}, {f['ext']}, {f['dlc']}, "
                          f"{1 if f['decision'] == 'DROP' else 0}, {rules.get(f['rule'], 0)}, 0x{f['id']:X}u, "
                          f"{{ {', '.join(f'0x{b:02X}' for b in d)} }} }},")
        cases.append(f"    {{ \"{c['name']}\", {int(c['workshop_key'])}, {int(c['tamper'])}, {first}u, {len(c['frames'])}u }},")
    digest = hashlib.sha256(json.dumps(vec, sort_keys=True).encode()).hexdigest()
    return "\n".join([
        "/* vectors_generated.h -- GENERATED by tools/gen_guard_vectors.py from tests/vectors.json. DO NOT EDIT. */",
        f"/* vectors sha256 {digest} */",
        "#ifndef CGV_VECTORS_H", "#define CGV_VECTORS_H", "#include <stdint.h>", "",
        "typedef struct { uint32_t t_us; uint8_t dir, ext, dlc, drop, rule; uint32_t id; uint8_t data[8]; } cgv_frame_t;",
        "typedef struct { const char *name; uint8_t workshop, tamper; uint32_t first, n; } cgv_case_t;", "",
        f"#define CGV_N_FRAMES {len(frames)}u", f"#define CGV_N_CASES {len(cases)}u", "",
        "static const cgv_frame_t cgv_frames[CGV_N_FRAMES] = {", *frames, "};", "",
        "static const cgv_case_t cgv_cases[CGV_N_CASES] = {", *cases, "};", "", "#endif", ""])


def generate() -> Tuple[str, str]:
    vec = build()
    return json.dumps(vec, indent=1, sort_keys=True) + "\n", render_header(vec)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    js, hdr = generate()
    targets = {args.out_dir / "vectors.json": js, args.out_dir / "vectors_generated.h": hdr}
    if args.check:
        stale = [str(p) for p, txt in targets.items() if not p.exists() or p.read_text(encoding="utf-8") != txt]
        for p in stale:
            print(f"gen_guard_vectors: {p} is stale", file=sys.stderr)
        return 1 if stale else 0
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for p, txt in targets.items():
        p.write_text(txt, encoding="utf-8")
        print(f"gen_guard_vectors: wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
