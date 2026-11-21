#!/usr/bin/env python3
"""GOK-GW1 policy compiler.

``config/can_signals.json`` (DBC) + ``config/config.yaml`` (``gateway:`` section)
-> ``firmware/gokguard/policy_generated.h``.

The output is deterministic (no timestamps, no absolute paths). The header comment carries the SHA-256 of
the DBC file and of the canonical ``gateway:`` section, so a stale header is detected by ``--check``.
``build_model()`` is also what ``src/gateway_model.py`` (the Python mirror) is built from: one source of truth.

    python tools/policy_compiler.py            # write the header
    python tools/policy_compiler.py --check    # exit 1 if the header is stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

import yaml

COMPILER_VERSION = "1"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIGNALS = ROOT / "config" / "can_signals.json"
DEFAULT_CONFIG = ROOT / "config" / "config.yaml"
DEFAULT_OUT = ROOT / "firmware" / "gokguard" / "policy_generated.h"

F_A_ALLOWED, F_CRITICAL, F_COUNTER_CRC = 1, 2, 4
COUNTER_SIGNAL, CRC_SIGNAL = "rolling_counter", "crc8_checksum"


class PolicyError(ValueError):
    """Invalid or unsafe source configuration."""


def _int(value: Any, what: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise PolicyError(f"{what} must be an integer in [{lo}, {hi}], got {value!r}")
    return value


def _ids(values: Any, what: str, hi: int = 0x7FF) -> List[int]:
    if not isinstance(values, list):
        raise PolicyError(f"gateway.{what} must be a list")
    out = [_int(v, f"gateway.{what} entry", 0, hi) for v in values]
    if len(set(out)) != len(out):
        raise PolicyError(f"gateway.{what} has duplicates")
    return sorted(out)


def _bound(value: Any, offset: Any, scale: Decimal, length: int, up: bool) -> int:
    """Engineering bound -> raw bound, rounded towards the inside of the range, clamped to the bit width."""
    q = ((Decimal(str(value)) - Decimal(str(offset))) / scale).quantize(Decimal("0.000001"))
    # min rounds up (ceil), max rounds down (floor): the allowed raw range never exceeds the DBC range
    raw = int(math.floor(q)) if up else int(math.ceil(q))
    return max(0, min((1 << length) - 1, raw))


def build_model(signals: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    gw = config.get("gateway")
    if not isinstance(gw, dict):
        raise PolicyError("config.yaml has no 'gateway' section")
    a_ids = _ids(gw.get("a_to_b_ids", []), "a_to_b_ids")
    crit = _ids(gw.get("critical_ids", []), "critical_ids")
    uds = _ids(gw.get("uds_request_ids", []), "uds_request_ids")
    dang = _ids(gw.get("dangerous_services", []), "dangerous_services", 0xFF)
    mult = _int(gw.get("per_id_rate_multiplier", 2), "per_id_rate_multiplier", 1, 20)
    id_burst = _int(gw.get("per_id_burst", 4), "per_id_burst", 1, 255)
    tot_rate = _int(gw.get("total_rate_fps", 200), "total_rate_fps", 1, 4000)
    tot_burst = _int(gw.get("total_burst", 40), "total_burst", 1, 4000)
    if set(a_ids) & set(crit):
        raise PolicyError("an ID cannot be both a_to_b and critical (GW-10 must win)")
    if set(a_ids) & set(uds):
        raise PolicyError("an ID cannot be both a_to_b and a UDS request ID")
    msgs, sigs, seen = [], [], set()
    for m in signals.get("messages", []):
        mid = _int(m["id_dec"], "message id", 0, 0x7FF)
        if mid in seen:
            raise PolicyError(f"duplicate message id 0x{mid:03X}")
        seen.add(mid)
        dlc = _int(m["dlc"], f"0x{mid:03X} dlc", 0, 8)
        cycle = _int(m["cycle_time_ms"], f"0x{mid:03X} cycle_time_ms", 1, 100000)
        first = len(sigs)
        cnt = crc = None
        for s in m.get("signals", []):
            if s.get("endian", "little") != "little":
                raise PolicyError(f"0x{mid:03X}.{s['name']}: only little-endian signals are supported")
            start = _int(s["start_bit"], "start_bit", 0, 63)
            length = _int(s["length"], "length", 1, 32)
            if start + length > dlc * 8:
                raise PolicyError(f"0x{mid:03X}.{s['name']}: signal does not fit into DLC {dlc}")
            scale = Decimal(str(s.get("scale", 1)))
            if scale <= 0:
                raise PolicyError(f"0x{mid:03X}.{s['name']}: scale must be > 0")
            lo = _bound(s["min"], s.get("offset", 0), scale, length, up=False)
            hi = _bound(s["max"], s.get("offset", 0), scale, length, up=True)
            if lo > hi:
                raise PolicyError(f"0x{mid:03X}.{s['name']}: empty raw range")
            sigs.append({"msg": mid, "name": s["name"], "start": start, "len": length, "raw_min": lo, "raw_max": hi})
            if s["name"] == COUNTER_SIGNAL:
                cnt = (start, length)
            if s["name"] == CRC_SIGNAL:
                if start % 8 or length != 8:
                    raise PolicyError(f"0x{mid:03X}: CRC signal must be one aligned byte")
                crc = start // 8
        if (cnt is None) != (crc is None):
            raise PolicyError(f"0x{mid:03X}: counter and CRC signals must come together")
        if cnt and cnt[0] % 8 + cnt[1] > 8:
            raise PolicyError(f"0x{mid:03X}: counter must sit inside one byte")
        flags = (F_A_ALLOWED if mid in a_ids else 0) | (F_CRITICAL if mid in crit else 0) | (F_COUNTER_CRC if cnt else 0)
        msgs.append({"id": mid, "name": m["name"], "dlc": dlc, "flags": flags,
                     "rate_fps": -(-mult * 1000 // cycle), "sig_first": first, "sig_n": len(sigs) - first,
                     "cnt_start": cnt[0] if cnt else 0, "cnt_len": cnt[1] if cnt else 0,
                     "crc_byte": crc if crc is not None else 0})
    msgs.sort(key=lambda x: x["id"])
    unknown = (set(a_ids) | set(crit)) - seen
    if unknown:
        raise PolicyError("gateway IDs not in the DBC: " + ", ".join(f"0x{i:03X}" for i in sorted(unknown)))
    order = {m["id"]: i for i, m in enumerate(msgs)}
    sigs.sort(key=lambda x: (order[x["msg"]], x["start"]))
    pos = 0
    for m in msgs:                                     # re-index after sorting
        m["sig_first"] = pos
        pos += m["sig_n"]
    return {"msgs": msgs, "sigs": sigs, "uds_ids": uds, "dangerous": dang, "id_burst": id_burst,
            "total_rate_fps": tot_rate, "total_burst": tot_burst, "multiplier": mult}


def _digest(signals_path: Path, config: Dict[str, Any]) -> Dict[str, str]:
    canon = json.dumps(config.get("gateway"), sort_keys=True, separators=(",", ":"))
    return {"signals": hashlib.sha256(signals_path.read_bytes()).hexdigest(),
            "gateway": hashlib.sha256(canon.encode()).hexdigest()}


def render(model: Dict[str, Any], dig: Dict[str, str]) -> str:
    L: List[str] = []
    a = L.append
    a("/* policy_generated.h -- GENERATED by tools/policy_compiler.py. DO NOT EDIT. */")
    a("/*")
    a(f" * compiler version      : {COMPILER_VERSION}")
    a(f" * can_signals.json      : sha256 {dig['signals']}")
    a(f" * config.yaml [gateway] : sha256 {dig['gateway']}")
    a(" * Regenerate: .venv/bin/python tools/policy_compiler.py   (--check verifies freshness)")
    a(" */")
    a("#ifndef CG_POLICY_GENERATED_H")
    a("#define CG_POLICY_GENERATED_H")
    a("")
    a("#include <stdint.h>")
    a("")
    a("#define CG_F_A_ALLOWED  1u   /* may be sent A -> B */")
    a("#define CG_F_CRITICAL   2u   /* safety critical: never accepted from A (GW-10) */")
    a("#define CG_F_COUNTER_CRC 4u  /* rolling counter + CRC-8 SAE J1850 (GW-05) */")
    a("")
    a("typedef struct { uint8_t start; uint8_t len; uint32_t raw_min; uint32_t raw_max; } cg_sig_t;")
    a("typedef struct { uint16_t id; uint8_t dlc; uint8_t flags; uint16_t rate_fps; uint8_t sig_first; uint8_t sig_n;")
    a("                  uint8_t cnt_start; uint8_t cnt_len; uint8_t crc_byte; } cg_msg_t;")
    a("")
    a(f"#define CG_N_MSGS          {len(model['msgs'])}u")
    a(f"#define CG_N_SIGS          {len(model['sigs'])}u")
    a(f"#define CG_ID_BURST        {model['id_burst']}u    /* GW-03 bucket depth */")
    a(f"#define CG_TOTAL_RATE_FPS  {model['total_rate_fps']}u   /* GW-08 */")
    a(f"#define CG_TOTAL_BURST     {model['total_burst']}u")
    a(f"#define CG_N_UDS_IDS       {len(model['uds_ids'])}u")
    a(f"#define CG_N_DANGEROUS     {len(model['dangerous'])}u")
    a("")
    a("/* DBC messages, sorted by ID. rate_fps = ceil(multiplier x 1000 / cycle_ms). */")
    a("static const cg_msg_t cg_msgs[CG_N_MSGS] = {")
    for m in model["msgs"]:
        a(f"    {{ 0x{m['id']:03X}u, {m['dlc']}u, {m['flags']}u, {m['rate_fps']}u, {m['sig_first']}u, {m['sig_n']}u, "
          f"{m['cnt_start']}u, {m['cnt_len']}u, {m['crc_byte']}u }},   /* {m['name']} */")
    a("};")
    a("")
    a("/* Signal raw ranges (little-endian bit start/length); engineering min/max / scale, rounded inwards. */")
    a("static const cg_sig_t cg_sigs[CG_N_SIGS] = {")
    for s in model["sigs"]:
        a(f"    {{ {s['start']}u, {s['len']}u, {s['raw_min']}u, {s['raw_max']}u }},   /* 0x{s['msg']:03X} {s['name']} */")
    a("};")
    a("")
    a("/* UDS request IDs (GW-06) and dangerous services (GW-07). */")
    a("static const uint16_t cg_uds_ids[CG_N_UDS_IDS] = { " + ", ".join(f"0x{i:03X}u" for i in model["uds_ids"]) + " };")
    a("static const uint8_t cg_dangerous[CG_N_DANGEROUS] = { " + ", ".join(f"0x{i:02X}u" for i in model["dangerous"]) + " };")
    a("")
    a("#endif /* CG_POLICY_GENERATED_H */")
    return "\n".join(L) + "\n"


def load_sources(signals_path: Path = DEFAULT_SIGNALS, config_path: Path = DEFAULT_CONFIG):
    signals_path, config_path = Path(signals_path), Path(config_path)
    signals = json.loads(signals_path.read_text(encoding="utf-8"))
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return signals, config


def compile_policy(signals_path: Path = DEFAULT_SIGNALS, config_path: Path = DEFAULT_CONFIG) -> str:
    signals, config = load_sources(signals_path, config_path)
    return render(build_model(signals, config), _digest(Path(signals_path), config))


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--signals", type=Path, default=DEFAULT_SIGNALS)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if --out is stale")
    args = ap.parse_args(argv)
    try:
        text = compile_policy(args.signals, args.config)
    except (PolicyError, OSError, KeyError, ValueError, yaml.YAMLError) as exc:
        print(f"policy_compiler: error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        if not args.out.exists() or args.out.read_text(encoding="utf-8") != text:
            print(f"policy_compiler: {args.out} is stale; re-run without --check", file=sys.stderr)
            return 1
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"policy_compiler: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
