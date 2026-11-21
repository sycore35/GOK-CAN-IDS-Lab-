"""IDS Rule Designer back end: user-defined detection rules, persisted as JSON and evaluated live
inside CANIntrusionDetectionEngine (engine.custom_rules)."""
import collections
import json
import operator
import os
import re
import threading
from typing import Any, Deque, Dict, List, Optional

from src.can_frame import CANFrame
from src.can_ids import CANAlert

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
OPS = {">": operator.gt, "<": operator.lt, ">=": operator.ge, "<=": operator.le, "==": operator.eq, "!=": operator.ne}
TYPES = {
    "signal_threshold": ("signal", "op", "value"),
    "signal_delta": ("signal", "max_delta"),
    "rate": ("max_count", "window_ms"),
    "payload_match": ("pattern_hex",),
    "dlc_mismatch": (),
}


def _hex_bytes(s: str) -> bytes:
    clean = re.sub(r"[\s:,]|0x", "", str(s))
    if clean and (len(clean) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", clean)):
        raise ValueError(f"'{s}' is not a valid hex byte string")
    return bytes.fromhex(clean)


def _parse_id(v: Any) -> Optional[int]:
    if v in (None, "", "*", "any"):
        return None
    i = int(str(v), 16) if isinstance(v, str) and (v.lower().startswith("0x") or re.search(r"[a-fA-F]", v)) else int(v)
    if not 0 <= i <= 0x1FFFFFFF:
        raise ValueError("arbitration id out of range")
    return i


def _finite(v: Any, name: str, lo: float = -1e12, hi: float = 1e12) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"'{name}' must be a number")
    if not (lo <= x <= hi):   # rejects NaN / +-inf / absurd magnitudes
        raise ValueError(f"'{name}' must be between {lo:g} and {hi:g}")
    return x


def validate_rule(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalised rule dict or raise ValueError with a readable message."""
    if not isinstance(raw, dict):
        raise ValueError("Rule must be an object.")
    r: Dict[str, Any] = {}
    r["name"] = str(raw.get("name", "")).strip()
    if not r["name"]:
        raise ValueError("Rule name is required.")
    r["type"] = raw.get("type")
    if r["type"] not in TYPES:
        raise ValueError(f"Unknown rule type '{r['type']}'. Allowed: {sorted(TYPES)}")
    r["severity"] = str(raw.get("severity", "MEDIUM")).upper()
    if r["severity"] not in SEVERITIES:
        raise ValueError(f"Severity must be one of {SEVERITIES}")
    r["enabled"] = bool(raw.get("enabled", True))
    r["description"] = str(raw.get("description", ""))
    try:
        r["arb_id"] = _parse_id(raw.get("arb_id"))
    except ValueError:
        raise ValueError(f"Invalid arbitration id '{raw.get('arb_id')}'")
    for k in TYPES[r["type"]]:
        if raw.get(k) in (None, ""):
            raise ValueError(f"Field '{k}' is required for rule type '{r['type']}'.")
    t = r["type"]
    if t == "signal_threshold":
        if raw["op"] not in OPS:
            raise ValueError(f"Operator must be one of {list(OPS)}")
        r.update(signal=str(raw["signal"]), op=raw["op"], value=_finite(raw["value"], "value"))
    elif t == "signal_delta":
        r.update(signal=str(raw["signal"]), max_delta=_finite(raw["max_delta"], "max_delta"))
        if r["max_delta"] < 0:
            raise ValueError("max_delta must be >= 0")
    elif t == "rate":
        r.update(max_count=int(_finite(raw["max_count"], "max_count", 1, 100000)),
                 window_ms=_finite(raw["window_ms"], "window_ms", 0.001, 60000))
        if r["arb_id"] is None:
            raise ValueError("A rate rule needs a specific CAN ID.")
    elif t == "payload_match":
        pat = _hex_bytes(raw["pattern_hex"])
        mask = _hex_bytes(raw.get("mask_hex") or "") or b"\xff" * len(pat)
        if not pat or len(mask) != len(pat) or len(pat) > 64:
            raise ValueError("pattern_hex must be 1..64 bytes and mask_hex (if given) the same length.")
        r.update(pattern_hex=pat.hex().upper(), mask_hex=mask.hex().upper())
    if "id" in raw and raw["id"]:
        r["id"] = str(raw["id"])
    return r


class RuleSet:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.rules: Dict[str, Dict[str, Any]] = {}
        self._rate: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._last_val: Dict[str, float] = {}
        self.hits: Dict[str, int] = collections.defaultdict(int)
        self._lock = threading.RLock()
        self._n = 0
        self.load()

    def _next_id(self) -> str:
        while True:
            self._n += 1
            rid = f"CUST-{self._n:03d}"
            if rid not in self.rules:
                return rid

    def add(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            r = validate_rule({**raw, "id": None})
            r["id"] = self._next_id()
            self.rules[r["id"]] = r
            self.save()
            return r

    def update(self, rid: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if rid not in self.rules:
                raise KeyError(rid)
            r = validate_rule({**self.rules[rid], **raw, "id": rid})
            self.rules[rid] = r
            self._reset_state(rid)
            self.save()
            return r

    def delete(self, rid: str) -> None:
        with self._lock:
            if rid not in self.rules:
                raise KeyError(rid)
            del self.rules[rid]
            self._reset_state(rid)
            self.save()

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{**r, "hits": self.hits.get(r["id"], 0)} for r in self.rules.values()]

    def reset_state(self) -> None:
        """Forget all per-rule runtime state (rate windows, last values, hit counters), e.g. on a lab reset."""
        with self._lock:
            self._rate.clear()
            self._last_val.clear()
            self.hits.clear()

    def _reset_state(self, rid):
        self._rate.pop(rid, None)
        self._last_val.pop(rid, None)

    def save(self) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "rules": list(self.rules.values())}, f, indent=2)
        os.replace(tmp, self.path)

    def load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("rules", []):
                try:   # one bad rule must not wipe the others
                    v = validate_rule(r)
                    v["id"] = str(r["id"])
                    self.rules[v["id"]] = v
                except (ValueError, KeyError, TypeError):
                    continue
            nums = [int(k.split("-")[1]) for k in self.rules if re.fullmatch(r"CUST-\d+", k)]
            self._n = max(nums or [0])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            self.rules = {}

    def evaluate(self, frame: CANFrame, decoded: Dict[str, Any], engine=None) -> List[CANAlert]:
        out: List[CANAlert] = []
        with self._lock:
            rules = [r for r in self.rules.values() if r["enabled"]]
        for r in rules:
            if r["arb_id"] is not None and r["arb_id"] != frame.arbitration_id:
                continue
            msg = self._check(r, frame, decoded, engine)
            if msg is None:
                continue
            observed, expected, evidence = msg
            self.hits[r["id"]] += 1
            out.append(CANAlert(
                rule_id=r["id"], rule_name=r["name"], severity=r["severity"], arbitration_id=frame.arbitration_id,
                hex_id=frame.hex_id, message_name=decoded.get("name", "UNKNOWN"), observed_value=observed,
                expected_threshold=expected, evidence=evidence,
                mitigation=r.get("description") or "User-defined rule: review and tune in the Rule Designer.",
                raw_frame_hex=frame.hex_data, timestamp=frame.timestamp, qev_event_id="QEV_CUSTOM_RULE",
                unece_r155_code="USER_DEFINED"))
        return out

    def _check(self, r, frame, decoded, engine=None):
        t = r["type"]
        if t == "signal_threshold":
            s = decoded.get("signals", {}).get(r["signal"])
            if s and s.get("valid") and OPS[r["op"]](float(s["value"]), r["value"]):
                return (f"{r['signal']}={s['value']}", f"not ({r['signal']} {r['op']} {r['value']:g})",
                        f"Signal {r['signal']} = {s['value']} satisfies the condition {r['op']} {r['value']:g}.")
        elif t == "signal_delta":
            s = decoded.get("signals", {}).get(r["signal"])
            if s and s.get("valid"):
                v = float(s["value"])
                prev = self._last_val.get(r["id"])
                self._last_val[r["id"]] = v
                if prev is not None and abs(v - prev) > r["max_delta"]:
                    return (f"Δ{r['signal']}={v - prev:+.2f}", f"|Δ| <= {r['max_delta']:g} per frame",
                            f"{r['signal']} changed from {prev} to {v} between consecutive frames.")
        elif t == "rate":
            q = self._rate.get(r["id"])
            if q is None or q.maxlen != r["max_count"] + 1:
                q = self._rate[r["id"]] = collections.deque(maxlen=r["max_count"] + 1)   # bounded window
            now = frame.timestamp
            if q and now < q[-1]:   # simulation clock went backwards (reset): old timestamps are meaningless
                q.clear()
            q.append(now)
            while q and q[0] < now - r["window_ms"] / 1000.0:
                q.popleft()
            if len(q) > r["max_count"]:
                return (f"{len(q)} frames in {r['window_ms']:g} ms", f"<= {r['max_count']} frames",
                        f"{frame.hex_id} exceeded {r['max_count']} frames per {r['window_ms']:g} ms.")
        elif t == "payload_match":
            pat, mask = bytes.fromhex(r["pattern_hex"]), bytes.fromhex(r["mask_hex"])
            d = frame.data
            if len(d) >= len(pat) and all((d[i] & mask[i]) == (pat[i] & mask[i]) for i in range(len(pat))):
                return (frame.hex_data, f"payload not matching {r['pattern_hex']}/{r['mask_hex']}",
                        "Payload matches the forbidden byte pattern.")
        elif t == "dlc_mismatch":
            d = (engine.dbc.get_message_def(frame.arbitration_id) if engine else None)
            if d and d.get("dlc") is not None and len(frame.data) != int(d["dlc"]):
                return (f"{len(frame.data)} bytes", f"{d['dlc']} bytes per DBC",
                        "Frame length differs from the DBC definition.")
        return None
