"""Python mirror of the GÖK-GW1 gateway firmware (firmware/gokguard/policy.c + guard.c).

Same policy (GW-01..GW-10), same evaluation ORDER, same integer token buckets, same CRC-8 SAE J1850 as the C code;
tools/gen_guard_vectors.py proves the parity with replayable vectors. The policy tables are built by
tools/policy_compiler.py (single source of truth: config/can_signals.json + config/config.yaml).

Domains: ATTACKER:* and tester/OBD sources are domain A (untrusted); ECU_* are domain B (protected, their traffic never
crosses the gateway). The model watches the live bus passively: it never changes what happens on the bus.
"""
import collections
import math
import re
import threading
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from src.dbc_decoder import calc_crc8_sae_j1850
from tools import policy_compiler as pc

FORWARD, DROP = "FORWARD", "DROP"
A2B, B2A = "A>B", "B>A"
RULES = tuple(f"GW-{i:02d}" for i in range(1, 11))
RULE_TEXT_TR = {
    "GW-01": "Listede olmayan ya da bu yönde izinsiz kimlik",
    "GW-02": "Veri uzunluğu (DLC) tanımla uyuşmuyor",
    "GW-03": "Kimlik başına hız sınırı aşıldı",
    "GW-04": "Sinyal fiziksel aralığın dışında",
    "GW-05": "Sayaç ya da CRC-8 hatası",
    "GW-06": "Atölye anahtarı yokken tanılama (UDS) kimliği",
    "GW-07": "Atölye anahtarı yokken tehlikeli UDS servisi",
    "GW-08": "Toplam bus seli sınırı aşıldı",
    "GW-09": "Tamper kilidi: A tarafından hiçbir şey geçmez",
    "GW-10": "Güvenlik kritik kimlik A tarafından geçmez",
}
# Attackers that must already sit inside domain B to work (here: the masquerade silences the real ABS node, which
# is only possible from a compromised ECU on the protected bus). The gateway never sees their frames.
ATTACK_ORIGIN = {"speed_spoof_stealth": "B"}
EVENT_COALESCE_MS = 100
EVENT_KEEP = 200
U32 = 0xFFFFFFFF


def classify_domain(source: str) -> str:
    """'A' (untrusted: attacker, OBD/tester, unknown) or 'B' (protected: ECU_* nodes, compromised-in-B attackers)."""
    if source.startswith("ECU_"):
        return "B"
    if source.startswith("ATTACKER:"):
        return ATTACK_ORIGIN.get(source.split(":", 1)[1], "A")
    return "A"


def default_policy() -> Dict[str, Any]:
    signals, config = pc.load_sources()
    return pc.build_model(signals, config)


class _Bucket:
    __slots__ = ("tokens", "last_us")

    def __init__(self, burst: int):
        self.tokens = burst * 1_000_000
        self.last_us = 0

    def take(self, rate_fps: int, burst: int, now_us: int) -> bool:
        el = (now_us - self.last_us) & U32
        if el > 1_000_000:
            el = 1_000_000
        self.last_us = now_us
        tok = min(self.tokens + el * rate_fps, burst * 1_000_000)
        if tok < 1_000_000:
            self.tokens = tok
            return False
        self.tokens = tok - 1_000_000
        return True


class GatewayModel:
    def __init__(self, policy: Optional[Dict[str, Any]] = None):
        self.policy = policy or default_policy()
        self._msgs = {m["id"]: m for m in self.policy["msgs"]}
        self._sigs = self.policy["sigs"]
        self._uds = set(self.policy["uds_ids"])
        self._dangerous = set(self.policy["dangerous"])
        self.lock = threading.RLock()
        self.workshop_key = False
        self.tamper = False      # switch position (lid open)
        self.locked = False      # latched lockdown; like guard.c it survives closing the lid until cleared
        self.events: Deque[Dict[str, Any]] = collections.deque(maxlen=EVENT_KEEP)
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self, keep_switches: bool = True) -> None:
        with self.lock:
            if not keep_switches:
                self.workshop_key = self.tamper = self.locked = False
            self._total = _Bucket(self.policy["total_burst"])
            self._per_id = {i: _Bucket(self.policy["id_burst"]) for i in self._msgs}
            self._last_counter: Dict[int, int] = {}
            self.stats = {"passed": 0, "blocked": 0, "b_to_a": 0, "b_internal": 0, "hardware_events": 0,
                          "events_suppressed": 0, "by_rule": {}}
            self.events.clear()
            self._last_ev_ms: Dict[str, int] = {}
            self._seq = 0
            self._now_s = 0.0

    def set_switches(self, workshop_key: Optional[bool] = None, tamper: Optional[bool] = None) -> None:
        with self.lock:
            if workshop_key is not None:
                self.workshop_key = bool(workshop_key)
            if tamper is not None:
                self.tamper = bool(tamper)
                if self.tamper and not self.locked:      # latch, like the firmware's LOCKDOWN (sample_inputs)
                    self.locked = True
                    self._push_event(self._now_s, "LOCKDOWN", "GW-09", 0, False, b"", 0, force=True)
                    self.stats["blocked"] += 1
                    self.stats["by_rule"]["GW-09"] = self.stats["by_rule"].get("GW-09", 0) + 1

    def clear_lockdown(self) -> bool:
        """Mirror of guard_clear_lockdown(): refused while the tamper switch is still open."""
        with self.lock:
            if self.tamper:
                return False
            self.locked = False
            return True

    @property
    def mode(self) -> str:
        return "locked" if self.locked else ("workshop" if self.workshop_key else "normal")

    # --------------------------------------------------------------- decision
    @staticmethod
    def _service(dlc: int, data: bytes) -> int:
        if dlc < 2:
            return -1
        pci, n = data[0] >> 4, data[0] & 0x0F
        if pci == 0 and 1 <= n <= dlc - 1:
            return data[1]
        if pci == 1 and dlc >= 3:
            return data[2]
        return -1

    def _decide(self, can_id: int, ext: bool, dlc: int, data: bytes, direction: str, t_us: int) -> Tuple[str, Optional[str]]:
        if direction == B2A:
            return FORWARD, None
        if direction != A2B:
            return DROP, "GW-01"
        if self.locked:
            return DROP, "GW-09"
        if dlc > 8:
            return DROP, "GW-02"
        if not self._total.take(self.policy["total_rate_fps"], self.policy["total_burst"], t_us):
            return DROP, "GW-08"
        if not ext and can_id in self._uds:
            if self.workshop_key:
                return FORWARD, None
            return DROP, ("GW-07" if self._service(dlc, data) in self._dangerous else "GW-06")
        m = None if ext else self._msgs.get(can_id)
        if m is None:
            return DROP, "GW-01"
        if dlc != m["dlc"]:
            return DROP, "GW-02"
        if m["flags"] & pc.F_COUNTER_CRC:
            mask = (1 << m["cnt_len"]) - 1
            cnt = (data[m["cnt_start"] >> 3] >> (m["cnt_start"] & 7)) & mask
            if calc_crc8_sae_j1850(bytes(data[:m["crc_byte"]])) != data[m["crc_byte"]]:
                return DROP, "GW-05"
            last = self._last_counter.get(can_id)
            ok = last is None or cnt == ((last + 1) & mask)
            self._last_counter[can_id] = cnt
            if not ok:
                return DROP, "GW-05"
        word = int.from_bytes(data[:8].ljust(8, b"\0"), "little")
        for s in self._sigs[m["sig_first"]:m["sig_first"] + m["sig_n"]]:
            raw = (word >> s["start"]) & ((1 << s["len"]) - 1)
            if raw < s["raw_min"] or raw > s["raw_max"]:
                return DROP, "GW-04"
        if m["flags"] & pc.F_CRITICAL:
            return DROP, "GW-10"
        if not m["flags"] & pc.F_A_ALLOWED:
            return DROP, "GW-01"
        if not self._per_id[can_id].take(m["rate_fps"], self.policy["id_burst"], t_us):
            return DROP, "GW-03"
        return FORWARD, None

    def _push_event(self, t: float, kind: str, rule: str, can_id: int, ext: bool, data: bytes, dlc: int,
                    force: bool = False, source: str = "sim") -> None:
        t_ms = int(t * 1000 + 1e-6)   # floor, like the firmware's t_us / 1000
        if not force and kind == "BLOCK":
            last = self._last_ev_ms.get(rule)
            if last is not None and ((t_ms - last) & U32) < EVENT_COALESCE_MS:
                self.stats["events_suppressed"] += 1
                return
            self._last_ev_ms[rule] = t_ms
        idtxt = f"0x{can_id:08X}" if ext else f"0x{can_id:03X}"
        self.events.append({"t": round(t_ms / 1000, 3), "ev": kind, "rule": rule, "dir": A2B, "id": idtxt,
                            "dlc": dlc, "data": data[:dlc].hex(), "seq": self._seq, "source": source})
        self._seq += 1

    def evaluate_raw(self, can_id: int, ext: bool, dlc: int, data: bytes, direction: str, t_us: int,
                     t: Optional[float] = None) -> Tuple[str, Optional[str]]:
        """Decision + bookkeeping (stats, events). `t_us` is the uint32 microsecond clock the firmware sees."""
        t_us &= U32
        data = bytes(data[:8]).ljust(8, b"\0")
        with self.lock:
            self._now_s = (t_us // 1000) / 1000 if t is None else t
            decision, rule = self._decide(can_id, ext, dlc, data, direction, t_us)
            if direction == B2A:
                self.stats["b_to_a"] += 1
            elif decision == FORWARD:
                self.stats["passed"] += 1
            else:
                self.stats["blocked"] += 1
                self.stats["by_rule"][rule] = self.stats["by_rule"].get(rule, 0) + 1
                self._push_event((t_us // 1000) / 1000 if t is None else t, "BLOCK", rule, can_id, ext, data, min(dlc, 8))
            return decision, rule

    def evaluate(self, frame, direction: str, t: float) -> Tuple[str, Optional[str]]:
        """frame: any object with arbitration_id, data, dlc, is_extended_id (CANFrame). t: seconds."""
        return self.evaluate_raw(frame.arbitration_id, bool(frame.is_extended_id), int(frame.dlc), bytes(frame.data),
                                 direction, int(round(t * 1_000_000)), t)

    # ----------------------------------------------------------- live passive
    def observe(self, frame, t: Optional[float] = None) -> Optional[Tuple[str, Optional[str]]]:
        """Classify a frame seen on the (simulated) bus. B-domain frames only count; A-domain frames are evaluated
        A>B. Never raises, never touches the bus."""
        t = frame.timestamp if t is None else t
        if classify_domain(frame.source) == "B":
            with self.lock:
                self.stats["b_internal"] += 1
            return None
        return self.evaluate(frame, A2B, t)

    # ------------------------------------------------------------------ views
    _HW_EV = ("BLOCK", "PASS", "LOCKDOWN", "BOOT", "WARN")
    _RULE_RE = re.compile(r"GW-(0[1-9]|10)")

    @classmethod
    def sanitize_hardware_event(cls, it: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Whitelist and bound the fields of an event line sent by a real GÖK-GW1 (via TN1). None = invalid."""
        if not isinstance(it, dict) or it.get("ev") not in cls._HW_EV:
            return None
        ev: Dict[str, Any] = {"ev": it["ev"], "source": "hardware"}
        try:
            t = float(it.get("t", 0.0))
            ev["t"] = round(t, 3) if math.isfinite(t) and 0 <= t < 1e10 else 0.0
        except (TypeError, ValueError):
            ev["t"] = 0.0
        rule = str(it.get("rule", ""))
        ev["rule"] = rule if cls._RULE_RE.fullmatch(rule) else "GW-??"
        if it.get("dir") in (A2B, B2A):
            ev["dir"] = it["dir"]
        cid = it.get("id")
        try:
            n = int(cid, 0) if isinstance(cid, str) else int(cid)
            if 0 <= n <= 0x1FFFFFFF:
                ev["id"] = f"0x{n:03X}"
        except (TypeError, ValueError, OverflowError):
            pass
        if isinstance(it.get("dlc"), int) and 0 <= it["dlc"] <= 64:
            ev["dlc"] = it["dlc"]
        data = it.get("data")
        if isinstance(data, str) and re.fullmatch(r"[0-9A-Fa-f]{0,128}", data):
            ev["data"] = data.upper()
        if isinstance(it.get("seq"), int) and 0 <= it["seq"] < 2 ** 32:
            ev["seq"] = it["seq"]
        mac = it.get("mac")
        if isinstance(mac, str) and re.fullmatch(r"[0-9A-Fa-f]{16,64}", mac):
            ev["mac"] = mac.upper()
            ev["mac_verified"] = False   # the lab has no device key; a real deployment verifies with the ATECC608A
        return ev

    def add_hardware_events(self, items: Iterable[Dict[str, Any]]) -> int:
        clean = [e for e in (self.sanitize_hardware_event(i) for i in items) if e is not None]
        with self.lock:
            for ev in clean:
                ev.setdefault("seq", self._seq)
                self._seq += 1
                self.events.append(ev)
                self.stats["hardware_events"] += 1
                if ev["ev"] in ("BLOCK", "LOCKDOWN"):
                    self.stats["blocked"] += 1
                    self.stats["by_rule"][ev["rule"]] = self.stats["by_rule"].get(ev["rule"], 0) + 1
        return len(clean)

    def state(self) -> Dict[str, Any]:
        with self.lock:
            return {"mode": self.mode, "workshop_key": self.workshop_key, "tamper": self.tamper, "locked": self.locked,
                    "stats": {**self.stats, "by_rule": dict(self.stats["by_rule"])},
                    "events": list(self.events)[-50:]}
