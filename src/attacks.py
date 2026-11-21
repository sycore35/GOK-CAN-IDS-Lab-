"""Attack Laboratory: simulated-bus-only attack scenarios (spoofing, replay, flooding, fuzzing, ...).

Attackers are just another node on the SimBus. Their frames carry source="ATTACKER:<id>", which is the
ground-truth label used by the benchmark. Nothing here touches a real network or device.
"""
import random
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

from src.can_frame import CANFrame
from src.dbc_decoder import calc_crc8_sae_j1850

Emit = Tuple[CANFrame, float]  # (frame, ready_time)


# Allowed ranges per parameter name. Rates are bounded so a single request cannot stall the event loop.
_RANGES = {
    "rate_hz": (0.1, 2000.0), "rate_fps": (1.0, 10000.0), "offset_kmh": (-300.0, 300.0),
    "ramp_kmh_per_s": (0.1, 100.0), "max_offset_kmh": (0.0, 300.0), "record_s": (0.1, 30.0),
    "period_s": (0.05, 60.0), "bar": (0.0, 300.0),
}
_ID_KEYS = ("target_id", "arb_id", "id_min", "id_max")


def _num(key: str, v: Any) -> float:
    if isinstance(v, bool):
        raise ValueError(f"{key}: sayı olmalı")
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{key}: sayı olmalı (verilen: {v!r})")
    lo, hi = _RANGES.get(key, (-1e6, 1e6))
    if not (lo <= x <= hi):   # also rejects NaN and +-inf
        raise ValueError(f"{key}: {lo:g} ile {hi:g} arasında olmalı (verilen: {v!r})")
    return x


def _can_id(key: str, v: Any) -> int:
    try:
        x = int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{key}: CAN kimliği olmalı (ör. 0x180)")
    if isinstance(v, float) and v != x or not 0 <= x <= 0x7FF:
        raise ValueError(f"{key}: 0x000 ile 0x7FF arasında olmalı (verilen: {v!r})")
    return x


def validate_params(attack: "Attack", params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Coerce and range-check attack parameters against the attack's defaults. Raises ValueError (-> HTTP 400)."""
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params bir nesne olmalı")
    unknown = sorted(set(params) - set(attack.defaults))
    if unknown:
        raise ValueError(f"bilinmeyen parametre: {', '.join(unknown)} (izinli: {', '.join(attack.defaults)})")
    out = dict(attack.defaults)
    for k, v in params.items():
        if k in _ID_KEYS:
            out[k] = _can_id(k, v)
        elif k == "payload_hex":
            try:
                raw = bytes.fromhex(str(v).replace(" ", ""))
            except ValueError:
                raise ValueError("payload_hex: geçerli onaltılık bayt dizisi olmalı (ör. 00 10 5A)")
            if len(raw) > 8:
                raise ValueError("payload_hex: klasik CAN en çok 8 bayt taşır")
            out[k] = " ".join(f"{b:02X}" for b in raw)
        elif k == "ids":
            if not isinstance(v, (list, tuple)) or not v or len(v) > 32:
                raise ValueError("ids: 1-32 CAN kimliği içeren bir liste olmalı")
            out[k] = [_can_id("ids", x) for x in v]
        else:
            out[k] = _num(k, v)
    if "id_min" in out and "id_max" in out and out["id_min"] > out["id_max"]:
        raise ValueError("id_min, id_max'tan büyük olamaz")
    return out


class Attack:
    id = "base"
    name = ""
    description = ""
    category = ""
    defaults: Dict[str, Any] = {}
    expected_layers: Tuple[str, ...] = ()

    def __init__(self, bench, params: Optional[Dict[str, Any]], t0: float, duration: float):
        self.bench = bench
        self.params = validate_params(self, params)
        self.t0 = t0
        self.duration = duration
        self.injected = 0
        self._stopped = False
        self._acc = 0.0
        self._last_t = t0
        self._next = t0
        self.rng = random.Random(bench.seed * 7919 + zlib.crc32(self.id.encode()) % 1000)
        self.start()

    @property
    def source(self) -> str:
        return f"ATTACKER:{self.id}"

    def start(self) -> None:
        pass

    def observe(self, frame: CANFrame) -> None:
        pass

    def stop(self) -> None:
        pass

    def active(self, t: float) -> bool:
        return self.t0 <= t < self.t0 + self.duration

    def mk(self, arb_id: int, data: bytes, ready: float, **kw) -> Emit:
        return CANFrame(arb_id, data, len(data), timestamp=ready, source=self.source, **kw), ready

    def due_periodic(self, t: float, rate_hz: float) -> int:
        if not (rate_hz > 0):          # defensive: validate_params already guarantees this
            return 0
        n = 0
        while self._next <= t:
            n += 1
            self._next += 1.0 / rate_hz
        return n

    def tick(self, t: float) -> List[Emit]:
        return []

    def describe(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "category": self.category,
                "defaults": self.defaults, "expected_layers": list(self.expected_layers)}


class SpeedSpoof(Attack):
    id, name, category = "speed_spoof", "Speed spoofing (ID 0x244 jump)", "spoofing"
    description = "Attacker transmits forged vehicle-speed frames far above the true speed."
    defaults = {"offset_kmh": 110.0, "rate_hz": 20.0}
    expected_layers = ("CAN-IDS-03", "CAN-IDS-02")

    def tick(self, t):
        out = []
        for _ in range(self.due_periodic(t, self.params["rate_hz"])):
            abs_ecu = self.bench.ecus["ECU_Brake"]
            spd = min(300.0, self.bench.physics.speed_kmh + float(self.params["offset_kmh"]))
            out.append(self.mk(0x244, abs_ecu.build_speed_payload(spd), t))
        return out


class StealthSpeedSpoof(Attack):
    id, name, category = "speed_spoof_stealth", "Speed masquerade (ABS silenced + ramped fake)", "spoofing"
    description = ("Attacker silences the genuine 0x244 sender and takes over with a slowly drifting speed: "
                   "correct period, no jump. Per-frame layers see nothing; only physics-based analysis can.")
    defaults = {"ramp_kmh_per_s": 8.0, "max_offset_kmh": 45.0, "rate_hz": 20.0}
    expected_layers = ()

    def start(self):
        self.bench.ecus["ECU_Brake"].muted_ids.add(0x244)

    def stop(self):
        self.bench.ecus["ECU_Brake"].muted_ids.discard(0x244)

    def tick(self, t):
        out = []
        off = min(float(self.params["max_offset_kmh"]), (t - self.t0) * float(self.params["ramp_kmh_per_s"]))
        for _ in range(self.due_periodic(t, self.params["rate_hz"])):
            abs_ecu = self.bench.ecus["ECU_Brake"]
            out.append(self.mk(0x244, abs_ecu.build_speed_payload(self.bench.physics.speed_kmh + off), t))
        return out


class IdSpoof(Attack):
    id, name, category = "spoof_id", "Arbitrary CAN ID spoofing", "spoofing"
    description = "Transmits a chosen ID/payload at a chosen rate, impersonating its legitimate sender."
    defaults = {"target_id": 0x180, "payload_hex": "00 10 5A 00 00 00 00 00", "rate_hz": 50.0}
    expected_layers = ("CAN-IDS-02", "CAN-IDS-06")

    def tick(self, t):
        data = bytes.fromhex(str(self.params["payload_hex"]).replace(" ", ""))[:8]
        return [self.mk(int(self.params["target_id"]), data, t)
                for _ in range(self.due_periodic(t, self.params["rate_hz"]))]


class Replay(Attack):
    id, name, category = "replay", "Record & replay (0x180/0x200/0x244)", "replay"
    description = "Records legitimate frames for a while, then re-injects them with their original spacing."
    defaults = {"record_s": 1.5, "ids": [0x180, 0x200, 0x244]}
    expected_layers = ("CAN-IDS-04", "CAN-IDS-06", "CAN-IDS-02")

    def start(self):
        self.recorded: List[Tuple[float, CANFrame]] = []
        self._cursor = 0
        self._loop_t0: Optional[float] = None

    def observe(self, frame):
        t = frame.timestamp
        if (self.t0 <= t < self.t0 + float(self.params["record_s"]) and not frame.source.startswith("ATTACKER")
                and frame.arbitration_id in self.params["ids"]):
            self.recorded.append((t - self.t0, frame))

    def tick(self, t):
        rec_s = float(self.params["record_s"])
        if t < self.t0 + rec_s or not self.recorded:
            return []
        if self._loop_t0 is None:
            self._loop_t0 = t
            self._cursor = 0
        out = []
        rel = t - self._loop_t0
        while self._cursor < len(self.recorded) and self.recorded[self._cursor][0] <= rel:
            f = self.recorded[self._cursor][1]
            out.append(self.mk(f.arbitration_id, f.data, t))
            self._cursor += 1
        if self._cursor >= len(self.recorded):
            self._loop_t0, self._cursor = t, 0
        return out


class Flood(Attack):
    id, name, category = "flooding", "Flooding / DoS (ID 0x000)", "dos"
    description = "Highest-priority frames at full rate: wins every arbitration and starves legitimate ECUs."
    defaults = {"rate_fps": 4000, "arb_id": 0, "payload_hex": "AA BB CC DD EE FF 00 11"}
    expected_layers = ("CAN-IDS-05", "CAN-IDS-01", "CAN-IDS-02")

    def start(self):
        self.bench.bus.attach(self.source, mailbox_size=64)

    def tick(self, t):
        rate = min(6000.0, float(self.params["rate_fps"]))     # hard cap, simulation only
        self._acc += rate * (t - self._last_t)
        self._last_t = t
        n, self._acc = int(self._acc), self._acc - int(self._acc)
        data = bytes.fromhex(str(self.params["payload_hex"]).replace(" ", ""))[:8]
        return [self.mk(int(self.params["arb_id"]), data, t) for _ in range(n)]


class Fuzz(Attack):
    id, name, category = "fuzzing", "CAN fuzzing (random IDs/payloads)", "fuzzing"
    description = "Seeded pseudo-random identifiers and payloads to provoke unexpected ECU behaviour."
    defaults = {"rate_fps": 150, "id_min": 0, "id_max": 0x7FF}
    expected_layers = ("CAN-IDS-01",)

    def tick(self, t):
        out = []
        for _ in range(self.due_periodic(t, float(self.params["rate_fps"]))):
            n = self.rng.randint(0, 8)
            out.append(self.mk(self.rng.randint(int(self.params["id_min"]), int(self.params["id_max"])),
                               bytes(self.rng.randrange(256) for _ in range(n)), t))
        return out


class CounterCrcDesync(Attack):
    id, name, category = "counter_crc_desync", "Brake counter / CRC tampering (0x200)", "tampering"
    description = "Injects brake frames with a stale rolling counter and corrupted CRC-8."
    defaults = {"rate_hz": 50.0}
    expected_layers = ("CAN-IDS-04",)

    def tick(self, t):
        out = []
        for _ in range(self.due_periodic(t, self.params["rate_hz"])):
            b = self.bench.ecus["ECU_Brake"]
            out.append(self.mk(0x200, b.build_brake_payload(self.bench.physics.brake_bar, self.bench.physics.gear,
                                                           b.counter, crc=0xDE), t))
        return out


class UnauthorizedId(Attack):
    id, name, category = "unauthorized_id", "Foreign diagnostic ID (0x6F1)", "injection"
    description = "Frames with an identifier that is not in the vehicle's DBC."
    defaults = {"rate_hz": 20.0}
    expected_layers = ("CAN-IDS-01",)

    def tick(self, t):
        return [self.mk(0x6F1, b"\x02\x10\x03\0\0\0\0\0", t) for _ in range(self.due_periodic(t, self.params["rate_hz"]))]


class UdsDiagnosticAttack(Attack):
    id, name, category = "uds_diagnostic_attack", "UDS session + SecurityAccess brute force", "diagnostic"
    description = "Programming-session request on 0x7DF and repeated NRC 0x35 InvalidKey responses."
    defaults = {"rate_hz": 10.0}
    expected_layers = ("CAN-IDS-07",)

    def tick(self, t):
        out = []
        for _ in range(self.due_periodic(t, self.params["rate_hz"])):
            out.append(self.mk(0x7DF, b"\x02\x10\x02\0\0\0\0\0", t))
            out.append(self.mk(0x7E8, b"\x03\x7F\x27\x35\0\0\0\0", t))
        return out


class UdsReflash(Attack):
    id, name, category = "uds_reflash", "Multi-frame UDS 0x34 firmware reflash", "diagnostic"
    description = "ISO-TP segmented RequestDownload (First Frame + Consecutive Frames) on 0x7E0 — invisible to single-frame inspection."
    defaults = {"period_s": 1.0, "arb_id": 0x7E0}
    expected_layers = ("CAN-IDS-07",)

    def tick(self, t):
        if t < self._next:
            return []
        self._next = t + float(self.params["period_s"])
        a = int(self.params["arb_id"])
        base = t
        return [self.mk(a, bytes([0x10, 0x0F, 0x34, 0x00, 0x44, 0x00, 0x10, 0x00]), base),
                self.mk(a, bytes([0x21, 0x00, 0x00, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC]), base + 0.001),
                self.mk(a, bytes([0x22, 0xDD, 0xEE, 0, 0, 0, 0, 0]), base + 0.002)]


class DoorUnlock(Attack):
    id, name, category = "headlight_can_injection_unlock", "Body-bus injection: door unlock (0x320)", "injection"
    description = "Extra Body_Status frames reporting doors unlocked."
    defaults = {"rate_hz": 10.0}
    expected_layers = ("CAN-IDS-02",)

    def tick(self, t):
        return [self.mk(0x320, b"\0\0\0\0", t) for _ in range(self.due_periodic(t, self.params["rate_hz"]))]


class BrakePressureSpoof(Attack):
    id, name, category = "brake_spoof", "Forged brake pressure + zero throttle", "spoofing"
    description = "Valid-CRC brake frames (80 bar) and throttle=0 engine frames while the car accelerates: looks fine per frame, physically impossible."
    defaults = {"bar": 80.0, "rate_hz": 100.0}
    expected_layers = ("CAN-IDS-04", "CAN-IDS-02")

    def tick(self, t):
        out = []
        for _ in range(self.due_periodic(t, self.params["rate_hz"])):
            b = self.bench.ecus["ECU_Brake"]
            p = self.bench.physics
            out.append(self.mk(0x200, b.build_brake_payload(float(self.params["bar"]), p.gear, (b.counter + 1) % 16), t))
            eng = struct.pack("<HBB4s", int(p.rpm / 0.25) & 0xFFFF, int(p.engine_temp + 40) & 0xFF, 0, b"\0\0\0\0")
            out.append(self.mk(0x180, eng, t))
        return out


ATTACKS = {c.id: c for c in (SpeedSpoof, StealthSpeedSpoof, IdSpoof, Replay, Flood, Fuzz, CounterCrcDesync,
                             UnauthorizedId, UdsDiagnosticAttack, UdsReflash, DoorUnlock, BrakePressureSpoof)}
