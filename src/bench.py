"""Virtual automotive test bench: ECUs + coupled dynamics + arbitrated bus + attack lab + detectors.

`VirtualTestBench.advance(dt)` moves virtual time forward in 1 ms ticks. Everything is in memory and
deterministic for a given seed (apart from wall-clock timings measured by the benchmark).
"""
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.attacks import ATTACKS, Attack
from src.behavior import VehicleBehaviorAnalyzer
from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder
from src.ecus import ECU, build_ecus
from src.sim_bus import Delivered, SimBus
from src.vehicle_dynamics import DriverInputs, VehiclePhysics

TICK = 0.001
PHYS_DT = 0.005
ALERT_WINDOW_AFTER = 1.0

# legacy scenario names accepted by /api/scenarios/start
SCENARIO_ALIASES = {"unauthorized_uds": "unauthorized_id"}


@dataclass
class Record:
    d: Delivered
    attack: bool
    ids_alerts: list = field(default_factory=list)
    vba_alerts: list = field(default_factory=list)


class VirtualTestBench:
    def __init__(self, dbc: DBCDecoder, ids=None, behavior: Optional[VehicleBehaviorAnalyzer] = None,
                 seed: int = 1, bitrate_bps: int = 500_000):
        self.dbc, self.ids, self.behavior, self.seed = dbc, ids, behavior, seed
        self.bitrate = bitrate_bps
        self.reset(seed)

    def reset(self, seed: Optional[int] = None) -> None:
        self.seed = self.seed if seed is None else seed
        self.rng = random.Random(self.seed)
        self.t = 0.0
        self._phys_acc = 0.0
        self.physics = VehiclePhysics()
        self.bus = SimBus(self.bitrate)
        self.ecus: Dict[str, ECU] = build_ecus(self.physics, self.rng)
        for e in self.ecus.values():
            self.bus.attach(e.name, e.mailbox)
        self.attacks: Dict[str, Attack] = {}
        self.finished: List[Dict[str, Any]] = []
        self.external_node = "TESTER"
        self.bus.attach(self.external_node, 64)
        if self.ids is not None and hasattr(self.ids, "reset_state"):
            self.ids.reset_state()
        if self.behavior is not None:
            self.behavior.reset()

    def set_driver(self, **kw) -> DriverInputs:
        inp = self.physics.inputs
        for k, v in kw.items():
            if v is not None and hasattr(inp, k):
                setattr(inp, k, v)
        if "target_speed_kmh" in kw and kw["target_speed_kmh"] is not None:
            self.physics.cycle_enabled = False
        if kw.get("mode") == "auto" and kw.get("target_speed_kmh") is None:
            self.physics.cycle_enabled = True
        return inp

    def start_attack(self, attack_id: str, params: Optional[Dict[str, Any]] = None, duration: float = 6.0,
                     replace: bool = True) -> Attack:
        attack_id = SCENARIO_ALIASES.get(attack_id, attack_id)
        if attack_id not in ATTACKS:
            raise KeyError(attack_id)
        if replace:
            self.stop_attacks()
        duration = max(0.2, min(120.0, float(duration)))
        atk = ATTACKS[attack_id](self, params, self.t, duration)
        atk._snap = {"dropped": self._legit_dropped(), "peak": self.bus.peak_load_pct}
        atk.first_alert_t = None
        atk.alerts_by_rule = {}
        atk.max_cluster_err = 0.0
        atk.legit_max_latency_ms = 0.0
        atk.peak_load = 0.0
        self.bus.attach(atk.source, 64)
        self.attacks[atk.id] = atk
        return atk

    def stop_attacks(self) -> None:
        for a in list(self.attacks.values()):
            self._finish(a)
        self.attacks.clear()

    def _legit_dropped(self) -> int:
        return int(sum(s["dropped"] for n, s in self.bus.node_stats.items() if n.startswith("ECU_")))

    def _finish(self, atk: Attack) -> None:
        if not atk._stopped:
            atk._stopped = True
            atk.stop()
        self.finished.append(self.attack_summary(atk, ended=True))
        del self.finished[:-10]
        self.bus.detach(atk.source)

    def inject(self, frame: CANFrame, ready_t: Optional[float] = None) -> bool:
        frame.source = frame.source or self.external_node
        return self.bus.enqueue(self.external_node, frame, self.t if ready_t is None else ready_t)

    def advance(self, dt: float) -> List[Record]:
        end = self.t + dt
        out: List[Record] = []
        while self.t < end - 1e-12:
            nt = min(self.t + TICK, end)
            self._phys_acc += nt - self.t
            while self._phys_acc >= PHYS_DT - 1e-12:
                self.physics.step(PHYS_DT)
                self._phys_acc -= PHYS_DT
            for e in self.ecus.values():
                for f in e.tick(nt):
                    self.bus.enqueue(e.name, f, nt)
            for a in list(self.attacks.values()):
                if a.active(nt):
                    for f, ready in a.tick(nt):
                        if self.bus.enqueue(a.source, f, ready):
                            a.injected += 1
                else:
                    if not a._stopped:
                        a._stopped = True
                        a.stop()
                if nt >= a.t0 + a.duration + ALERT_WINDOW_AFTER:
                    self._finish(a)
                    del self.attacks[a.id]
            for d in self.bus.advance(nt):
                out.append(self._process(d))
            self.t = nt
        return out

    def _process(self, d: Delivered) -> Record:
        f = d.frame
        is_attack = f.source.startswith("ATTACKER")
        for e in self.ecus.values():
            e.on_rx(f)
        for a in self.attacks.values():
            a.observe(f)
        rec = Record(d, is_attack)
        decoded = self.dbc.decode_frame(f)
        if self.ids is not None:
            rec.ids_alerts = self.ids.process_frame(f, d.bus_load_pct)
        if self.behavior is not None:
            rec.vba_alerts = self.behavior.update(decoded, f.timestamp)
        n_alerts = len(rec.ids_alerts) + len(rec.vba_alerts)
        for a in self.attacks.values():
            if f.timestamp >= a.t0:
                a.max_cluster_err = max(a.max_cluster_err, abs(self.ecus["ECU_Cluster"].displayed_speed - self.physics.speed_kmh))
                a.peak_load = max(a.peak_load, d.bus_load_pct)
                if f.source.startswith("ECU_"):
                    a.legit_max_latency_ms = max(a.legit_max_latency_ms, d.latency_s * 1000)
                if n_alerts and f.timestamp <= a.t0 + a.duration + ALERT_WINDOW_AFTER:
                    if a.first_alert_t is None:
                        a.first_alert_t = f.timestamp
                    for x in rec.ids_alerts:
                        a.alerts_by_rule[x.rule_id] = a.alerts_by_rule.get(x.rule_id, 0) + 1
                    for x in rec.vba_alerts:
                        a.alerts_by_rule[x["rule_id"]] = a.alerts_by_rule.get(x["rule_id"], 0) + 1
        return rec

    def attack_summary(self, a: Attack, ended: bool = False) -> Dict[str, Any]:
        return {
            "id": a.id, "name": a.name, "started_at": round(a.t0, 3), "duration_s": a.duration,
            "elapsed_s": round(max(0.0, min(self.t - a.t0, a.duration)), 3), "ended": ended or not a.active(self.t),
            "injected_frames": a.injected, "params": {k: v for k, v in a.params.items()},
            "detected": a.first_alert_t is not None,
            "detection_delay_ms": None if a.first_alert_t is None else round((a.first_alert_t - a.t0) * 1000, 1),
            "alerts_by_rule": dict(a.alerts_by_rule),
            "expected_layers": list(a.expected_layers),
            "effects": {
                "max_cluster_speed_error_kmh": round(a.max_cluster_err, 1),
                "legit_frames_dropped": self._legit_dropped() - a._snap["dropped"],
                "legit_max_queue_latency_ms": round(a.legit_max_latency_ms, 2),
                "peak_bus_load_pct": round(a.peak_load, 1),
            },
        }

    def status(self) -> Dict[str, Any]:
        return {"active": [self.attack_summary(a) for a in self.attacks.values()], "recent": list(self.finished[-5:])}

    def telemetry(self) -> Dict[str, Any]:
        p = self.physics
        c = self.ecus["ECU_Cluster"]
        return {**p.snapshot(), "cluster_speed_kmh": round(c.displayed_speed, 1), "lamps": c.lamps(),
                "driver": {"mode": p.inputs.mode, "target_speed_kmh": p.inputs.target_speed_kmh,
                           "cycle": p.cycle_enabled}}

    def ecu_info(self) -> List[Dict[str, Any]]:
        out = []
        for e in self.ecus.values():
            i = e.info()
            i.update(self.bus.node_stats.get(e.name, {}))
            out.append(i)
        return out
