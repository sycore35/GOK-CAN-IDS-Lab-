"""Vehicle Behaviour Analysis: flags *physically inconsistent* signal combinations.

Unlike the per-frame IDS layers, this looks at what the decoded signals mean together
(speed vs. rpm vs. gear vs. brake vs. throttle ...). A forged frame can have a perfect CRC and counter
and still describe a car that cannot exist. Rules keep a sliding evidence window to tolerate the
interleaving of forged and genuine frames.
"""
import collections
from typing import Any, Deque, Dict, List, Optional, Tuple

from src.vehicle_dynamics import speed_from_rpm_gear


class _Window:
    """Fraction of True evaluations over the last `hold_s` seconds, requiring the span to be covered."""

    def __init__(self, hold_s: float, fraction: float = 0.6):
        self.hold, self.fraction = hold_s, fraction
        self.samples: Deque[Tuple[float, bool]] = collections.deque()

    def add(self, t: float, v: bool) -> bool:
        self.samples.append((t, v))
        while self.samples and self.samples[0][0] < t - self.hold:
            self.samples.popleft()
        if not self.samples or t - self.samples[0][0] < self.hold * 0.9:
            return False
        return sum(1 for _, x in self.samples if x) / len(self.samples) >= self.fraction

    def reset(self):
        self.samples.clear()


RULES = {
    "VBA-01": ("Acceleration with brake applied and zero throttle", "HIGH"),
    "VBA-02": ("Speed inconsistent with engine RPM and gear", "HIGH"),
    "VBA-03": ("Brake pressure without deceleration", "MEDIUM"),
    "VBA-04": ("Implausible steering rate", "MEDIUM"),
    "VBA-05": ("Cluster speed differs from wheel speed", "MEDIUM"),
    "VBA-06": ("Engine temperature jump", "MEDIUM"),
}


class VehicleBehaviorAnalyzer:
    def __init__(self, eval_interval_s: float = 0.05, cooldown_s: float = 2.0):
        self.eval_interval = eval_interval_s
        self.cooldown = cooldown_s
        self.sig: Dict[str, Tuple[float, float]] = {}
        self.speed_hist: Deque[Tuple[float, float]] = collections.deque(maxlen=400)
        self.temp_hist: Deque[Tuple[float, float]] = collections.deque(maxlen=200)
        self.win = {"VBA-01": _Window(0.6), "VBA-02": _Window(1.2), "VBA-03": _Window(1.5),
                    "VBA-05": _Window(1.0)}
        self.last_fire: Dict[str, float] = {}
        self.last_eval = -1.0
        self.last_gear_change = -10.0
        self._gear = None
        self.alerts: Deque[Dict[str, Any]] = collections.deque(maxlen=300)
        self.hits: Dict[str, int] = collections.defaultdict(int)
        self._prev_steer: Optional[Tuple[float, float]] = None

    def update(self, decoded: Dict[str, Any], ts: float) -> List[Dict[str, Any]]:
        """Feed one decoded frame (DBCDecoder.decode_frame output). Returns newly raised alerts."""
        out: List[Dict[str, Any]] = []
        if not decoded.get("decoded"):
            return out
        for name, s in decoded["signals"].items():
            if not s.get("valid"):
                continue
            self.sig[name] = (float(s["value"]), ts)
        if "speed_kmh" in decoded["signals"] and decoded["signals"]["speed_kmh"].get("valid"):
            self.speed_hist.append((ts, float(decoded["signals"]["speed_kmh"]["value"])))
        if "engine_temp" in decoded["signals"]:
            self.temp_hist.append((ts, float(decoded["signals"]["engine_temp"]["value"])))
        if "gear_actual" in decoded["signals"]:
            g = int(decoded["signals"]["gear_actual"]["value"])
            if g != self._gear:
                self._gear, self.last_gear_change = g, ts
        if "steering_angle_deg" in decoded["signals"]:
            ang = float(decoded["signals"]["steering_angle_deg"]["value"])
            if self._prev_steer and ts - self._prev_steer[0] > 0.004:
                rate = abs(ang - self._prev_steer[1]) / (ts - self._prev_steer[0])
                if rate > 900.0:
                    out += self._fire("VBA-04", ts, f"{rate:.0f} deg/s", "<= 900 deg/s",
                                      f"Steering angle changed {self._prev_steer[1]:.1f} -> {ang:.1f} deg in {1000*(ts-self._prev_steer[0]):.1f} ms.")
            self._prev_steer = (ts, ang)
        if ts - self.last_eval >= self.eval_interval:
            self.last_eval = ts
            out += self._evaluate(ts)
        return out

    def _val(self, name: str, ts: float, max_age: float = 0.5) -> Optional[float]:
        v = self.sig.get(name)
        return v[0] if v and ts - v[1] <= max_age else None

    def _slope(self, hist: Deque[Tuple[float, float]], ts: float, span: float = 0.8) -> Optional[float]:
        pts = [(t, v) for t, v in hist if t >= ts - span]
        if len(pts) < 4 or pts[-1][0] - pts[0][0] < span * 0.6:
            return None
        # least-squares slope is robust to interleaved forged/genuine samples
        n = len(pts)
        mt = sum(t for t, _ in pts) / n
        mv = sum(v for _, v in pts) / n
        den = sum((t - mt) ** 2 for t, _ in pts)
        return sum((t - mt) * (v - mv) for t, v in pts) / den if den else None

    def _evaluate(self, ts: float) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        speed = self._val("speed_kmh", ts)
        brake = self._val("brake_pressure_bar", ts)
        thr = self._val("throttle_pct", ts)
        rpm = self._val("rpm", ts)
        gear = self._val("gear_actual", ts, 0.5)
        slope = self._slope(self.speed_hist, ts)

        if None not in (brake, thr, slope):
            cond = brake > 10.0 and thr <= 2.0 and slope > 3.0
            if self.win["VBA-01"].add(ts, cond):
                out += self._fire("VBA-01", ts, f"brake={brake:.0f} bar, throttle={thr:.0f}%, dv/dt=+{slope:.1f} km/h/s",
                                  "speed must not rise while braking with zero throttle",
                                  "Reported brake pressure and throttle contradict the reported acceleration: at least one signal is forged or a sensor is faulty.")
        if None not in (speed, rpm, gear) and 1 <= gear <= 6:
            expected = speed_from_rpm_gear(rpm, int(gear))
            settled = ts - self.last_gear_change > 1.5
            cond = settled and speed > 15.0 and abs(speed - expected) > 0.35 * max(speed, expected)
            if self.win["VBA-02"].add(ts, cond):
                out += self._fire("VBA-02", ts, f"speed={speed:.0f} km/h vs {expected:.0f} km/h implied by rpm={rpm:.0f}, gear {int(gear)}",
                                  "within 35% of rpm/gear-implied speed",
                                  "Wheel speed does not match engine speed through the engaged gear ratio; speed signal likely spoofed.")
        if None not in (brake, speed, slope):
            cond = brake > 30.0 and speed > 20.0 and slope > -0.5
            if self.win["VBA-03"].add(ts, cond):
                out += self._fire("VBA-03", ts, f"brake={brake:.0f} bar with dv/dt={slope:+.1f} km/h/s",
                                  "deceleration while braking hard",
                                  "High brake pressure reported but the vehicle is not slowing down.")
        disp = self._val("displayed_speed", ts, 1.0)
        if None not in (speed, disp):
            cond = abs(disp - speed) > max(8.0, 0.10 * speed)
            if self.win["VBA-05"].add(ts, cond):
                out += self._fire("VBA-05", ts, f"cluster={disp:.0f} vs wheel={speed:.0f} km/h", "within 10%",
                                  "Instrument cluster is showing a different speed than the wheel-speed signal.")
        pts = [(t, v) for t, v in self.temp_hist if t >= ts - 1.0]
        if len(pts) >= 3 and max(v for _, v in pts) - min(v for _, v in pts) > 8.0:
            out += self._fire("VBA-06", ts, f"{max(v for _, v in pts) - min(v for _, v in pts):.0f} C in 1 s",
                              "< 8 C per second", "Coolant temperature cannot change this fast physically.")
        return out

    def _fire(self, rule: str, ts: float, observed: str, expected: str, evidence: str) -> List[Dict[str, Any]]:
        if ts - self.last_fire.get(rule, -1e9) < self.cooldown:
            return []
        self.last_fire[rule] = ts
        name, sev = RULES[rule]
        a = {"timestamp": round(ts, 4), "rule_id": rule, "rule_name": name, "severity": sev,
             "observed_value": observed, "expected_threshold": expected, "evidence": evidence}
        self.alerts.append(a)
        self.hits[rule] += 1
        return [a]

    def reset(self) -> None:
        self.__init__(self.eval_interval, self.cooldown)

    def summary(self) -> Dict[str, Any]:
        return {"total_alerts": len(self.alerts), "rule_hits": dict(self.hits),
                "rules": {k: {"name": v[0], "severity": v[1]} for k, v in RULES.items()}}
