"""Coupled longitudinal vehicle dynamics for the virtual ECUs (simulation model, not a calibrated vehicle).

Engine torque -> gearbox ratio x final drive -> wheel force -> acceleration; the engine speed is
*derived from road speed and the engaged gear* (rpm = f(speed, gear)), so speed, rpm and gear are
physically coupled. Brake pressure, drag and engine braking decelerate the car; engine temperature
follows load.
"""
import math
from dataclasses import dataclass
from typing import Dict, List, Tuple

GEAR_RATIOS: Dict[int, float] = {1: 3.6, 2: 2.2, 3: 1.5, 4: 1.1, 5: 0.9, 6: 0.75}
FINAL_DRIVE = 3.7
WHEEL_RADIUS_M = 0.31
IDLE_RPM = 850.0
REDLINE_RPM = 6800.0
MASS_KG = 1450.0 * 1.05          # incl. rotating inertia
T_MAX_NM = 160.0
BRAKE_N_PER_BAR = 75.0
MAX_BRAKE_BAR = 120.0


def rpm_from_speed_gear(speed_kmh: float, gear: int) -> float:
    """Engine speed implied by road speed and gear when the clutch is locked."""
    if gear not in GEAR_RATIOS:
        return 0.0
    wheel_rps = (speed_kmh / 3.6) / (2 * math.pi * WHEEL_RADIUS_M)
    return wheel_rps * 60.0 * GEAR_RATIOS[gear] * FINAL_DRIVE


def speed_from_rpm_gear(rpm: float, gear: int) -> float:
    """Road speed (km/h) implied by engine speed and gear."""
    if gear not in GEAR_RATIOS:
        return 0.0
    wheel_rps = rpm / 60.0 / (GEAR_RATIOS[gear] * FINAL_DRIVE)
    return wheel_rps * 2 * math.pi * WHEEL_RADIUS_M * 3.6


def engine_torque(rpm: float, throttle_pct: float) -> float:
    curve = max(0.3, 1.0 - ((rpm - 3800.0) / 4200.0) ** 2)
    pos = T_MAX_NM * (throttle_pct / 100.0) * curve
    engine_brake = -28.0 * (rpm / 3000.0) * (1.0 - throttle_pct / 100.0)
    return pos + engine_brake


@dataclass
class DriverInputs:
    mode: str = "auto"               # auto (driving cycle / cruise) | manual
    target_speed_kmh: float = 60.0
    throttle_pct: float = 0.0        # manual
    brake_pct: float = 0.0           # manual, 0..100 of MAX_BRAKE_BAR
    steering_deg: float = 0.0        # manual


# (hold seconds, target km/h) — repeating urban/highway style cycle for the auto driver
DRIVING_CYCLE: List[Tuple[float, float]] = [(14.0, 60.0), (14.0, 90.0), (10.0, 40.0), (12.0, 70.0), (8.0, 0.0)]


class VehiclePhysics:
    def __init__(self):
        self.speed_kmh = 0.0
        self.accel_ms2 = 0.0
        self.rpm = IDLE_RPM
        self.gear = 1
        self.shifting = False
        self.shift_target = 1
        self._shift_timer = 0.0
        self._since_shift = 10.0
        self.throttle_pct = 0.0
        self.brake_bar = 0.0
        self.steering_deg = 0.0
        self.steering_rate = 0.0
        self.engine_temp = 88.0
        self.trans_temp = 70.0
        self.odometer_km = 12450.0
        self.torque_nm = 0.0
        self.inputs = DriverInputs()
        self.cycle_enabled = True
        self._cycle_t = 0.0
        self._integ = 0.0
        self._t = 0.0

    def _driver(self, dt: float):
        inp = self.inputs
        if inp.mode == "manual":
            return inp.throttle_pct, inp.brake_pct / 100.0 * MAX_BRAKE_BAR, inp.steering_deg
        target = inp.target_speed_kmh
        if self.cycle_enabled:
            self._cycle_t += dt
            total = sum(h for h, _ in DRIVING_CYCLE)
            ph = self._cycle_t % total
            for hold, tgt in DRIVING_CYCLE:
                if ph < hold:
                    target = tgt
                    break
                ph -= hold
        err = target - self.speed_kmh
        brake = 0.0
        if err < -3.0:
            throttle, self._integ = 0.0, 0.0
            brake = min(45.0, (-err - 3.0) * 2.2 + 6.0)
        else:
            self._integ = max(0.0, min(40.0, self._integ + err * dt * 1.2))
            throttle = max(0.0, min(100.0, 5.0 + 5.0 * err + self._integ)) if err > -1.0 else 0.0
        if target == 0.0 and self.speed_kmh < 1.0:
            throttle, brake = 0.0, 8.0
        steer = 0.0
        if self.speed_kmh > 5.0:
            steer = 18.0 * math.sin(self._t / 9.0 * 2 * math.pi) * min(1.0, self.speed_kmh / 40.0)
        return throttle, brake, steer

    def _transmission(self, dt: float):
        self._since_shift += dt
        if self.shifting:
            self._shift_timer -= dt
            if self._shift_timer <= 0:
                self.gear, self.shifting, self._since_shift = self.shift_target, False, 0.0
            return
        rpm_locked = rpm_from_speed_gear(self.speed_kmh, self.gear)
        up_rpm = 2600.0 + 2400.0 * (self.throttle_pct / 100.0)
        if self.gear < 6 and rpm_locked > up_rpm and self._since_shift > 0.8:
            self.shifting, self.shift_target, self._shift_timer = True, self.gear + 1, 0.35
        elif self.gear > 1 and rpm_locked < 1250.0 and self._since_shift > 0.8:
            self.shifting, self.shift_target, self._shift_timer = True, self.gear - 1, 0.25

    def step(self, dt: float) -> None:
        self._t += dt
        thr_cmd, brake_cmd, steer_cmd = self._driver(dt)
        # actuator lags
        self.throttle_pct += max(-90 * dt, min(90 * dt, thr_cmd - self.throttle_pct))
        self.brake_bar += (brake_cmd - self.brake_bar) * min(1.0, dt * 10.0)
        if self.brake_bar < 0.05:
            self.brake_bar = 0.0
        prev_steer = self.steering_deg
        self.steering_deg += (steer_cmd - self.steering_deg) * min(1.0, dt * 6.0)
        self.steering_rate = (self.steering_deg - prev_steer) / dt if dt > 0 else 0.0

        self._transmission(dt)

        v = self.speed_kmh / 3.6
        locked = rpm_from_speed_gear(self.speed_kmh, self.gear)
        slip = self.speed_kmh < 4.0
        target_rpm = (IDLE_RPM + 3000.0 * self.throttle_pct / 100.0) if slip else max(locked, IDLE_RPM)
        self.rpm += (target_rpm - self.rpm) * min(1.0, dt * 8.0)
        self.rpm = max(IDLE_RPM * 0.95, min(REDLINE_RPM, self.rpm))

        self.torque_nm = 0.0 if self.shifting else engine_torque(self.rpm, self.throttle_pct)
        ratio = GEAR_RATIOS[self.gear] * FINAL_DRIVE
        f_drive = self.torque_nm * ratio * 0.9 / WHEEL_RADIUS_M * (0.85 if slip else 1.0)
        f_res = 170.0 + 0.4 * v * v
        f_brake = self.brake_bar * BRAKE_N_PER_BAR
        net = f_drive - f_brake - (f_res if v > 0.05 else 0.0)
        if v <= 0.05 and net < 0:
            net = 0.0
        self.accel_ms2 = net / MASS_KG
        v = max(0.0, v + self.accel_ms2 * dt)
        self.speed_kmh = min(230.0, v * 3.6)
        self.odometer_km += self.speed_kmh / 3600.0 * dt

        load = max(0.0, self.torque_nm) / T_MAX_NM * min(1.0, self.rpm / 4500.0)
        t_target = max(78.0, 84.0 + 28.0 * load - 0.03 * self.speed_kmh)
        self.engine_temp += (t_target - self.engine_temp) * dt / 25.0
        self.trans_temp += ((68.0 + 22.0 * load) - self.trans_temp) * dt / 60.0

    def snapshot(self) -> Dict[str, float]:
        return {
            "speed_kmh": round(self.speed_kmh, 2), "rpm": round(self.rpm, 1), "gear": self.gear,
            "throttle_pct": round(self.throttle_pct, 1), "brake_bar": round(self.brake_bar, 2),
            "steering_deg": round(self.steering_deg, 2), "engine_temp": round(self.engine_temp, 2),
            "trans_temp": round(self.trans_temp, 2), "odometer_km": round(self.odometer_km, 3),
            "accel_ms2": round(self.accel_ms2, 3), "shifting": self.shifting,
        }
