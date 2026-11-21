import struct
from src.behavior import VehicleBehaviorAnalyzer
from src.vehicle_dynamics import rpm_from_speed_gear


def dec(**sigs):
    return {"decoded": True, "signals": {k: {"value": v, "valid": True} for k, v in sigs.items()}}


def feed(a, seconds, fn, dt=0.02, t0=0.0):
    out = []
    t = t0
    while t < t0 + seconds:
        for d in fn(t - t0):
            out += a.update(d, t)
        t += dt
    return out


def test_speed_rising_with_brake_and_zero_throttle_is_flagged():
    a = VehicleBehaviorAnalyzer()
    out = feed(a, 3.0, lambda t: [dec(speed_kmh=30 + 8 * t), dec(brake_pressure_bar=70.0), dec(throttle_pct=0.0)])
    assert any(x["rule_id"] == "VBA-01" for x in out)


def test_normal_acceleration_and_normal_braking_are_not_flagged():
    a = VehicleBehaviorAnalyzer()
    acc = feed(a, 4.0, lambda t: [dec(speed_kmh=30 + 8 * t), dec(brake_pressure_bar=0.0), dec(throttle_pct=45.0)])
    brk = feed(a, 4.0, lambda t: [dec(speed_kmh=62 - 8 * t), dec(brake_pressure_bar=40.0), dec(throttle_pct=0.0)], t0=4.0)
    assert [x for x in acc + brk if x["rule_id"] in ("VBA-01", "VBA-03")] == []


def test_speed_rpm_gear_mismatch_flagged_but_consistent_is_not():
    bad = VehicleBehaviorAnalyzer()
    out = feed(bad, 4.0, lambda t: [dec(speed_kmh=140.0, rpm=rpm_from_speed_gear(60, 3), gear_actual=3)])
    assert any(x["rule_id"] == "VBA-02" for x in out)
    ok = VehicleBehaviorAnalyzer()
    out = feed(ok, 4.0, lambda t: [dec(speed_kmh=60.0, rpm=rpm_from_speed_gear(60, 3), gear_actual=3)])
    assert out == []


def test_brake_without_deceleration_and_cluster_mismatch_and_steering_and_temp():
    a = VehicleBehaviorAnalyzer()
    out = feed(a, 3.0, lambda t: [dec(speed_kmh=80.0, brake_pressure_bar=60.0)])
    assert any(x["rule_id"] == "VBA-03" for x in out)
    a = VehicleBehaviorAnalyzer()
    out = feed(a, 3.0, lambda t: [dec(speed_kmh=40.0, displayed_speed=150.0)])
    assert any(x["rule_id"] == "VBA-05" for x in out)
    a = VehicleBehaviorAnalyzer()
    assert a.update(dec(steering_angle_deg=0.0), 1.000) == []
    assert any(x["rule_id"] == "VBA-04" for x in a.update(dec(steering_angle_deg=300.0), 1.010))
    a = VehicleBehaviorAnalyzer()
    out = feed(a, 1.0, lambda t: [dec(engine_temp=85 + 20 * t)])
    assert any(x["rule_id"] == "VBA-06" for x in out)


def test_alert_cooldown_prevents_flood():
    a = VehicleBehaviorAnalyzer(cooldown_s=2.0)
    out = feed(a, 6.0, lambda t: [dec(speed_kmh=30 + 8 * t, brake_pressure_bar=70.0, throttle_pct=0.0)])
    n = len([x for x in out if x["rule_id"] == "VBA-01"])
    assert 1 <= n <= 3
