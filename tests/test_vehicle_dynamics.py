import pytest
from src.vehicle_dynamics import (VehiclePhysics, rpm_from_speed_gear, speed_from_rpm_gear, DriverInputs, IDLE_RPM)


def run(p, secs, dt=0.005):
    for _ in range(int(secs / dt)):
        p.step(dt)


def test_speed_rpm_gear_are_inverse_and_monotonic():
    for g in range(1, 7):
        for v in (20.0, 60.0, 110.0):
            assert speed_from_rpm_gear(rpm_from_speed_gear(v, g), g) == pytest.approx(v, rel=1e-6)
    assert rpm_from_speed_gear(60, 1) > rpm_from_speed_gear(60, 3) > rpm_from_speed_gear(60, 6)


def test_engine_rpm_follows_road_speed_and_gear_when_driving():
    p = VehiclePhysics()
    p.cycle_enabled = False
    p.inputs = DriverInputs(mode="auto", target_speed_kmh=80)
    run(p, 40)
    assert p.speed_kmh == pytest.approx(80, abs=4)
    # coupling: the implied speed from (rpm, gear) matches the road speed
    assert speed_from_rpm_gear(p.rpm, p.gear) == pytest.approx(p.speed_kmh, rel=0.06)
    assert p.gear >= 4


def test_gears_shift_up_while_accelerating():
    p = VehiclePhysics()
    p.inputs = DriverInputs(mode="manual", throttle_pct=70)
    seen = set()
    for _ in range(int(25 / 0.005)):
        p.step(0.005)
        seen.add(p.gear)
    assert {1, 2, 3}.issubset(seen) and p.speed_kmh > 60


def test_braking_decelerates_and_zero_throttle_without_brake_coasts_down():
    p = VehiclePhysics()
    p.inputs = DriverInputs(mode="manual", throttle_pct=60)
    run(p, 15)
    v0 = p.speed_kmh
    p.inputs = DriverInputs(mode="manual", throttle_pct=0, brake_pct=40)
    run(p, 3)
    assert p.speed_kmh < v0 - 10 and p.accel_ms2 < 0
    p2 = VehiclePhysics()
    p2.inputs = DriverInputs(mode="manual", throttle_pct=60)
    run(p2, 15)
    p2.inputs = DriverInputs(mode="manual", throttle_pct=0, brake_pct=0)
    run(p2, 3)
    assert p2.accel_ms2 < 0 and p2.speed_kmh > p.speed_kmh   # coasting decelerates less than braking


def test_engine_warms_under_load_and_stays_bounded():
    p = VehiclePhysics()
    p.inputs = DriverInputs(mode="manual", throttle_pct=100)
    t0 = p.engine_temp
    run(p, 60)
    assert p.engine_temp > t0 + 3 and p.engine_temp < 125


def test_idle_and_standstill():
    p = VehiclePhysics()
    p.inputs = DriverInputs(mode="manual")
    run(p, 3)
    assert p.speed_kmh == 0 and p.rpm == pytest.approx(IDLE_RPM, abs=60)


def test_default_cycle_stays_physically_plausible():
    p = VehiclePhysics()
    mx_acc = mx_dec = 0
    for _ in range(int(80 / 0.005)):
        p.step(0.005)
        mx_acc, mx_dec = max(mx_acc, p.accel_ms2), min(mx_dec, p.accel_ms2)
        assert p.rpm <= 6800 and 0 <= p.speed_kmh <= 230
    assert mx_acc < 5.5 and mx_dec > -4.5 and p.odometer_km > 12450
