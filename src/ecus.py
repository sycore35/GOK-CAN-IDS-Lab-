"""Virtual ECUs attached to the simulated bus. Each ECU owns periodic messages, reads the shared
vehicle physics for its sensors, and may react to frames it receives (cluster displays what the bus says)."""
import random
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from src.can_frame import CANFrame
from src.dbc_decoder import calc_crc8_sae_j1850
from src.can_ids import SECOC_KEY_0C4, compute_secoc_mac
from src.vehicle_dynamics import VehiclePhysics


@dataclass
class TxSpec:
    arb_id: int
    period_s: float
    build: Callable[[], bytes]
    name: str
    next_due: float = 0.0


class ECU:
    description = ""

    def __init__(self, name: str, physics: VehiclePhysics, rng: random.Random, mailbox: int = 8):
        self.name = name
        self.physics = physics
        self.rng = rng
        self.mailbox = mailbox
        self.online = True
        self.muted_ids = set()   # message IDs this ECU no longer sends (e.g. silenced by an attacker)
        self.tx_count = 0
        self.rx_count = 0
        self.specs: List[TxSpec] = []

    def tick(self, t: float) -> List[CANFrame]:
        if not self.online:
            return []
        out = []
        for s in self.specs:
            if s.arb_id in self.muted_ids:
                continue
            if t >= s.next_due:
                data = s.build()
                out.append(CANFrame(s.arb_id, data, len(data), timestamp=t, source=self.name))
                self.tx_count += 1
                jitter = 1.0 + self.rng.uniform(-0.004, 0.004)
                s.next_due = max(s.next_due + s.period_s * jitter, t + s.period_s * 0.5)
        return out

    def on_rx(self, frame: CANFrame) -> None:
        self.rx_count += 1

    def info(self) -> Dict[str, object]:
        return {"name": self.name, "online": self.online, "tx": self.tx_count, "rx": self.rx_count,
                "description": self.description,
                "messages": [{"id": f"0x{s.arb_id:03X}", "name": s.name, "period_ms": round(s.period_s * 1000)}
                             for s in self.specs]}


class EngineECU(ECU):
    description = "Engine control: RPM, coolant temperature, throttle position"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.specs = [TxSpec(0x180, 0.020, self._b180, "Engine_Telemetry")]

    def _b180(self) -> bytes:
        p = self.physics
        return struct.pack("<HBB4s", int(p.rpm / 0.25) & 0xFFFF, int(p.engine_temp + 40) & 0xFF,
                           min(255, int(p.throttle_pct / 0.392)), b"\0\0\0\0")


class BrakeECU(ECU):
    description = "Brake / ABS: brake pressure with rolling counter + CRC-8, wheel speed, odometer"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.counter = 0
        self.specs = [TxSpec(0x200, 0.020, self._b200, "Brake_Safety_Control"),
                      TxSpec(0x244, 0.050, self._b244, "Vehicle_Speed_Status")]

    def build_brake_payload(self, bar: float, gear: int, counter: int, crc: Optional[int] = None) -> bytes:
        part = struct.pack("<HBBBBB", int(bar / 0.01) & 0xFFFF, gear & 0xFF, 0, 0, 0, counter & 0x0F)
        return part + bytes([calc_crc8_sae_j1850(part) if crc is None else crc])

    def _b200(self) -> bytes:
        self.counter = (self.counter + 1) % 16
        return self.build_brake_payload(self.physics.brake_bar, self.physics.gear, self.counter)

    def build_speed_payload(self, speed_kmh: float) -> bytes:
        return struct.pack("<HI2s", int(max(0.0, speed_kmh) / 0.01) & 0xFFFF,
                           int(self.physics.odometer_km / 0.1) & 0xFFFFFFFF, b"\0\0")

    def _b244(self) -> bytes:
        return self.build_speed_payload(self.physics.speed_kmh)


class SteeringECU(ECU):
    description = "Steering angle sensor (angle + rate)"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.specs = [TxSpec(0x0C4, 0.010, self._b0c4, "Steering_Sensor")]
        self.freshness = 0

    def _b0c4(self) -> bytes:
        """AUTOSAR SecOC-style frame: 4 data bytes, 8-bit freshness value, 24-bit truncated HMAC-SHA256."""
        p = self.physics
        data = struct.pack("<HH", int((p.steering_deg + 500.0) / 0.1) & 0xFFFF,
                           int((max(-250.0, min(249.0, p.steering_rate)) + 250.0) / 0.5) & 0xFFFF)
        self.freshness = (self.freshness + 1) & 0xFF
        return data + bytes([self.freshness]) + compute_secoc_mac(SECOC_KEY_0C4, 0x0C4, data, self.freshness)


class TransmissionECU(ECU):
    description = "Transmission control: selected/actual gear, oil temperature, shift state"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.specs = [TxSpec(0x2A0, 0.050, self._b2a0, "Transmission_Status")]

    def _b2a0(self) -> bytes:
        p = self.physics
        sel = p.shift_target if p.shifting else p.gear
        return bytes([(p.gear & 0x0F) | ((sel & 0x0F) << 4), int(p.trans_temp + 40) & 0xFF,
                      1 if p.shifting else 0, 0])


class ClusterECU(ECU):
    description = "Instrument cluster: displays the speed it *receives* on the bus (0x244) and raises warning lamps"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.displayed_speed = 0.0
        self.rx_brake_bar = 0.0
        self.rx_temp = 88.0
        self.specs = [TxSpec(0x3C0, 0.100, self._b3c0, "Cluster_Display")]

    def on_rx(self, frame: CANFrame) -> None:
        super().on_rx(frame)
        d = frame.data
        if frame.arbitration_id == 0x244 and len(d) >= 2:
            self.displayed_speed = (d[0] | d[1] << 8) * 0.01
        elif frame.arbitration_id == 0x200 and len(d) >= 2:
            self.rx_brake_bar = (d[0] | d[1] << 8) * 0.01
        elif frame.arbitration_id == 0x180 and len(d) >= 3:
            self.rx_temp = d[2] - 40.0

    def lamps(self) -> int:
        bits = 0
        if self.displayed_speed > 130.0:
            bits |= 1                       # over-speed chime
        if self.rx_brake_bar > 90.0:
            bits |= 2                       # brake warning
        if self.rx_temp > 105.0:
            bits |= 4                       # coolant over-temperature
        return bits

    def _b3c0(self) -> bytes:
        return struct.pack("<HBB", int(min(655.0, self.displayed_speed) / 0.01) & 0xFFFF, self.lamps(), 0)


class BodyECU(ECU):
    description = "Body control: door locks, turn signals, hazards"

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.specs = [TxSpec(0x320, 0.100, self._b320, "Body_Status")]

    def _b320(self) -> bytes:
        return bytes([0x01, 0x00, 0x00, 0x00])    # doors locked, no hazard


def build_ecus(physics: VehiclePhysics, rng: random.Random) -> Dict[str, ECU]:
    ecus = [EngineECU("ECU_Engine", physics, rng), BrakeECU("ECU_Brake", physics, rng),
            SteeringECU("ECU_Steering", physics, rng), TransmissionECU("ECU_Transmission", physics, rng),
            ClusterECU("ECU_Cluster", physics, rng), BodyECU("ECU_Body", physics, rng)]
    # stagger start offsets so ECUs do not all collide at t=0
    for i, e in enumerate(ecus):
        for j, s in enumerate(e.specs):
            s.next_due = 0.001 * (i * 3 + j + 1)
    return {e.name: e for e in ecus}
