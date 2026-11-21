"""CAN IDS katmanlari: ID whitelist, zamanlama, kinematik sicrama, sayac/CRC-8, bus yuku, replay penceresi."""
import time
import collections
from typing import Dict, Any, List, Optional
from src.can_frame import CANFrame
from src.dbc_decoder import DBCDecoder, calc_crc8_sae_j1850
from src.isotp_uds import ISOTPUDSInspector

# Detection layers that can be switched on/off independently (benchmark + UI)
LAYER_IDS = ("CAN-IDS-01", "CAN-IDS-02", "CAN-IDS-03", "CAN-IDS-04", "CAN-IDS-05", "CAN-IDS-06", "CAN-IDS-07")
LAYER_NAMES = {
    "CAN-IDS-01": "ID Whitelist", "CAN-IDS-02": "Timing Jitter", "CAN-IDS-03": "Kinematic Jump",
    "CAN-IDS-04": "Counter / CRC / SecOC", "CAN-IDS-05": "Bus Load Flooding",
    "CAN-IDS-06": "Replay Window", "CAN-IDS-07": "ISO-TP / UDS Firewall",
}


import hmac
import hashlib


SECOC_KEY_0C4 = b"autosar_secoc_key_steering_0c4"   # lab key shared by ECU_Steering and the IDS (demo only)


def compute_secoc_mac(key: bytes, arbitration_id: int, payload_bytes: bytes, freshness: int) -> bytes:
    """Computes AUTOSAR SecOC 24-bit truncated HMAC-SHA256 MAC over payload + freshness."""
    msg = payload_bytes[:4] + bytes([freshness])
    return hmac.new(key, msg, hashlib.sha256).digest()[:3]


class CANAlert:
    """Structured explainable automotive intrusion alert with AUTOSAR IdsM & UNECE R155 metadata."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        arbitration_id: int,
        hex_id: str,
        message_name: str,
        observed_value: Any,
        expected_threshold: Any,
        evidence: str,
        mitigation: str,
        raw_frame_hex: str,
        timestamp: Optional[float] = None,
        qev_event_id: str = "QEV_CAN_INTRUSION_01",
        sensor_instance_id: int = 1,
        count: int = 1,
        unece_r155_code: str = "MITRE_M1030_CAN_INJECTION"
    ):
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.arbitration_id = arbitration_id
        self.hex_id = hex_id
        self.message_name = message_name
        self.observed_value = observed_value
        self.expected_threshold = expected_threshold
        self.evidence = evidence
        self.mitigation = mitigation
        self.raw_frame_hex = raw_frame_hex
        self.qev_event_id = qev_event_id
        self.sensor_instance_id = sensor_instance_id
        self.count = count
        self.unece_r155_code = unece_r155_code

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 4),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "arbitration_id": self.arbitration_id,
            "hex_id": self.hex_id,
            "message_name": self.message_name,
            "observed_value": self.observed_value,
            "expected_threshold": self.expected_threshold,
            "evidence": self.evidence,
            "mitigation": self.mitigation,
            "raw_frame_hex": self.raw_frame_hex,
            "qev_event_id": self.qev_event_id,
            "sensor_instance_id": self.sensor_instance_id,
            "count": self.count,
            "unece_r155_code": self.unece_r155_code
        }


class CANIntrusionDetectionEngine:
    """Stateful, rule-based automotive IDS."""

    def __init__(self, dbc: DBCDecoder, config: Optional[Dict[str, Any]] = None):
        self.dbc = dbc
        self.config = config or {}
        
        # Adjustable Thresholds
        thresholds = self.config.get("thresholds", {})
        self.max_accel_kmh_s = float(thresholds.get("max_accel_kmh_per_sec", 45.0))
        self.timing_jitter_pct = float(thresholds.get("timing_jitter_tolerance_pct", 80.0))
        self.bus_load_alert_pct = float(thresholds.get("bus_load_alert_pct", 75.0))
        self.replay_window_ms = float(thresholds.get("replay_duplicate_window_ms", 15.0))

        # Per-ID tracking state
        self.last_frame_time: Dict[int, float] = {}
        self.last_payload: Dict[int, bytes] = {}
        self.last_rolling_counter: Dict[int, int] = {}
        self.last_decoded_speed: Optional[tuple[float, float]] = None # (timestamp, speed_kmh)

        # AUTOSAR SecOC state
        self.secoc_key = SECOC_KEY_0C4
        self.last_secoc_freshness: Dict[int, int] = {}

        # ISO-TP reassembly + UDS deep inspection (Layer 7), wired into process_frame
        self.isotp = ISOTPUDSInspector()

        # Layer switches and optional user-designed rules (rule designer)
        self.enabled_layers = set(LAYER_IDS)
        self.custom_rules = None  # object with evaluate(frame, decoded, now) -> List[CANAlert]

        # Recent alerts buffer
        self.alerts: collections.deque[CANAlert] = collections.deque(maxlen=500)
        self.rule_hit_counts: Dict[str, int] = collections.defaultdict(int)

    def process_frame(
        self,
        frame: CANFrame,
        current_bus_load_pct: float = 0.0,
        bus_load_pct: Optional[float] = None
    ) -> List[CANAlert]:
        """Analyzes an incoming CAN frame across all active defensive layers."""
        if bus_load_pct is not None:
            current_bus_load_pct = bus_load_pct
        triggered_alerts: List[CANAlert] = []
        on = self.enabled_layers
        now = frame.timestamp
        aid = frame.arbitration_id
        decoded_info = self.dbc.decode_frame(frame)
        msg_name = decoded_info.get("name", "UNKNOWN")

        # Layer 1: CAN-IDS-01 — ID Whitelist / Unknown Arbitration ID
        if "CAN-IDS-01" in on and not self.dbc.is_known_id(aid, frame.is_extended_id):
            alert = CANAlert(
                rule_id="CAN-IDS-01",
                rule_name="Unknown Arbitration ID Injection",
                severity="HIGH",
                arbitration_id=aid,
                hex_id=frame.hex_id,
                message_name="UNKNOWN_ID",
                observed_value=frame.hex_id,
                expected_threshold="DBC Authorized Allowlist",
                evidence=f"Arbitration ID {frame.hex_id} ({aid}) is not defined in authorized vehicle signal manifest.",
                mitigation="Block unauthorized frame at central gateway ECU; verify OBD-II diagnostics port isolation.",
                raw_frame_hex=frame.hex_data,
                timestamp=now
            )
            triggered_alerts.append(alert)

        # Layer 2: CAN-IDS-02 — Frequency & Timing Jitter Anomaly
        msg_def = self.dbc.get_message_def(aid)
        if "CAN-IDS-02" in on and msg_def and "cycle_time_ms" in msg_def:
            nominal_cycle_s = msg_def["cycle_time_ms"] / 1000.0
            if aid in self.last_frame_time:
                dt = now - self.last_frame_time[aid]
                min_allowed_dt = nominal_cycle_s * (1.0 - (self.timing_jitter_pct / 100.0))
                # Trigger if inter-arrival is an order of magnitude faster than scheduled
                if dt < min_allowed_dt and dt > 0.0001:
                    alert = CANAlert(
                        rule_id="CAN-IDS-02",
                        rule_name="High-Rate Timing Jitter Anomaly",
                        severity="MEDIUM",
                        arbitration_id=aid,
                        hex_id=frame.hex_id,
                        message_name=msg_name,
                        observed_value=f"{dt * 1000:.1f} ms",
                        expected_threshold=f">= {min_allowed_dt * 1000:.1f} ms (Cycle: {msg_def['cycle_time_ms']} ms)",
                        evidence=f"Frame arrived in {dt*1000:.2f} ms; violation of nominal schedule for {msg_name}.",
                        mitigation="Inspect CAN controller transmission buffer; filter unauthorized high-frequency frame bursts.",
                        raw_frame_hex=frame.hex_data,
                        timestamp=now
                    )
                    triggered_alerts.append(alert)

        # Layer 3: CAN-IDS-03 — Kinematic Jump (Speed Delta Violation)
        if aid == 0x244 and decoded_info.get("decoded"):
            speed_signal = decoded_info.get("signals", {}).get("speed_kmh")
            if speed_signal and speed_signal.get("valid"):
                curr_speed = float(speed_signal["value"])
                if "CAN-IDS-03" in on and self.last_decoded_speed is not None:
                    prev_time, prev_speed = self.last_decoded_speed
                    dt = now - prev_time
                    if dt > 0.005:
                        accel_kmh_s = abs(curr_speed - prev_speed) / dt
                        if accel_kmh_s > self.max_accel_kmh_s:
                            alert = CANAlert(
                                rule_id="CAN-IDS-03",
                                rule_name="Kinematic Acceleration Delta Violation",
                                severity="CRITICAL",
                                arbitration_id=aid,
                                hex_id=frame.hex_id,
                                message_name=msg_name,
                                observed_value=f"{accel_kmh_s:.1f} km/h/s (Δv={curr_speed - prev_speed:.1f} km/h in {dt*1000:.1f}ms)",
                                expected_threshold=f"<= {self.max_accel_kmh_s:.1f} km/h/s",
                                evidence=f"Speed jumped from {prev_speed:.1f} to {curr_speed:.1f} km/h in {dt*1000:.1f}ms, violating physical vehicle dynamics.",
                                mitigation="Switch to secondary wheel-speed sensor arbitration (ABS/ESP); flag spoofed speed metric.",
                                raw_frame_hex=frame.hex_data,
                                timestamp=now
                            )
                            triggered_alerts.append(alert)
                self.last_decoded_speed = (now, curr_speed)

        # Layer 4: CAN-IDS-04 — Rolling Counter & CRC-8 Checksum Verification
        if "CAN-IDS-04" in on and aid == 0x200 and len(frame.data) >= 8:
            # Message 0x200 contains rolling counter in bits 48..51 and CRC-8 in byte 7
            cnt = (frame.data[6] >> 0) & 0x0F
            received_crc = frame.data[7]
            expected_crc = calc_crc8_sae_j1850(frame.data[:7])

            # Check CRC
            if received_crc != expected_crc:
                alert = CANAlert(
                    rule_id="CAN-IDS-04",
                    rule_name="Brake Payload Application CRC-8 Checksum Failure (SAE J1850)",
                    severity="CRITICAL",
                    arbitration_id=aid,
                    hex_id=frame.hex_id,
                    message_name=msg_name,
                    observed_value=f"CRC: 0x{received_crc:02X}",
                    expected_threshold=f"CRC: 0x{expected_crc:02X} (SAE J1850)",
                    evidence=f"Payload corruption or tampering detected on critical safety message {msg_name}.",
                    mitigation="Discard invalid brake command; activate ADAS fail-safe hydraulic fallback.",
                    raw_frame_hex=frame.hex_data,
                    timestamp=now
                )
                triggered_alerts.append(alert)

            # Check Rolling Counter Monotonicity
            if aid in self.last_rolling_counter:
                prev_cnt = self.last_rolling_counter[aid]
                expected_cnt = (prev_cnt + 1) % 16
                if cnt != expected_cnt:
                    alert = CANAlert(
                        rule_id="CAN-IDS-04",
                        rule_name="Brake Payload Rolling Counter Sequence Anomaly",
                        severity="HIGH",
                        arbitration_id=aid,
                        hex_id=frame.hex_id,
                        message_name=msg_name,
                        observed_value=f"Counter: {cnt}",
                        expected_threshold=f"Expected: {expected_cnt} (Prev: {prev_cnt})",
                        evidence=f"Rolling counter sequence broken on {msg_name}; potential message replay or drop.",
                        mitigation="Verify transceiver buffer health; discard out-of-order brake control frames.",
                        raw_frame_hex=frame.hex_data,
                        timestamp=now
                    )
                    triggered_alerts.append(alert)
            self.last_rolling_counter[aid] = cnt

        # Layer 4B: CAN-IDS-04B — AUTOSAR SecOC Cryptographic Verification
        # Message 0x0C4 Steering: bytes 0..3: data, byte 4: freshness, bytes 5..7: 24-bit MAC
        if "CAN-IDS-04" in on and aid == 0x0C4 and len(frame.data) < 8:
            # 0x0C4 is SecOC-protected: a frame without room for freshness + MAC is unauthenticated by definition.
            triggered_alerts.append(CANAlert(
                rule_id="CAN-IDS-04B", rule_name="AUTOSAR SecOC Authenticator Missing (unsigned steering frame)",
                severity="CRITICAL", arbitration_id=aid, hex_id=frame.hex_id, message_name=msg_name,
                observed_value=f"DLC {len(frame.data)} (no freshness/MAC)", expected_threshold="DLC 8: data + FV + 24-bit MAC",
                evidence=f"Steering message {msg_name} arrived without a SecOC authenticator; legitimate ECU_Steering frames are always signed.",
                mitigation="Reject steering command; fall back to mechanical torque-sensing limp mode.",
                raw_frame_hex=frame.hex_data, timestamp=now,
                qev_event_id="QEV_SECOC_VERIFICATION_FAIL", unece_r155_code="UNECE_R155_ANNEX5_CRYPTO_MAC_INVALID"))
        if "CAN-IDS-04" in on and aid == 0x0C4 and len(frame.data) >= 8:
            freshness = frame.data[4]
            received_mac = frame.data[5:8]
            expected_mac = hmac.new(self.secoc_key, frame.data[:5], hashlib.sha256).digest()[:3]

            if received_mac != expected_mac:
                alert = CANAlert(
                    rule_id="CAN-IDS-04B",
                    rule_name="AUTOSAR SecOC Cryptographic MAC Failure (24-bit Truncated MAC)",
                    severity="CRITICAL",
                    arbitration_id=aid,
                    hex_id=frame.hex_id,
                    message_name=msg_name,
                    observed_value=f"MAC: 0x{received_mac.hex().upper()}",
                    expected_threshold=f"MAC: 0x{expected_mac.hex().upper()}",
                    evidence=f"Cryptographic authentication tag mismatch on steering message {msg_name} (AUTOSAR SecOC Profile 1/2).",
                    mitigation="Reject steering command; fall back to mechanical torque-sensing limp mode.",
                    raw_frame_hex=frame.hex_data,
                    timestamp=now,
                    qev_event_id="QEV_SECOC_VERIFICATION_FAIL",
                    unece_r155_code="UNECE_R155_ANNEX5_CRYPTO_MAC_INVALID"
                )
                triggered_alerts.append(alert)

            if aid in self.last_secoc_freshness:
                prev_fv = self.last_secoc_freshness[aid]
                expected_fv = (prev_fv + 1) & 0xFF
                if freshness != expected_fv:
                    alert = CANAlert(
                        rule_id="CAN-IDS-04B",
                        rule_name="AUTOSAR SecOC Freshness Counter Sequence Failure",
                        severity="HIGH",
                        arbitration_id=aid,
                        hex_id=frame.hex_id,
                        message_name=msg_name,
                        observed_value=f"Freshness: {freshness}",
                        expected_threshold=f"Expected: {expected_fv} (Prev: {prev_fv})",
                        evidence=f"SecOC freshness value discontinuity on {msg_name}; indicates message replay or drop.",
                        mitigation="Synchronize ECU freshness manager counter; flag security audit event.",
                        raw_frame_hex=frame.hex_data,
                        timestamp=now,
                        qev_event_id="QEV_SECOC_FRESHNESS_FAIL",
                        unece_r155_code="UNECE_R155_ANNEX5_REPLAY_DETECTED"
                    )
                    triggered_alerts.append(alert)
            self.last_secoc_freshness[aid] = freshness

        # Layer 5: CAN-IDS-05 — Bus Load Saturation & Flooding
        if "CAN-IDS-05" in on and current_bus_load_pct >= self.bus_load_alert_pct:
            alert = CANAlert(
                rule_id="CAN-IDS-05",
                rule_name="CAN Bus Load Saturation Flooding",
                severity="HIGH",
                arbitration_id=aid,
                hex_id=frame.hex_id,
                message_name=msg_name,
                observed_value=f"{current_bus_load_pct:.1f}% Bus Load",
                expected_threshold=f"< {self.bus_load_alert_pct:.1f}%",
                evidence=f"Bus bandwidth saturated at {current_bus_load_pct:.1f}%; priority starvation hazard for safety frames.",
                mitigation="Isolate flooding node; enable transceiver bus-off containment at central CAN gateway.",
                raw_frame_hex=frame.hex_data,
                timestamp=now
            )
            triggered_alerts.append(alert)

        # Layer 6: CAN-IDS-06 — Fast Payload Replay / Duplicate Injection
        if "CAN-IDS-06" in on and aid in self.last_payload and aid in self.last_frame_time:
            dt_replay_ms = (now - self.last_frame_time[aid]) * 1000.0
            if dt_replay_ms < self.replay_window_ms and frame.data == self.last_payload[aid] and aid in (0x180, 0x244, 0x200):
                alert = CANAlert(
                    rule_id="CAN-IDS-06",
                    rule_name="Rapid Identical Payload Replay",
                    severity="MEDIUM",
                    arbitration_id=aid,
                    hex_id=frame.hex_id,
                    message_name=msg_name,
                    observed_value=f"Identical payload in {dt_replay_ms:.2f} ms",
                    expected_threshold=f"> {self.replay_window_ms:.1f} ms",
                    evidence=f"Message {msg_name} ({frame.hex_id}) re-injected with identical payload within {dt_replay_ms:.2f} ms (below replay window threshold).",
                    mitigation="Correlate rolling counters; verify physical ECU transmitter clock drift.",
                    raw_frame_hex=frame.hex_data,
                    timestamp=now
                )
                triggered_alerts.append(alert)

        # Layer 7: CAN-IDS-07 — ISO-TP reassembly + UDS (ISO 14229) deep inspection
        # Every diagnostic-ID frame (SF/FF/CF) goes through the stateful reassembler; the
        # *reassembled* UDS message is audited, so multi-frame attacks (e.g. 0x34 reflash) are seen.
        if "CAN-IDS-07" in on and self.isotp.is_diag_id(aid):
            for fd in self.isotp.inspect(frame, self.last_vehicle_speed_kmh):
                triggered_alerts.append(CANAlert(
                    rule_id=fd["rule_id"], rule_name=fd["rule_name"], severity=fd["severity"],
                    arbitration_id=aid, hex_id=frame.hex_id, message_name=fd["message_name"],
                    observed_value=fd["observed_value"], expected_threshold=fd["expected_threshold"],
                    evidence=fd["evidence"], mitigation=fd["mitigation"], raw_frame_hex=frame.hex_data,
                    timestamp=now, qev_event_id=fd["qev_event_id"], unece_r155_code=fd["unece_r155_code"]))

        # User-designed rules (IDS Rule Designer)
        if self.custom_rules is not None:
            triggered_alerts.extend(self.custom_rules.evaluate(frame, decoded_info, self))

        # Update tracking
        self.last_frame_time[aid] = now
        self.last_payload[aid] = frame.data

        for a in triggered_alerts:
            self.alerts.append(a)
            self.rule_hit_counts[a.rule_id] += 1

        return triggered_alerts

    def reset_state(self) -> None:
        """Forget per-ID history (used when the virtual bench restarts); keeps config, layers and rules."""
        self.last_frame_time.clear()
        self.last_payload.clear()
        self.last_rolling_counter.clear()
        self.last_secoc_freshness.clear()
        self.last_decoded_speed = None
        self.isotp = ISOTPUDSInspector()
        rules = getattr(self, "custom_rules", None)
        if rules is not None and hasattr(rules, "reset_state"):   # rate windows use the bench clock too
            rules.reset_state()

    def tune_thresholds(self, new_thresholds: Dict[str, Any]) -> None:
        """Dynamically tunes IDS thresholds for false-positive reduction."""
        if "max_accel_kmh_per_sec" in new_thresholds:
            self.max_accel_kmh_s = float(new_thresholds["max_accel_kmh_per_sec"])
        if "timing_jitter_tolerance_pct" in new_thresholds:
            self.timing_jitter_pct = float(new_thresholds["timing_jitter_tolerance_pct"])
        if "bus_load_alert_pct" in new_thresholds:
            self.bus_load_alert_pct = float(new_thresholds["bus_load_alert_pct"])
        if "replay_duplicate_window_ms" in new_thresholds:
            self.replay_window_ms = float(new_thresholds["replay_duplicate_window_ms"])

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self.alerts),
            "rule_hits": dict(self.rule_hit_counts),
            "enabled_layers": sorted(self.enabled_layers),
            "current_thresholds": {
                "max_accel_kmh_s": self.max_accel_kmh_s,
                "timing_jitter_pct": self.timing_jitter_pct,
                "bus_load_alert_pct": self.bus_load_alert_pct,
                "replay_window_ms": self.replay_window_ms
            }
        }

    @property
    def uds_log(self) -> List[Dict[str, Any]]:
        return list(self.isotp.log)

    def set_layer_enabled(self, layer_id: str, enabled: bool) -> None:
        if layer_id not in LAYER_IDS:
            raise KeyError(layer_id)
        (self.enabled_layers.add if enabled else self.enabled_layers.discard)(layer_id)

    @property
    def last_vehicle_speed_kmh(self) -> float:
        return self.last_decoded_speed[1] if self.last_decoded_speed is not None else 0.0
