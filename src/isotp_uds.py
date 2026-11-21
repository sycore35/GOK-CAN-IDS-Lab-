"""ISO-TP (ISO 15765-2) birlestirme ve UDS (ISO 14229) denetimi."""

import time
import collections
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Any
from src.can_frame import CANFrame


UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting"
}


@dataclass
class ISOTPSession:
    arbitration_id: int
    total_length: int
    buffer: bytearray = field(default_factory=bytearray)
    expected_sn: int = 1
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    completed: bool = False
    error: Optional[str] = None


@dataclass
class UDSMessage:
    arbitration_id: int
    service_id: int
    service_name: str
    sub_function: Optional[int]
    payload: bytes
    is_negative_response: bool = False
    nrc_code: Optional[int] = None
    security_risk: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW


class ISOTPReassembler:
    """Stateful ISO 15765-2 Multi-Frame Reassembly Engine."""

    def __init__(self, session_timeout_sec: float = 1.0):
        self.sessions: Dict[int, ISOTPSession] = {}
        self.session_timeout_sec = session_timeout_sec
        self.completed_messages: List[Tuple[int, bytes]] = []
        self.expired_events: List[Dict[str, Any]] = []  # drained by the inspector

    def process_frame(self, frame: CANFrame) -> Dict[str, Any]:
        """
        Processes single CAN frame and returns state:
        {"status": "COMPLETE" | "IN_PROGRESS" | "ERROR", "payload": bytes, "error": str}
        """
        now = frame.timestamp or time.time()
        self._expire_stale_sessions(now)

        pci = frame.parse_isotp_pci()
        if not pci.get("valid"):
            return {"status": "IGNORED", "error": "Invalid PCI"}

        pci_type = pci["type"]
        arb_id = frame.arbitration_id

        # 1. Single Frame (SF)
        if pci_type == "SF":
            payload = pci["uds_payload"]
            if pci["length"] == 0 or pci["length"] > 7 or len(payload) < pci["length"]:
                return {"status": "ERROR", "error": "INVALID_SF_LENGTH", "arbitration_id": arb_id}
            return {"status": "COMPLETE", "arbitration_id": arb_id, "payload": payload}

        # 2. First Frame (FF)
        elif pci_type == "FF":
            total_len = pci["total_length"]
            uds_chunk = pci["uds_payload"]
            if total_len < 8:
                return {"status": "ERROR", "error": "INVALID_FF_LENGTH", "arbitration_id": arb_id,
                        "details": f"First Frame announces {total_len} bytes (<8 must be a Single Frame)"}
            restarted = arb_id in self.sessions
            session = ISOTPSession(
                arbitration_id=arb_id,
                total_length=total_len,
                buffer=bytearray(uds_chunk),
                expected_sn=1,
                start_time=now,
                last_update=now
            )
            self.sessions[arb_id] = session
            return {"status": "IN_PROGRESS", "total_length": total_len,
                    "accumulated": len(session.buffer), "session_restarted": restarted}

        # 3. Consecutive Frame (CF)
        elif pci_type == "CF":
            session = self.sessions.get(arb_id)
            if not session:
                return {
                    "status": "ERROR",
                    "arbitration_id": arb_id,
                    "error": "ORPHAN_CONSECUTIVE_FRAME",
                    "details": f"CF received for ID {frame.hex_id} without active First Frame session"
                }

            sn = pci["sequence_number"]
            if sn != session.expected_sn:
                session.error = f"SEQUENCE_MISMATCH: expected {session.expected_sn}, got {sn}"
                del self.sessions[arb_id]
                return {"status": "ERROR", "error": "SEQUENCE_MISMATCH", "arbitration_id": arb_id,
                        "expected": session.expected_sn, "got": sn}

            uds_chunk = pci["uds_payload"]
            remaining = session.total_length - len(session.buffer)
            session.buffer.extend(uds_chunk[:remaining])
            session.expected_sn = (session.expected_sn + 1) & 0x0F
            session.last_update = now

            if len(session.buffer) >= session.total_length:
                completed_payload = bytes(session.buffer[:session.total_length])
                del self.sessions[arb_id]
                return {
                    "status": "COMPLETE",
                    "arbitration_id": arb_id,
                    "payload": completed_payload,
                    "reassembled": True
                }

            return {"status": "IN_PROGRESS", "total_length": session.total_length, "accumulated": len(session.buffer)}

        # 4. Flow Control (FC)
        elif pci_type == "FC":
            return {"status": "FLOW_CONTROL", "flow_status": pci.get("flow_status")}

        return {"status": "UNKNOWN"}

    def _expire_stale_sessions(self, now: float):
        expired = [
            arb_id for arb_id, s in self.sessions.items()
            if (now - s.last_update) > self.session_timeout_sec
        ]
        for arb_id in expired:
            sess = self.sessions.pop(arb_id)
            self.expired_events.append({
                "arbitration_id": arb_id, "total_length": sess.total_length,
                "accumulated": len(sess.buffer), "first_byte": sess.buffer[0] if sess.buffer else None,
            })


class UDSServiceAuditor:
    """ISO 14229 Unified Diagnostic Services (UDS) Security Inspection Engine."""

    @staticmethod
    def audit_uds_payload(arbitration_id: int, payload: bytes) -> Optional[UDSMessage]:
        if not payload:
            return None

        sid = payload[0]
        # Check Negative Response: 0x7F <Rejected_SID> <NRC>
        if sid == 0x7F and len(payload) >= 3:
            rejected_sid = payload[1]
            nrc = payload[2]
            return UDSMessage(
                arbitration_id=arbitration_id,
                service_id=rejected_sid,
                service_name=UDS_SERVICES.get(rejected_sid, f"Service_0x{rejected_sid:02X}"),
                sub_function=None,
                payload=payload,
                is_negative_response=True,
                nrc_code=nrc,
                security_risk="LOW"
            )

        service_name = UDS_SERVICES.get(sid, f"Service_0x{sid:02X}")
        sub_fn = payload[1] if len(payload) > 1 else None

        # Threat classification
        risk = "LOW"
        if sid == 0x34 or sid == 0x36:
            risk = "CRITICAL"  # Unauthorized Firmware Download / Reflash attempt
        elif sid == 0x27:
            risk = "HIGH"      # SecurityAccess Seed/Key handshake
        elif sid == 0x28:
            risk = "HIGH"      # CommunicationControl (Bus-off / Silence)
        elif sid == 0x11:
            risk = "MEDIUM"    # ECU Reset
        elif sid in (0x2E, 0x31, 0x23, 0x85):
            risk = "MEDIUM"    # Write DID / Routine / ReadMemory / DTC setting

        return UDSMessage(
            arbitration_id=arbitration_id,
            service_id=sid,
            service_name=service_name,
            sub_function=sub_fn,
            payload=payload,
            is_negative_response=False,
            security_risk=risk
        )


DIAG_REQUEST_IDS = frozenset([0x7DF] + list(range(0x7E0, 0x7E8)))
DIAG_RESPONSE_IDS = frozenset(range(0x7E8, 0x7F0))
DIAG_IDS = DIAG_REQUEST_IDS | DIAG_RESPONSE_IDS


class ISOTPUDSInspector:
    """Stateful ISO-TP -> UDS inspector used by the main IDS engine (Layer 7).

    Feeds every diagnostic-ID frame through the ISO-TP reassembler, audits each completed
    UDS message and returns a list of *findings* (plain dicts) that the engine turns into
    CANAlert objects. Keeping findings as dicts keeps this module free of an import cycle.
    """

    def __init__(self, session_timeout_sec: float = 1.0, log_size: int = 200):
        self.reassembler = ISOTPReassembler(session_timeout_sec=session_timeout_sec)
        self.invalid_key_counts: Dict[int, int] = collections.defaultdict(int)
        self.log: collections.deque = collections.deque(maxlen=log_size)

    @staticmethod
    def is_diag_id(arbitration_id: int) -> bool:
        return arbitration_id in DIAG_IDS

    def inspect(self, frame: CANFrame, vehicle_speed_kmh: float = 0.0) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        res = self.reassembler.process_frame(frame)

        for ev in self.reassembler.expired_events:
            findings.append(self._f(
                "CAN-IDS-07C", "ISO-TP Multi-Frame Session Timeout (incomplete transfer)", "MEDIUM",
                ev["arbitration_id"], "UDS_ISOTP_TIMEOUT",
                f"{ev['accumulated']}/{ev['total_length']} bytes", "Complete transfer within the N_Cr timeout",
                "A First Frame was never completed; truncated transfers are a known IDS-evasion/fuzzing pattern.",
                "Drop the partial session at the gateway; review the sending node.",
                "QEV_ISOTP_TIMEOUT", "UNECE_R155_ANNEX5_DIAGNOSTIC_ATTACK"))
        self.reassembler.expired_events.clear()

        status = res.get("status")
        if status == "ERROR":
            err = res.get("error", "ERROR")
            if err in ("SEQUENCE_MISMATCH", "ORPHAN_CONSECUTIVE_FRAME", "INVALID_FF_LENGTH", "INVALID_SF_LENGTH"):
                sev = "HIGH" if err == "SEQUENCE_MISMATCH" else "MEDIUM"
                obs = (f"expected SN {res.get('expected')}, got {res.get('got')}"
                       if err == "SEQUENCE_MISMATCH" else err)
                findings.append(self._f(
                    "CAN-IDS-07C", f"ISO-TP Framing Anomaly: {err}", sev,
                    frame.arbitration_id, "UDS_ISOTP_ANOMALY", obs, "Well-formed SF/FF/CF sequence",
                    res.get("details") or f"ISO 15765-2 framing violation ({err}) on {frame.hex_id}.",
                    "Reset the transport session; correlate with fuzzing or injection from the diagnostic port.",
                    "QEV_ISOTP_FRAMING", "UNECE_R155_ANNEX5_DIAGNOSTIC_ATTACK"))
            return findings
        if status != "COMPLETE":
            return findings

        payload = res["payload"]
        msg = UDSServiceAuditor.audit_uds_payload(frame.arbitration_id, payload)
        if msg is None:
            return findings
        self.log.append({
            "timestamp": round(frame.timestamp, 4), "hex_id": frame.hex_id,
            "service_id": msg.service_id, "service_name": msg.service_name,
            "sub_function": msg.sub_function, "risk": msg.security_risk,
            "negative_response": msg.is_negative_response, "nrc": msg.nrc_code,
            "length": len(payload), "reassembled": bool(res.get("reassembled")),
            "payload_hex": payload[:32].hex().upper(),
        })

        sid = msg.service_id
        aid = frame.arbitration_id
        moving = vehicle_speed_kmh > 0.0

        if not msg.is_negative_response and sid == 0x67:   # SecurityAccess granted: the "consecutive" streak ends
            self.invalid_key_counts[aid] = 0
        if msg.is_negative_response:
            if msg.nrc_code == 0x35 and sid == 0x27:
                self.invalid_key_counts[aid] += 1
                n = self.invalid_key_counts[aid]
                if n >= 3:
                    findings.append(self._f(
                        "CAN-IDS-07B", "UDS SecurityAccess Brute-Force Key Guessing (NRC 0x35)", "HIGH",
                        aid, "UDS_NEGATIVE_RESPONSE", f"{n} Consecutive NRC 0x35 InvalidKey",
                        "< 3 InvalidKey Negative Responses",
                        "Repeated invalid security keys on diagnostic port indicates cryptographic brute-force attack.",
                        "Enforce exponential backoff lockout timer on diagnostic security server.",
                        "QEV_UDS_BRUTE_FORCE", "UNECE_R155_ANNEX5_BRUTE_FORCE"))
            return findings

        if moving:
            sub_fn = None if msg.sub_function is None else msg.sub_function & 0x7F   # bit 7 = suppressPosRspMsg
            if sid == 0x10 and sub_fn in (0x02, 0x03):
                sub = "Programming Session" if sub_fn == 0x02 else "Extended Session"
                findings.append(self._f(
                    "CAN-IDS-07", f"UDS {sub} Prohibited While Driving (ISO 14229 SID 0x10)", "CRITICAL",
                    aid, "UDS_DIAG_REQUEST", f"SID 0x10 {msg.sub_function:02X} at Speed={vehicle_speed_kmh:.1f} km/h",
                    "Diagnostic programming prohibited when speed > 0 km/h",
                    f"ECU diagnostic programming session requested while vehicle in motion ({vehicle_speed_kmh:.1f} km/h).",
                    "Central gateway rejects UDS request; alert vehicle SOC over telematics.",
                    "QEV_UDS_MOTION_PROHIBITED", "UNECE_R155_ANNEX5_DIAGNOSTIC_ATTACK"))
                return findings
            if sid == 0x11:
                findings.append(self._f(
                    "CAN-IDS-07", "UDS ECUReset Prohibited While Driving (ISO 14229 SID 0x11)", "CRITICAL",
                    aid, "UDS_DIAG_REQUEST", f"SID 0x11 ECUReset at Speed={vehicle_speed_kmh:.1f} km/h",
                    "ECU reset prohibited when speed > 0 km/h",
                    f"Critical ECU hard reset requested via diagnostics while driving at {vehicle_speed_kmh:.1f} km/h.",
                    "Drop diagnostic reset frame; log unauthorized OBD command.",
                    "QEV_UDS_RESET_MOTION", "UNECE_R155_ANNEX5_ECU_TAMPERING"))
                return findings
            if sid == 0x27:
                findings.append(self._f(
                    "CAN-IDS-07", "UDS SecurityAccess Prohibited While Driving (ISO 14229 SID 0x27)", "CRITICAL",
                    aid, "UDS_DIAG_REQUEST", f"SID 0x27 SecurityAccess at Speed={vehicle_speed_kmh:.1f} km/h",
                    "SecurityAccess unlock prohibited when speed > 0 km/h",
                    f"SecurityAccess unlock attempted on diagnostic port while vehicle in motion ({vehicle_speed_kmh:.1f} km/h).",
                    "Lock diagnostic session; enforce delay timer.",
                    "QEV_UDS_SECURITY_ACCESS_MOTION", "UNECE_R155_ANNEX5_SECURITY_ACCESS_TAMPER"))
                return findings

        if sid in (0x34, 0x36):
            how = "multi-frame (reassembled)" if res.get("reassembled") else "single-frame"
            findings.append(self._f(
                "CAN-IDS-07", (f"UDS {msg.service_name} Firmware Flash Prohibited In Motion (SID 0x{sid:02X})" if moving
                 else f"UDS {msg.service_name} Firmware Flash Attempt (SID 0x{sid:02X})"), "CRITICAL",
                aid, "UDS_DIAG_REQUEST",
                f"SID 0x{sid:02X} {msg.service_name}, {len(payload)} B {how}"
                + (f" at Speed={vehicle_speed_kmh:.1f} km/h" if moving else ""),
                "Firmware download/transfer must not originate from the vehicle bus",
                "OTA/diagnostic firmware flashing observed"
                + (" while the vehicle is actively moving." if moving else " on the diagnostic channel."),
                "Immediate gateway firewall drop; notify fleet security operations.",
                "QEV_UDS_FLASH_IN_MOTION" if moving else "QEV_UDS_FLASH_ATTEMPT",
                "UNECE_R155_ANNEX5_UNAUTHORIZED_FLASH"))
        elif sid == 0x28:
            findings.append(self._f(
                "CAN-IDS-07", "UDS CommunicationControl (bus silence) Request (SID 0x28)", "HIGH",
                aid, "UDS_DIAG_REQUEST", "SID 0x28 CommunicationControl", "Not expected outside a workshop session",
                "CommunicationControl can silence ECUs and hide an attack from monitors.",
                "Require authenticated diagnostic session before accepting.",
                "QEV_UDS_COMM_CONTROL", "UNECE_R155_ANNEX5_DIAGNOSTIC_ATTACK"))
        return findings

    @staticmethod
    def _f(rule_id, rule_name, severity, aid, message_name, observed, expected, evidence, mitigation, qev, r155):
        return {"rule_id": rule_id, "rule_name": rule_name, "severity": severity, "arbitration_id": aid,
                "message_name": message_name, "observed_value": observed, "expected_threshold": expected,
                "evidence": evidence, "mitigation": mitigation, "qev_event_id": qev, "unece_r155_code": r155}
