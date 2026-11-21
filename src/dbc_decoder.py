"""
GÖK CAN-IDS Lab — DBC Signal Decoder & SAE J1850 CRC-8 Calculator.
Zero external library dependencies.
"""
import json
from typing import Dict, Any, List, Optional
from src.can_frame import CANFrame


def calc_crc8_sae_j1850(data: bytes, poly: int = 0x1D, init_val: int = 0xFF, xor_out: int = 0xFF) -> int:
    """
    Calculates automotive SAE J1850 CRC-8 (poly=0x1D, init=0xFF, xor_out=0xFF).

    CRITICAL ARCHITECTURAL DISTINCTION (ISO 11898-1 vs Application E2E):
    ----------------------------------------------------------------------
    1. Application-Layer CRC (This Function):
       Computes an end-to-end (E2E) protection checksum embedded inside the 8-byte
       CAN payload (specifically in byte 7 of message 0x200 Brake_Safety_Control).
       This verifies that payload content was not modified in transit by intermediate
       software, gateways, or spoofing attackers. This algorithm is specific to this
       synthetic benchmark profile and is NOT a universal automotive standard.

    2. Hardware CAN Link-Layer CRC (Data-Link Layer):
       Defined by ISO 11898-1 as a 15-bit CRC (CRC-15-CAN, poly 0x4599) calculated
       in silicon by the physical CAN transceiver/controller over SOF, arbitration,
       control, and data fields, followed by an ACK delimiter. The application layer
       never calculates or inspects the 15-bit hardware CRC directly.
    """
    crc = init_val
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc ^ xor_out


def signal_bit_positions(start_bit: int, length: int, endian: str) -> list:
    """Absolute bit indices (byte*8 + bit) occupied by a signal, MSB first.

    Intel / little-endian (@1): start_bit is the LSB, bits run upwards.
    Motorola / big-endian (@0): start_bit is the MSB in Vector "sawtooth" numbering.
    """
    if endian == "little":
        return list(range(start_bit, start_bit + length))
    bits, cur = [], start_bit
    for _ in range(length):
        bits.append(cur)
        cur = cur + 15 if cur % 8 == 0 else cur - 1
    return bits


def extract_raw(data: bytes, start_bit: int, length: int, endian: str = "little") -> Optional[int]:
    """Raw unsigned value of a signal, any length 1..64 and either byte order.
    Returns None when the signal does not fit into the available payload bytes."""
    if length <= 0:
        return None
    positions = signal_bit_positions(start_bit, length, endian)
    if any(b < 0 or (b >> 3) >= len(data) for b in positions):
        return None
    if endian == "little":
        raw = 0
        for i, b in enumerate(positions):
            raw |= ((data[b >> 3] >> (b & 7)) & 1) << i
        return raw
    raw = 0
    for b in positions:  # MSB first
        raw = (raw << 1) | ((data[b >> 3] >> (b & 7)) & 1)
    return raw


def insert_raw(buf: bytearray, start_bit: int, length: int, endian: str, raw: int) -> None:
    """Write a raw unsigned value into buf (inverse of extract_raw)."""
    positions = signal_bit_positions(start_bit, length, endian)
    if endian == "little":
        bits = [(raw >> i) & 1 for i in range(length)]
    else:
        bits = [(raw >> (length - 1 - i)) & 1 for i in range(length)]
    for b, v in zip(positions, bits):
        if (b >> 3) >= len(buf):
            raise ValueError(f"signal bit {b} outside payload of {len(buf)} bytes")
        if v:
            buf[b >> 3] |= 1 << (b & 7)
        else:
            buf[b >> 3] &= ~(1 << (b & 7)) & 0xFF


class DBCDecoder:
    """
    Decodes raw CANFrame payloads according to standard Vector ASCII .dbc files
    or synthetic can_signals.json specifications.
    Explicitly distinguishes between standard DBC syntax and custom JSON schemas.
    """

    @classmethod
    def parse_dbc_file(cls, path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return cls.parse_dbc_text(f.read())

    @classmethod
    def parse_dbc_text(cls, text: str) -> Dict[str, Any]:
        """
        Parses standard Vector ASCII .dbc files (BO_ and SG_ syntax).
        Standard Vector syntax:
          BO_ <id> <name>: <dlc> <transmitter>
          SG_ <name> : <start_bit>|<length>@<byte_order><sign> (<scale>,<offset>) [<min>|<max>] "<unit>" <receiver>
        """
        import re
        messages = []
        val_tables = {}
        mul_val_tables = {}
        current_msg = None

        bo_pattern = re.compile(r"^BO_\s+(\d+)\s+([A-Za-z0-9_]+)\s*:\s*(\d+)\s+([A-Za-z0-9_]+)")
        # Extended SG_ pattern: captures optional multiplexer indicator (e.g. M or m0) if present
        sg_pattern = re.compile(
            r"^\s*SG_\s+([A-Za-z0-9_]+)(?:\s+([Mm0-9]+))?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*\(([^,]+),([^)]+)\)\s*\[([^|]+)\|([^]]+)\]\s*\"([^\"]*)\"\s*([A-Za-z0-9_]+)"
        )
        val_pattern = re.compile(r"^VAL_\s+(\d+)\s+([A-Za-z0-9_]+)\s+(.*?)\s*;")
        mul_val_pattern = re.compile(r"^SG_MUL_VAL_\s+(\d+)\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+(.*?)\s*;")

        cycle_pattern = re.compile(r'^BA_\s+"GenMsgCycleTime"\s+BO_\s+(\d+)\s+(\d+)\s*;')
        cycle_times = {}
        if True:
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("//") or line.startswith("#"):
                    continue

                cyc_m = cycle_pattern.match(line)
                if cyc_m:
                    cycle_times[int(cyc_m.group(1))] = int(cyc_m.group(2))
                    continue

                # VAL_ <id> <signal_name> <val> "<desc>" ... ;
                val_m = val_pattern.match(line)
                if val_m:
                    v_aid = int(val_m.group(1))
                    v_sig = val_m.group(2)
                    v_pairs = re.findall(r'(\d+)\s+"([^"]*)"', val_m.group(3))
                    if v_aid not in val_tables:
                        val_tables[v_aid] = {}
                    val_tables[v_aid][v_sig] = {int(code): text for code, text in v_pairs}
                    continue

                # SG_MUL_VAL_ <id> <signal_name> <mux_switch> <range> ;
                mul_m = mul_val_pattern.match(line)
                if mul_m:
                    m_aid = int(mul_m.group(1))
                    m_sig = mul_m.group(2)
                    m_switch = mul_m.group(3)
                    m_range = mul_m.group(4)
                    if m_aid not in mul_val_tables:
                        mul_val_tables[m_aid] = {}
                    mul_val_tables[m_aid][m_sig] = {"switch": m_switch, "range": m_range}
                    continue

                bo_m = bo_pattern.match(line)
                if bo_m:
                    raw_id = int(bo_m.group(1))
                    # Vector DBC standard: Extended 29-bit CAN IDs have bit 31 set (0x80000000)
                    is_extended = bool(raw_id & 0x80000000)
                    can_id = (raw_id & 0x1FFFFFFF) if is_extended else raw_id

                    msg_name = bo_m.group(2)
                    dlc = int(bo_m.group(3))
                    transmitter = bo_m.group(4)
                    current_msg = {
                        "id_raw": raw_id,
                        "id_dec": can_id,
                        "id_hex": f"0x{can_id:08X}" if is_extended else f"0x{can_id:03X}",
                        "is_extended": is_extended,
                        "name": msg_name,
                        "dlc": dlc,
                        "transmitter": transmitter,
                        "signals": []
                    }
                    messages.append(current_msg)
                    continue

                sg_m = sg_pattern.match(line)
                if sg_m and current_msg is not None:
                    sig_name = sg_m.group(1)
                    mux_indicator = sg_m.group(2)
                    start_bit = int(sg_m.group(3))
                    length = int(sg_m.group(4))
                    endian_bit = sg_m.group(5)  # 1 = little (Intel), 0 = big (Motorola)
                    is_signed = (sg_m.group(6) == "-")
                    scale = float(sg_m.group(7))
                    offset = float(sg_m.group(8))
                    min_val = float(sg_m.group(9))
                    max_val = float(sg_m.group(10))
                    unit = sg_m.group(11)

                    current_msg["signals"].append({
                        "name": sig_name,
                        "mux": mux_indicator,
                        "start_bit": start_bit,
                        "length": length,
                        "endian": "little" if endian_bit == "1" else "big",
                        "is_signed": is_signed,
                        "scale": scale,
                        "offset": offset,
                        "min": min_val,
                        "max": max_val,
                        "unit": unit
                    })

        for m in messages:
            if m["id_raw"] in cycle_times:
                m["cycle_time_ms"] = cycle_times[m["id_raw"]]
        return {
            "format": "VECTOR_ASCII_DBC",
            "nominal_bitrate_kbps": 500,
            "messages": messages,
            "val_tables": val_tables,
            "mul_val_tables": mul_val_tables
        }

    def __init__(self, config_path: str):
        self.config_path = config_path
        if config_path.lower().endswith(".dbc"):
            self.config = self.parse_dbc_file(config_path)
            self.format_type = "VECTOR_ASCII_DBC"
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
            self.format_type = "SYNTHETIC_JSON_SCHEMA"

        self._index()

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "DBCDecoder":
        d = cls.__new__(cls)
        d.config_path = None
        d.format_type = "IN_MEMORY"
        d.config = config
        d._index()
        return d

    def load_config(self, config: Dict[str, Any]) -> None:
        """Replace the active database in place (used by the DBC editor / import)."""
        self.config = config
        self.format_type = "IN_MEMORY"
        self._index()

    def _index(self) -> None:
        self.nominal_bitrate = self.config.get("nominal_bitrate_kbps", 500) * 1000
        self.message_map: Dict[int, Dict[str, Any]] = {}
        self.val_tables: Dict[int, Dict[str, Dict[int, str]]] = self.config.get("val_tables", {})
        self.mul_val_tables: Dict[int, Dict[str, Any]] = self.config.get("mul_val_tables", {})

        for msg in self.config.get("messages", []):
            self.message_map[msg["id_dec"]] = msg
            if "id_raw" in msg:
                self.message_map[msg["id_raw"]] = msg

    def get_message_def(self, arbitration_id: int) -> Optional[Dict[str, Any]]:
        return self.message_map.get(arbitration_id) or self.message_map.get(arbitration_id & 0x1FFFFFFF)

    def is_known_id(self, arbitration_id: int, is_extended: Optional[bool] = None) -> bool:
        """Known in the DBC. With `is_extended`, the frame format must match too (a 29-bit 0x244 is not 0x244)."""
        msg = self.get_message_def(arbitration_id)
        if msg is None:
            return False
        return is_extended is None or bool(msg.get("is_extended", False)) == bool(is_extended)

    def decode_frame(self, frame: CANFrame) -> Dict[str, Any]:
        """Extracts named physical signals from the frame's data bytes."""
        msg_def = self.get_message_def(frame.arbitration_id)
        if not msg_def:
            return {
                "name": "UNKNOWN_ID",
                "signals": {},
                "decoded": False
            }

        signals: Dict[str, Any] = {}
        data = frame.data

        for sig in msg_def.get("signals", []):
            name = sig["name"]
            start_bit = sig["start_bit"]
            length = sig["length"]
            endian = sig.get("endian", "little")
            is_signed = sig.get("is_signed", False)
            scale = sig.get("scale", 1.0)
            offset = sig.get("offset", 0.0)
            unit = sig.get("unit", "")
            min_val = sig.get("min")
            max_val = sig.get("max")

            raw_opt = extract_raw(data, start_bit, length, endian)
            if raw_opt is None:
                signals[name] = {"value": 0, "unit": unit, "valid": False, "in_range": False}
                continue
            raw_val = raw_opt

            # Signed two's complement conversion if specified in DBC (@[01]-)
            if is_signed and length > 0:
                if raw_val & (1 << (length - 1)):
                    raw_val -= (1 << length)

            physical_val = round((raw_val * scale) + offset, 2)
            in_range = True
            if min_val is not None and max_val is not None and max_val > min_val:
                in_range = (min_val <= physical_val <= max_val)

            # Resolve enum description from VAL_ tables if available
            enum_desc = None
            msg_id_dec = msg_def.get("id_dec")
            msg_id_raw = msg_def.get("id_raw")
            if msg_id_dec in self.val_tables and name in self.val_tables[msg_id_dec]:
                enum_desc = self.val_tables[msg_id_dec][name].get(raw_val)
            elif msg_id_raw in self.val_tables and name in self.val_tables[msg_id_raw]:
                enum_desc = self.val_tables[msg_id_raw][name].get(raw_val)

            sig_entry: Dict[str, Any] = {
                "value": physical_val,
                "raw": raw_val,
                "unit": unit,
                "valid": True,
                "in_range": in_range
            }
            if enum_desc is not None:
                sig_entry["enum_desc"] = enum_desc

            signals[name] = sig_entry

        return {
            "name": msg_def.get("name", "UNNAMED"),
            "signals": signals,
            "decoded": True
        }

    def encode_message(self, key, values: Dict[str, float]) -> bytes:
        """Pack physical signal values into a payload using the active database (inverse of decode)."""
        msg = self.get_message_def(key) if isinstance(key, int) else next(
            (m for m in self.config.get("messages", []) if m.get("name") == key), None)
        if msg is None:
            raise KeyError(f"unknown message {key!r}")
        buf = bytearray(int(msg.get("dlc", 8)))
        for sig in msg.get("signals", []):
            if sig["name"] not in values:
                continue
            scale = float(sig.get("scale", 1.0)) or 1.0
            raw = int(round((float(values[sig["name"]]) - float(sig.get("offset", 0.0))) / scale))
            length = int(sig["length"])
            if sig.get("is_signed"):
                lo, hi = -(1 << (length - 1)), (1 << (length - 1)) - 1
                raw = max(lo, min(hi, raw)) & ((1 << length) - 1)
            else:
                raw = max(0, min((1 << length) - 1, raw))
            insert_raw(buf, int(sig["start_bit"]), length, sig.get("endian", "little"), raw)
        return bytes(buf)

    def validate_dbc_integrity(self) -> Dict[str, Any]:
        """Validates signal bit layout, detects bit overlaps, boundary overflows, and multiplexer consistency."""
        issues: list[str] = []
        messages_checked = 0
        signals_checked = 0

        for msg in self.config.get("messages", []):
            messages_checked += 1
            dlc = msg.get("dlc", 8)
            max_bit = dlc * 8
            bit_alloc: Dict[int, str] = {}

            for sig in msg.get("signals", []):
                signals_checked += 1
                s_name = sig.get("name", "UNNAMED")
                start = sig.get("start_bit", 0)
                length = sig.get("length", 1)
                endian = sig.get("endian", "little")

                occupied_bits = signal_bit_positions(start, length, endian)

                for b in occupied_bits:
                    if b >= max_bit:
                        issues.append(
                            f"Signal '{s_name}' in message '{msg.get('name')}' (ID {msg.get('id_hex')}) "
                            f"exceeds DLC boundary: bit {b} >= {max_bit}"
                        )
                    elif b in bit_alloc and not sig.get("mux"):
                        issues.append(
                            f"Signal overlap in message '{msg.get('name')}' (ID {msg.get('id_hex')}): "
                            f"'{s_name}' overlaps '{bit_alloc[b]}' at bit {b}"
                        )
                    else:
                        bit_alloc[b] = s_name

        return {
            "valid": len(issues) == 0,
            "messages_checked": messages_checked,
            "signals_checked": signals_checked,
            "issues_count": len(issues),
            "issues": issues
        }
