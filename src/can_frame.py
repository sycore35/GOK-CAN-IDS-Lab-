"""
GÖK CAN-IDS Lab — Pure-Python CAN Frame representation.
Zero external C-extension or driver dependencies.
"""
import time
from typing import Optional, Dict, Any


class CANFrame:
    """
    Represents Classical CAN 2.0A/B or CAN-FD (ISO 11898-1:2015) Frame.
    Supports extended 29-bit IDs, SAE J1939 PGN decomposition, and ISO-TP PCI parsing.
    """
    __slots__ = (
        "arbitration_id", "data", "dlc", "is_extended_id",
        "is_remote_frame", "timestamp", "is_fd", "brs", "source"
    )

    DLC_TO_BYTES_FD = {
        0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
        9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64
    }

    def __init__(
        self,
        arbitration_id: int,
        data: bytes = b"",
        dlc: Optional[int] = None,
        is_extended_id: bool = False,
        is_remote_frame: bool = False,
        timestamp: Optional[float] = None,
        is_fd: bool = False,
        brs: bool = False,
        source: str = ""
    ):
        self.source = source  # originating node (ECU name or ATTACKER:*), set by the simulator
        self.arbitration_id = arbitration_id & (0x1FFFFFFF if is_extended_id else 0x7FF)
        max_bytes = 64 if is_fd else 8
        self.data = bytes(data[:max_bytes])
        self.is_fd = is_fd
        self.brs = brs

        if dlc is None:
            self.dlc = len(self.data)
        else:
            self.dlc = min(15 if is_fd else 8, max(0, dlc))

        self.is_extended_id = is_extended_id
        self.is_remote_frame = is_remote_frame
        self.timestamp = timestamp if timestamp is not None else time.time()

    def calc_wire_bits(self) -> int:
        """
        Calculates nominal bits on the wire including SOF, arbitration, control,
        data, CRC, ACK, EOF, and standard worst-case bit-stuffing factor.
        For CAN-FD, accounts for 64-byte payload and CRC-17/21 headers.
        """
        if self.is_fd:
            overhead = 75 if self.is_extended_id else 55
            raw_bits = overhead + (len(self.data) * 8)
            return int(raw_bits * 1.15)

        overhead = 67 if self.is_extended_id else 47
        raw_bits = overhead + (self.dlc * 8)
        return int(raw_bits * 1.18)

    @property
    def j1939_fields(self) -> Optional[Dict[str, int]]:
        """
        Decomposes 29-bit Extended ID into SAE J1939 standard fields:
        Priority (3-bit), EDP (1-bit), DP (1-bit), PDU Format (8-bit),
        PDU Specific (8-bit), Source Address (8-bit), and 18-bit PGN.
        """
        if not self.is_extended_id:
            return None

        raw = self.arbitration_id
        priority = (raw >> 26) & 0x07
        edp = (raw >> 25) & 0x01
        dp = (raw >> 24) & 0x01
        pf = (raw >> 16) & 0xFF
        ps = (raw >> 8) & 0xFF
        sa = raw & 0xFF

        # PGN calculation: If PF < 240 (PDU1 format), PS is Destination Address, not in PGN
        # If PF >= 240 (PDU2 format), PS is Group Extension and part of PGN
        if pf < 240:
            pgn = (dp << 16) | (pf << 8)
        else:
            pgn = (dp << 16) | (pf << 8) | ps

        return {
            "priority": priority,
            "edp": edp,
            "dp": dp,
            "pdu_format": pf,
            "pdu_specific": ps,
            "source_address": sa,
            "pgn": pgn,
            "pgn_hex": f"0x{pgn:06X}"
        }

    def parse_isotp_pci(self) -> Dict[str, Any]:
        """
        Parses ISO-TP (ISO 15765-2) Protocol Control Information (PCI) byte.
        Returns PCI frame type (SF, FF, CF, FC) and decoded transport parameters.
        """
        if not self.data:
            return {"type": "EMPTY", "type_name": "EMPTY", "valid": False}

        b0 = self.data[0]
        pci_type = (b0 >> 4) & 0x0F

        if pci_type == 0x0:
            # Single Frame (SF)
            sf_dl = b0 & 0x0F
            return {
                "type": "SF",
                "type_name": "SINGLE_FRAME",
                "length": sf_dl,
                "data_len": sf_dl,
                "uds_payload": self.data[1:1 + sf_dl],
                "valid": True
            }
        elif pci_type == 0x1:
            # First Frame (FF)
            b1 = self.data[1] if len(self.data) > 1 else 0
            total_dl = ((b0 & 0x0F) << 8) | b1
            return {
                "type": "FF",
                "type_name": "FIRST_FRAME",
                "total_length": total_dl,
                "data_len": total_dl,
                "uds_payload": self.data[2:],
                "valid": True
            }
        elif pci_type == 0x2:
            # Consecutive Frame (CF)
            seq_num = b0 & 0x0F
            return {
                "type": "CF",
                "type_name": "CONSECUTIVE_FRAME",
                "sequence_number": seq_num,
                "seq_num": seq_num,
                "uds_payload": self.data[1:],
                "valid": True
            }
        elif pci_type == 0x3:
            # Flow Control (FC)
            flow_status = b0 & 0x0F
            block_size = self.data[1] if len(self.data) > 1 else 0
            st_min = self.data[2] if len(self.data) > 2 else 0
            return {
                "type": "FC",
                "type_name": "FLOW_CONTROL",
                "flow_status": flow_status,
                "block_size": block_size,
                "st_min": st_min,
                "sep_time": st_min,
                "valid": True
            }

        return {"type": "UNKNOWN", "type_name": "UNKNOWN", "valid": False}

    @property
    def hex_id(self) -> str:
        return f"0x{self.arbitration_id:03X}" if not self.is_extended_id else f"0x{self.arbitration_id:08X}"

    @property
    def hex_data(self) -> str:
        return " ".join(f"{b:02X}" for b in self.data)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "arbitration_id": self.arbitration_id,
            "hex_id": self.hex_id,
            "dlc": self.dlc,
            "data_hex": self.hex_data,
            "is_extended": self.is_extended_id,
            "is_fd": self.is_fd,
            "brs": self.brs,
            "source": self.source,
            "timestamp": round(self.timestamp, 6)
        }
        if self.is_extended_id:
            d["j1939"] = self.j1939_fields
        return d

    def __repr__(self) -> str:
        fd_tag = " [FD]" if self.is_fd else ""
        return f"<CANFrame {self.hex_id}{fd_tag} [{self.dlc}] {self.hex_data}>"
