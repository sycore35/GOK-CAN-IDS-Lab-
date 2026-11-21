"""CAN FD extension (ISO 11898-1:2015) — separate from the classic CAN 2.0 `CANFrame` path.

Provides the FD length/DLC mapping, a strict `CANFDFrame` (up to 64 bytes, BRS/ESI flags), a
wire-time *estimate* with a faster data phase when BRS is set, and a conversion to the bus frame
type so FD traffic can run on the simulated bus and through the IDS.
"""
import math
import time
from dataclasses import dataclass, field
from typing import Dict, Any

from src.can_frame import CANFrame

# DLC code -> payload bytes (codes 0..8 are identical to classic CAN)
FD_DLC_TO_LEN = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
                 9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64}
FD_LEN_TO_DLC = {v: k for k, v in FD_DLC_TO_LEN.items()}
FD_VALID_LENGTHS = tuple(sorted(FD_LEN_TO_DLC))


def dlc_to_len(dlc: int) -> int:
    if dlc not in FD_DLC_TO_LEN:
        raise ValueError(f"CAN FD DLC code must be 0..15, got {dlc}")
    return FD_DLC_TO_LEN[dlc]


def len_to_dlc(length: int) -> int:
    """DLC code for an exact valid FD payload length (0-8, 12, 16, 20, 24, 32, 48, 64)."""
    if length not in FD_LEN_TO_DLC:
        raise ValueError(f"{length} is not a valid CAN FD payload length; valid: {FD_VALID_LENGTHS}")
    return FD_LEN_TO_DLC[length]


def next_valid_length(length: int) -> int:
    """Smallest valid FD payload length >= `length` (what padding rounds up to)."""
    if length < 0 or length > 64:
        raise ValueError("CAN FD payload must be 0..64 bytes")
    return next(v for v in FD_VALID_LENGTHS if v >= length)


def estimate_frame_time(payload_len: int, brs: bool, extended: bool = False,
                        nominal_bps: int = 500_000, data_bps: int = 2_000_000) -> float:
    """Estimated on-wire time (s) of one CAN FD frame. Documented approximation, not a bit-exact model:
    arbitration phase at the nominal rate; with BRS the control tail, data, stuff count and CRC run at
    the data rate; worst-case dynamic stuffing (1 per 5 bits) on the data field."""
    arb_bits = 35 if extended else 16                      # SOF..res (nominal)
    crc_len = 17 if payload_len <= 16 else 21
    data_field = 6 + 8 * payload_len                       # BRS,ESI,DLC + data
    stuffed = data_field + math.ceil(data_field / 5)
    fixed = 4 + crc_len + math.ceil(crc_len / 4) + 1       # stuff count, CRC (fixed stuffing), CRC delimiter
    tail_bits = 2 + 7 + 3                                  # ACK, EOF, IFS (nominal)
    data_rate = data_bps if brs else nominal_bps
    return (arb_bits + tail_bits) / nominal_bps + (stuffed + fixed) / data_rate


@dataclass
class CANFDFrame:
    arbitration_id: int
    data: bytes = b""
    brs: bool = False
    esi: bool = False
    is_extended_id: bool = False
    timestamp: float = field(default_factory=time.time)
    source: str = ""

    def __post_init__(self):
        self.data = bytes(self.data)
        if len(self.data) not in FD_LEN_TO_DLC:
            raise ValueError(
                f"CAN FD payload length {len(self.data)} invalid; use {FD_VALID_LENGTHS} "
                f"(CANFDFrame.padded() rounds up)")
        mask = 0x1FFFFFFF if self.is_extended_id else 0x7FF
        if not 0 <= self.arbitration_id <= mask:
            raise ValueError(f"arbitration id {self.arbitration_id:#x} out of range for "
                             f"{'29' if self.is_extended_id else '11'}-bit identifier")

    @classmethod
    def padded(cls, arbitration_id: int, data: bytes, pad: int = 0x00, **kw) -> "CANFDFrame":
        data = bytes(data)
        if len(data) > 64:
            raise ValueError("CAN FD payload is limited to 64 bytes")
        return cls(arbitration_id, data + bytes([pad]) * (next_valid_length(len(data)) - len(data)), **kw)

    @property
    def dlc(self) -> int:
        return len_to_dlc(len(self.data))

    def wire_time(self, nominal_bps: int = 500_000, data_bps: int = 2_000_000) -> float:
        return estimate_frame_time(len(self.data), self.brs, self.is_extended_id, nominal_bps, data_bps)

    def to_can_frame(self) -> CANFrame:
        return CANFrame(self.arbitration_id, self.data, dlc=self.dlc, is_extended_id=self.is_extended_id,
                        timestamp=self.timestamp, is_fd=True, brs=self.brs, source=self.source)

    def describe(self, nominal_bps: int = 500_000, data_bps: int = 2_000_000) -> Dict[str, Any]:
        n = len(self.data)
        classic_frames = max(1, math.ceil(n / 8))
        classic_t = classic_frames * CANFrame(self.arbitration_id, b"\0" * 8).calc_wire_bits() / nominal_bps
        t = self.wire_time(nominal_bps, data_bps)
        return {
            "arbitration_id": self.arbitration_id, "payload_len": n, "dlc_code": self.dlc,
            "brs": self.brs, "esi": self.esi, "fd_time_us": round(t * 1e6, 1),
            "classic_equivalent_frames": classic_frames, "classic_time_us": round(classic_t * 1e6, 1),
            "speedup_vs_classic": round(classic_t / t, 2), "payload_hex": self.data.hex().upper(),
            "note": "wire time is an estimate (worst-case stuffing), not a bit-exact controller model",
        }
