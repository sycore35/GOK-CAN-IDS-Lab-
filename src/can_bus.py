import os
import sys
import time
import socket
import struct
import re
import collections
from typing import Callable, List, Dict, Optional, Deque, Any
from src.can_frame import CANFrame


def export_candump_log(frames: List[CANFrame], interface: str = "vcan0") -> str:
    """
    Exports frame sequence in standard Linux candump -L log format:
    (timestamp) interface id#data
    """
    lines = []
    for f in frames:
        payload_hex = "".join(f"{b:02X}" for b in f.data)
        id_str = f"{f.arbitration_id:08X}" if f.is_extended_id else f"{f.arbitration_id:03X}"
        lines.append(f"({f.timestamp:.6f}) {interface} {id_str}#{payload_hex}")
    return "\n".join(lines)


def import_candump_log(log_text: str) -> List[CANFrame]:
    """
    Parses standard Linux candump -L format into structured CANFrame objects.
    """
    frames = []
    pattern = re.compile(r"^\((\d+\.\d+)\)\s+([A-Za-z0-9_]+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)$")
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        m = pattern.match(line)
        if m:
            ts = float(m.group(1))
            id_hex = m.group(3)
            data_hex = m.group(4)
            aid = int(id_hex, 16)
            is_extended = len(id_hex) > 3 or aid > 0x7FF
            data_bytes = bytes.fromhex(data_hex) if data_hex else b""
            frames.append(CANFrame(
                arbitration_id=aid,
                data=data_bytes,
                is_extended_id=is_extended,
                timestamp=ts
            ))
    return frames


class VirtualCANBus:
    """
    High-performance in-memory CAN Bus simulator.
    Supports publish/subscribe listener dispatch, rolling bus load calculation,
    and platform-independent message queuing.
    """

    def __init__(self, nominal_bitrate_kbps: int = 500):
        self.nominal_bps = nominal_bitrate_kbps * 1000
        self.listeners: List[Callable[[CANFrame], None]] = []
        self.frame_history: Deque[CANFrame] = collections.deque(maxlen=1000)

        # Rolling bus load tracking (last 500ms)
        self.load_window_sec = 0.5
        self.bit_window: Deque[tuple[float, int]] = collections.deque()

        # Statistics
        self.total_frames_sent = 0
        self.current_bus_load_pct = 0.0

    def subscribe(self, callback: Callable[[CANFrame], None]) -> None:
        """Register a subscriber callback for newly broadcast CAN frames."""
        if callback not in self.listeners:
            self.listeners.append(callback)

    def unsubscribe(self, callback: Callable[[CANFrame], None]) -> None:
        if callback in self.listeners:
            self.listeners.remove(callback)

    def send(self, frame: CANFrame) -> None:
        """Broadcast a CAN frame to all registered listeners."""
        now = frame.timestamp
        wire_bits = frame.calc_wire_bits()

        # Update rolling bit window
        self.bit_window.append((now, wire_bits))
        cutoff = now - self.load_window_sec
        while self.bit_window and self.bit_window[0][0] < cutoff:
            self.bit_window.popleft()

        total_bits_in_window = sum(bits for _, bits in self.bit_window)
        max_possible_bits = self.nominal_bps * self.load_window_sec
        self.current_bus_load_pct = min(100.0, (total_bits_in_window / max_possible_bits) * 100.0)

        self.total_frames_sent += 1
        self.frame_history.append(frame)

        for listener in self.listeners:
            try:
                listener(frame)
            except Exception:
                # Listener exception must never collapse the bus
                pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_frames_sent": self.total_frames_sent,
            "current_bus_load_pct": round(self.current_bus_load_pct, 2),
            "nominal_bitrate_kbps": self.nominal_bps / 1000
        }


class SocketCANTransport:
    """
    Hybrid Transport Layer.
    Attempts kernel SocketCAN connection (e.g. vcan0) on Linux;
    gracefully and deterministically falls back to VirtualCANBus on Windows
    or when vcan0 interface is absent with zero exceptions.
    """

    def __init__(self, interface: str = "vcan0", nominal_bitrate_kbps: int = 500):
        self.interface = interface
        self.nominal_bitrate_kbps = nominal_bitrate_kbps
        self.virtual_bus = VirtualCANBus(nominal_bitrate_kbps=nominal_bitrate_kbps)
        self.socketcan_active = False
        self.sock = None

        if sys.platform == "linux" and hasattr(socket, "AF_CAN") and hasattr(socket, "CAN_RAW"):
            try:
                self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
                self.sock.bind((interface,))
                self.sock.setblocking(False)
                self.socketcan_active = True
            except Exception:
                self.socketcan_active = False
                self.sock = None

    def subscribe(self, callback: Callable[[CANFrame], None]) -> None:
        self.virtual_bus.subscribe(callback)

    def unsubscribe(self, callback: Callable[[CANFrame], None]) -> None:
        self.virtual_bus.unsubscribe(callback)

    def send(self, frame: CANFrame) -> None:
        if self.socketcan_active and self.sock is not None:
            try:
                can_id = frame.arbitration_id
                if frame.is_extended_id:
                    can_id |= 0x80000000  # CAN_EFF_FLAG
                can_pkt = struct.pack("=IB3x8s", can_id, frame.dlc, frame.data.ljust(8, b"\x00"))
                self.sock.send(can_pkt)
            except Exception:
                pass
        self.virtual_bus.send(frame)

    def get_stats(self) -> Dict[str, Any]:
        stats = self.virtual_bus.get_stats()
        stats["socketcan_active"] = self.socketcan_active
        stats["interface"] = self.interface
        stats["fallback_mode"] = "VIRTUAL_IN_MEMORY" if not self.socketcan_active else "KERNEL_SOCKETCAN"
        return stats

    @property
    def frame_history(self) -> Deque[CANFrame]:
        return self.virtual_bus.frame_history

    @property
    def total_frames_sent(self) -> int:
        return self.virtual_bus.total_frames_sent

    @property
    def current_bus_load_pct(self) -> float:
        return self.virtual_bus.current_bus_load_pct
