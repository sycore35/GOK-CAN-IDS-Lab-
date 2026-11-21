"""Optional SocketCAN (Linux vcan0 / can0) backend via python-can.

TX: simulated frames are mirrored to the interface. RX: frames read from the interface are tagged
`SOCKETCAN:<channel>` and injected into the simulated bus, so the IDS, behaviour analysis and gateway
model inspect them like any other frame. Received frames are never mirrored back (no echo loops).

On macOS/Windows, or on Linux without python-can / without the interface, `status()` reports
"unavailable" with a reason and the lab keeps running on the in-memory simulator.
"""
import sys
from typing import Any, Callable, Dict, List, Optional

from src.can_frame import CANFrame

SETUP_HINT = "sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0"


def _default_loader():
    import can  # type: ignore
    return can


class SocketCANBackend:
    def __init__(self, channel: str = "vcan0", platform: Optional[str] = None,
                 loader: Optional[Callable[[], Any]] = None):
        self.channel = channel
        self.platform = platform or sys.platform
        self._loader = loader or _default_loader
        self._can = None
        self._bus = None
        self.available = False
        self.reason = "not probed"
        self.python_can_installed = False
        self.frames_mirrored = 0
        self.frames_received = 0
        self.rx_enabled = True
        self.probe()

    def probe(self) -> Dict[str, Any]:
        self.available, self._bus = False, None
        if not self.platform.startswith("linux"):
            self.reason = f"SocketCAN is Linux-only (platform={self.platform}); using the in-memory simulator"
            return self.status()
        try:
            self._can = self._loader()
            self.python_can_installed = True
        except Exception as exc:
            self.reason = f"python-can is not installed ({type(exc).__name__}); pip install python-can"
            return self.status()
        try:
            self._bus = self._can.Bus(interface="socketcan", channel=self.channel)
            self.available, self.reason = True, f"connected to {self.channel}"
        except Exception as exc:
            self.reason = f"interface {self.channel} unavailable: {exc}. Create it with: {SETUP_HINT}"
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available, "backend": "python-can/socketcan" if self.available else "simulator",
            "channel": self.channel, "platform": self.platform, "python_can_installed": self.python_can_installed,
            "reason": self.reason, "fallback": None if self.available else "simulator",
            "frames_mirrored": self.frames_mirrored, "frames_received": self.frames_received,
            "rx_enabled": self.rx_enabled, "rx_source": self.rx_source, "setup_hint": SETUP_HINT,
        }

    @property
    def rx_source(self) -> str:
        return f"SOCKETCAN:{self.channel}"

    def set_rx(self, enabled: bool) -> Dict[str, Any]:
        self.rx_enabled = bool(enabled)
        return self.status()

    def poll(self, max_frames: int = 200) -> List[CANFrame]:
        """Non-blocking read of up to `max_frames` frames from the interface (error frames are skipped)."""
        if not (self.available and self.rx_enabled) or self._bus is None:
            return []
        out: List[CANFrame] = []
        while len(out) < max_frames:
            try:
                msg = self._bus.recv(timeout=0)
            except Exception as exc:
                self.reason = f"receive failed: {exc}"
                break
            if msg is None:
                break
            if getattr(msg, "is_error_frame", False):
                continue
            out.append(CANFrame(msg.arbitration_id, bytes(msg.data), is_extended_id=bool(msg.is_extended_id),
                                is_remote_frame=bool(getattr(msg, "is_remote_frame", False)),
                                is_fd=bool(getattr(msg, "is_fd", False)), brs=bool(getattr(msg, "bitrate_switch", False)),
                                source=self.rx_source))
        self.frames_received += len(out)
        return out

    def mirror(self, frame: CANFrame) -> bool:
        """Best-effort TX of a simulated frame to the real interface. Frames that came from it are not echoed."""
        if not self.available or self._bus is None or frame.source.startswith("SOCKETCAN:"):
            return False
        try:
            msg = self._can.Message(arbitration_id=frame.arbitration_id, data=frame.data,
                                    is_extended_id=frame.is_extended_id, is_fd=frame.is_fd,
                                    bitrate_switch=frame.brs)
            self._bus.send(msg)
            self.frames_mirrored += 1
            return True
        except Exception as exc:
            self.reason = f"send failed: {exc}"
            return False

    def close(self) -> None:
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
        self._bus, self.available = None, False
