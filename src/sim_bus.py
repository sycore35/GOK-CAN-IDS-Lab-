"""Advanced CAN bus simulator: discrete-event, virtual-time, with real arbitration.

* Nodes (ECUs / attackers) place frames in transmit mailboxes (bounded -> overflow drops).
* Whenever the bus is idle the pending frame with the numerically lowest identifier wins
  arbitration (wire-AND dominance); losers wait and are counted (`arb_losses`).
* A frame occupies the bus for its wire time (classic: bits / bitrate, FD: nominal+data phase),
  so bus load, queueing latency and starvation under flooding are *emergent*, not scripted.
* Time is virtual (seconds); the caller advances it. Everything is in memory.
"""
import collections
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

from src.can_frame import CANFrame
from src.canfd import estimate_frame_time


@dataclass
class Delivered:
    frame: CANFrame
    node: str
    ready_t: float       # when the node queued it
    start_t: float       # when it won arbitration and started transmitting
    end_t: float         # when it finished (== frame.timestamp)
    arb_losses: int      # how many arbitrations it lost while waiting
    bus_load_pct: float  # rolling load at delivery

    @property
    def latency_s(self) -> float:
        return self.end_t - self.ready_t


@dataclass(eq=False)          # identity semantics: two identical frames are still two different transmissions
class _Pending:
    frame: CANFrame
    node: str
    ready_t: float
    seq: int
    losses: int = 0
    key: tuple = ()            # arbitration key, computed once at enqueue


class SimBus:
    def __init__(self, bitrate_bps: int = 500_000, data_bitrate_bps: int = 2_000_000,
                 load_window_s: float = 0.5, history: int = 2000):
        self.bitrate = bitrate_bps
        self.data_bitrate = data_bitrate_bps
        self.load_window = load_window_s
        self.clock = 0.0            # end of the last advance() horizon
        self.bus_free = 0.0         # instant the bus becomes idle
        self._pending: List[_Pending] = []
        self._node_pending: Dict[str, int] = collections.defaultdict(int)   # O(1) mailbox check
        self._seq = 0
        self.node_limits: Dict[str, int] = {}
        self.node_stats: Dict[str, Dict[str, float]] = {}
        self._busy: Deque = collections.deque()      # (end_t, duration)
        self._busy_sum = 0.0
        self.history: Deque[Delivered] = collections.deque(maxlen=history)
        self.total_frames = 0
        self.total_dropped = 0
        self.total_arb_losses = 0
        self.id_counts: Dict[int, int] = collections.defaultdict(int)
        self._lat: Deque[float] = collections.deque(maxlen=500)
        self.load_pct = 0.0
        self.peak_load_pct = 0.0

    def attach(self, name: str, mailbox_size: int = 16) -> None:
        self.node_limits[name] = mailbox_size
        self.node_stats.setdefault(name, {"tx": 0, "dropped": 0, "arb_losses": 0, "max_latency_ms": 0.0})

    def detach(self, name: str) -> None:
        self._pending = [p for p in self._pending if p.node != name]
        self._node_pending.pop(name, None)

    def enqueue(self, node: str, frame: CANFrame, ready_t: float) -> bool:
        if node not in self.node_limits:
            self.attach(node)
        frame.source = frame.source or node
        if self._node_pending[node] >= self.node_limits[node]:
            self.node_stats[node]["dropped"] += 1
            self.total_dropped += 1
            return False
        self._seq += 1
        p = _Pending(frame, node, ready_t, self._seq)
        p.key = self._arb_key(p)
        self._pending.append(p)
        self._node_pending[node] += 1
        return True

    def frame_duration(self, frame: CANFrame) -> float:
        if frame.is_fd:
            return estimate_frame_time(len(frame.data), frame.brs, frame.is_extended_id,
                                       self.bitrate, self.data_bitrate)
        return frame.calc_wire_bits() / self.bitrate

    def _arb_key(self, p: _Pending):
        f = p.frame
        # extended ids lose against standard ids with identical base id (IDE bit is recessive)
        return ((f.arbitration_id >> 18) if f.is_extended_id else f.arbitration_id,
                1 if f.is_extended_id else 0, f.arbitration_id, p.seq)

    def _update_load(self, now: float) -> None:
        cutoff = now - self.load_window
        while self._busy and self._busy[0][0] < cutoff:
            self._busy_sum -= self._busy.popleft()[1]
        self.load_pct = min(100.0, 100.0 * max(0.0, self._busy_sum) / self.load_window)
        self.peak_load_pct = max(self.peak_load_pct, self.load_pct)

    def advance(self, t_end: float) -> List[Delivered]:
        """Simulate the bus up to virtual time t_end; return frames completed in the interval."""
        out: List[Delivered] = []
        self.bus_free = max(self.bus_free, self.clock)
        inf = float("inf")
        while True:
            # one pass: ready set, arbitration winner (lowest key) and the next future ready time
            bf, ready, winner, wkey, widx, nxt = self.bus_free, [], None, None, -1, inf
            for i, p in enumerate(self._pending):
                if p.ready_t <= bf:
                    ready.append(p)
                    if wkey is None or p.key < wkey:
                        winner, wkey, widx = p, p.key, i
                elif p.ready_t < nxt:
                    nxt = p.ready_t
            if winner is None:
                if nxt >= t_end:
                    break
                self.bus_free = nxt
                continue
            if bf >= t_end:
                break
            if len(ready) > 1:
                ns = self.node_stats
                for p in ready:
                    if p is not winner:
                        p.losses += 1
                        ns[p.node]["arb_losses"] += 1
                self.total_arb_losses += len(ready) - 1
            del self._pending[widx]
            self._node_pending[winner.node] -= 1
            start = self.bus_free
            dur = self.frame_duration(winner.frame)
            end = start + dur
            self.bus_free = end
            winner.frame.timestamp = end
            self._busy.append((end, dur))
            self._busy_sum += dur
            self._update_load(end)
            d = Delivered(winner.frame, winner.node, winner.ready_t, start, end, winner.losses, self.load_pct)
            self.history.append(d)
            out.append(d)
            self.total_frames += 1
            self.id_counts[winner.frame.arbitration_id] += 1
            st = self.node_stats[winner.node]
            st["tx"] += 1
            st["max_latency_ms"] = max(st["max_latency_ms"], d.latency_s * 1000)
            self._lat.append(d.latency_s)
        self.clock = max(self.clock, t_end)
        self._update_load(t_end)
        return out

    def stats(self) -> Dict[str, object]:
        lat = list(self._lat)
        return {
            "bitrate_kbps": self.bitrate / 1000,
            "load_pct": round(self.load_pct, 2),
            "peak_load_pct": round(self.peak_load_pct, 2),
            "total_frames": self.total_frames,
            "dropped_frames": self.total_dropped,
            "arbitration_losses": self.total_arb_losses,
            "pending": len(self._pending),
            "avg_latency_us": round(1e6 * sum(lat) / len(lat), 1) if lat else 0.0,
            "max_latency_us": round(1e6 * max(lat), 1) if lat else 0.0,
            "nodes": {n: {k: (round(v, 3) if isinstance(v, float) else v) for k, v in s.items()}
                      for n, s in self.node_stats.items()},
        }
