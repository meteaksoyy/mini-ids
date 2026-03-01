from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Set


@dataclass
class PortScanAlert:
    timestamp: float
    src_ip: str
    unique_ports: int
    window_seconds: int
    alert_type: str = "PORT_SCAN"


class RollingPortWindow:
    """
    Tracks unique destination ports contacted by each source IP over a rolling time window.
    """

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = int(window_seconds)
        self._events: Dict[str, Deque[tuple[float, int]]] = defaultdict(deque)

    def add(self, src_ip: str, dst_port: int, ts: float | None = None) -> None:
        if ts is None:
            ts = time.time()
        self._events[src_ip].append((ts, int(dst_port)))
        self._prune(src_ip, now=ts)

    def unique_ports(self, src_ip: str, now: float | None = None) -> Set[int]:
        if now is None:
            now = time.time()
        self._prune(src_ip, now=now)
        return {p for _, p in self._events.get(src_ip, deque())}

    def _prune(self, src_ip: str, now: float) -> None:
        q = self._events.get(src_ip)
        if not q:
            return
        cutoff = now - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            self._events.pop(src_ip, None)
