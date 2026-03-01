from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .store import PortScanAlert, RollingPortWindow


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    tcp_flags: str  # e.g., "S" for SYN


class PortScanDetector:
    """
    Alerts if a source IP contacts >= threshold unique destination ports within window_seconds.
    """

    def __init__(self, window_seconds: int = 10, threshold: int = 20) -> None:
        self.window_seconds = int(window_seconds)
        self.threshold = int(threshold)
        self._window = RollingPortWindow(self.window_seconds)
        self._last_alert: dict[str, float] = {}

    def process(self, ev: PacketEvent) -> Optional[PortScanAlert]:
        # Basic scan heuristic: SYN packets (exclude SYN-ACK)
        if ev.proto != "TCP":
            return None
        if "S" not in ev.tcp_flags:
            return None
        if "A" in ev.tcp_flags:
            return None

        self._window.add(ev.src_ip, ev.dst_port, ts=ev.timestamp)
        unique_ports = len(self._window.unique_ports(ev.src_ip, now=ev.timestamp))

        if unique_ports < self.threshold:
            return None

        # Cooldown to avoid repeated alerts for same src within a window
        last = self._last_alert.get(ev.src_ip, 0.0)
        if ev.timestamp - last < self.window_seconds:
            return None

        self._last_alert[ev.src_ip] = ev.timestamp
        return PortScanAlert(
            timestamp=time.time(),
            src_ip=ev.src_ip,
            unique_ports=unique_ports,
            window_seconds=self.window_seconds,
        )
