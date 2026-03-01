from __future__ import annotations

import time
from typing import Callable

from scapy.all import IP, TCP, sniff  # type: ignore

from .detectors import PacketEvent


def sniff_packets(
    iface: str,
    on_event: Callable[[PacketEvent], None],
    bpf_filter: str = "tcp",
) -> None:
    """
    Sniff TCP/IP packets from an interface and emit normalized PacketEvent objects.
    """

    def handle(pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        ev = PacketEvent(
            timestamp=time.time(),
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            dst_port=int(tcp.dport),
            proto="TCP",
            tcp_flags=str(tcp.flags),
        )
        on_event(ev)

    sniff(iface=iface, prn=handle, filter=bpf_filter, store=False)
