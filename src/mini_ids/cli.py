from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Optional

from .detectors import PortScanDetector
from .sniff import sniff_packets


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mini-IDS: simple TCP port-scan detector")
    p.add_argument(
        "--iface",
        required=True,
        help="Network interface to monitor (e.g., Ethernet, Wi-Fi)",
    )
    p.add_argument(
        "--window", type=int, default=10, help="Rolling time window in seconds"
    )
    p.add_argument(
        "--threshold", type=int, default=20, help="Unique port threshold per source IP"
    )
    p.add_argument("--output", default="alerts.jsonl", help="Path to alerts JSONL file")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    detector = PortScanDetector(window_seconds=args.window, threshold=args.threshold)
    out_path = Path(args.output)

    def on_event(ev):
        alert = detector.process(ev)
        if not alert:
            return

        print(
            "[ALERT] Possible port scan detected\n"
            f"Source IP: {alert.src_ip}\n"
            f"Unique ports contacted: {alert.unique_ports}\n"
            f"Time window: {alert.window_seconds} seconds\n",
            flush=True,
        )

        record = {
            "timestamp": int(time.time()),
            "alert_type": alert.alert_type,
            "src_ip": alert.src_ip,
            "unique_ports": alert.unique_ports,
            "window": alert.window_seconds,
        }
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    sniff_packets(iface=args.iface, on_event=on_event, bpf_filter="tcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
