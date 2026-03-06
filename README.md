# Mini-IDS
Mini Network Intrusion Detection System

Mini-IDS is a lightweight Python-based intrusion detection tool that monitors live network traffic and detects suspicious behavior such as TCP port scanning.

This project demonstrates core intrusion detection concepts including packet capture, event normalization, rolling time-window analysis, and rule-based alerting.

---

## Features

- Live packet sniffing using Scapy
- TCP SYN-based port scan detection
- Rolling time-window tracking
- Configurable detection thresholds
- JSON alert logging
- Command-line interface

---

## Detection Logic

Mini-IDS captures TCP packets and monitors SYN flags to identify potential scanning behavior.

For each source IP address, the system tracks how many unique destination ports are contacted within a configurable time window.

If the number exceeds a defined threshold, an alert is generated. A cooldown prevents repeated alerts for the same source IP within the same time window.

**Default configuration:**

- Time window: 10 seconds
- Port threshold: 20 unique ports
- Detection type: TCP SYN scan

---

## Project Structure

```
mini-ids/
├── src/
│   └── mini_ids/
│       ├── sniff.py
│       ├── detectors.py
│       ├── store.py
│       └── cli.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.10+
- Scapy
- **Windows:** [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled
- **Linux/macOS:** Root privileges (`sudo`)

---

## Setup

**1. Clone the repository**

```
git clone <repo-url>
cd mini-ids
```

**2. Create and activate a virtual environment**

Windows:
```
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:
```
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**

```
pip install -r requirements.txt
```

---

## Finding Your Network Interface

Before running Mini-IDS, find the name of the interface you want to monitor:

```python
from scapy.all import get_if_list
print(get_if_list())
```

Common interfaces:
- **Windows Wi-Fi:** `\Device\NPF_{GUID}` (find your GUID using the snippet above)
- **Windows loopback:** `\Device\NPF_Loopback`
- **Linux:** `eth0`, `wlan0`, `lo`
- **macOS:** `en0`, `lo0`

---

## Usage

Run from the `src/` directory (Windows requires Administrator, Linux/macOS requires `sudo`):

```
cd src
python -m mini_ids.cli --iface "INTERFACE_NAME"
```

Custom configuration:

```
python -m mini_ids.cli --iface "INTERFACE_NAME" --window 15 --threshold 30 --output alerts.jsonl
```

### Arguments

| Argument       | Description                          | Default        |
|---------------|--------------------------------------|----------------|
| `--iface`     | Network interface to monitor         | Required       |
| `--window`    | Time window in seconds               | 10             |
| `--threshold` | Unique port threshold per source IP  | 20             |
| `--output`    | Path to write alerts to              | alerts.jsonl   |

---

## Example Alert

Console output:

```
[ALERT] Possible port scan detected
Source IP: 127.0.0.1
Unique ports contacted: 20
Time window: 10 seconds
```

JSON output (`alerts.jsonl`):

```json
{
  "timestamp": 1700000000,
  "alert_type": "PORT_SCAN",
  "src_ip": "127.0.0.1",
  "unique_ports": 20,
  "window": 10
}
```

---

## Testing

You can simulate a port scan using [nmap](https://nmap.org/).

**Single-machine test (loopback):**

Start Mini-IDS on the loopback interface:

```
python -m mini_ids.cli --iface "\Device\NPF_Loopback"   # Windows
python -m mini_ids.cli --iface lo                        # Linux/macOS
```

Then in a second terminal, scan localhost:

```
nmap -p 1-1000 127.0.0.1
```

An alert should trigger once 20 unique ports are contacted within 10 seconds.

---

## Limitations

- Rule-based detection only (no machine learning)
- No deep packet inspection
- TCP-focused detection
- Packet timestamps use the system clock (`time.time()`) rather than the wire arrival time, so there may be minor drift under high traffic
- Intended for educational and local monitoring use

---

## Disclaimer

This tool is intended for educational purposes only.
Do not use it to monitor networks without proper authorization.
Always ensure you have explicit permission before monitoring any network traffic.
