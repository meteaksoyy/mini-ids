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

If the number exceeds a defined threshold, an alert is generated.

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
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.10+
- Scapy
- Root/Administrator privileges (required for packet sniffing)

Install dependencies:

```
pip install -r requirements.txt
```

---

## Usage

Basic execution:

```
python -m mini_ids.cli --iface eth0
```

Custom configuration:

```
sudo python -m mini_ids.cli --iface eth0 --window 15 --threshold 30 --output alerts.jsonl
```

### Arguments

| Argument       | Description                          | Default |
|---------------|--------------------------------------|----------|
| `--iface`     | Network interface to monitor         | Required |
| `--window`    | Time window in seconds               | 10       |
| `--threshold` | Unique port threshold                | 20       |
| `--output`    | JSON file to write alerts to         | alerts.jsonl |

---

## Example Alert

Console output:

```
[ALERT] Possible port scan detected
Source IP: 192.168.1.15
Unique ports contacted: 45
Time window: 10 seconds
```

JSON output (`alerts.jsonl`):

```json
{
  "timestamp": 1700000000,
  "alert_type": "PORT_SCAN",
  "src_ip": "192.168.1.15",
  "unique_ports": 45,
  "window": 10
}
```

---

## Testing

You can simulate a port scan using `nmap`:

```
nmap -p 1-1000 <target_ip>
```

If the threshold is exceeded within the configured time window, an alert should be triggered.

---

## Limitations

- Rule-based detection only (no machine learning)
- No deep packet inspection
- TCP-focused detection
- Intended for educational and local monitoring use

---

## Disclaimer

This tool is intended for educational purposes only.  
Do not use it to monitor networks without proper authorization.
