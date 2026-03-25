# NetScope

**Real-time network packet sniffer and traffic visualizer**

NetScope captures live packets from your local network interface, classifies them by protocol, and streams everything to a browser dashboard — updating in real time without a page refresh.

---

## Screenshot

> *(Dashboard screenshot — run the app and capture your own)*

---

## Features

- Live packet capture via Scapy (TCP, UDP, ICMP, DNS, HTTP, Other)
- Browser dashboard with a rolling live packet table (200-packet window)
- Three live charts: protocol distribution, packets/second, top talkers
- JSON + CSV logging of every captured packet to the `logs/` directory
- Dark mode UI — plain HTML/CSS, no framework
- Single-command startup

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| macOS or Linux | (Windows not supported in v1) |
| Root / admin privileges | Required for raw packet capture |

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/netscope.git
cd netscope
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
sudo python app.py
```

> Packet capture requires root privileges. Without `sudo` the sniffer thread will exit with a clear error message.

### 5. Open the dashboard

Navigate to **http://127.0.0.1:5000** in your browser.

---

## Configuration

All settings live in `config.py` and can be overridden via environment variables:

| Variable | Default | Description |
|---|---|---|
| `NETSCOPE_INTERFACE` | *(auto)* | Network interface to sniff (e.g. `en0`, `eth0`) |
| `NETSCOPE_FILTER` | *(none)* | BPF filter string (e.g. `tcp port 443`) |
| `NETSCOPE_BUFFER_SIZE` | `200` | Max packets kept in memory |
| `NETSCOPE_STATS_INTERVAL` | `1.0` | Seconds between stats pushes |
| `NETSCOPE_LOG_DIR` | `logs` | Directory for log files |
| `NETSCOPE_HOST` | `127.0.0.1` | Flask host |
| `NETSCOPE_PORT` | `5000` | Flask port |

**Example** — capture only DNS traffic on a specific interface:

```bash
sudo NETSCOPE_INTERFACE=en0 NETSCOPE_FILTER="udp port 53" python app.py
```

---

## Project Structure

```
netscope/
├── app.py                  # Flask + SocketIO entry point
├── config.py               # All runtime settings
│
├── sniffing/
│   └── capturer.py         # Scapy sniffer (background thread)
│
├── parser/
│   └── packet_parser.py    # Protocol detection & field extraction
│
├── utils/
│   └── logger.py           # Async JSON + CSV log writer
│
├── static/
│   ├── css/style.css       # Dark mode dashboard styles
│   └── js/dashboard.js     # SocketIO client + Chart.js
│
├── templates/
│   └── index.html          # Dashboard layout
│
├── logs/                   # Auto-created at runtime
│   ├── packets.log.json    # NDJSON — one packet per line
│   └── packets.log.csv
│
├── requirements.txt
├── .gitignore
└── PRD.md
```

---

## Log Files

Both log files are created automatically in the `logs/` directory on first run.

**`packets.log.json`** — newline-delimited JSON (NDJSON), one object per line:
```json
{"timestamp": "2026-03-25T14:01:22.441", "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "protocol": "DNS", "length": 74, "info": "DNS Query: google.com"}
```

**`packets.log.csv`** — standard CSV with header row:
```
timestamp,src_ip,dst_ip,protocol,length,info
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `PermissionError` / no packets captured | Run with `sudo python app.py` |
| Dashboard shows "Connecting…" forever | Check that the Flask server started without errors in the terminal |
| No packets appear after connecting | Try pinging a host (`ping google.com`) to generate traffic |
| Scapy can't find an interface | Set `NETSCOPE_INTERFACE=en0` (or your actual interface name) |
| High CPU on fast interfaces | Add a BPF filter (`NETSCOPE_FILTER="tcp port 80"`) to reduce capture volume |

---

## Planned Features (v2+)

- Suspicious port alerts (e.g. 4444, 31337)
- ICMP spike detection
- GeoIP lookup via MaxMind
- Deeper HTTP header inspection
- Packet filtering from the dashboard UI
- CSV export button
- Docker support (`--net=host`)

---

## Disclaimer

NetScope is a portfolio / educational tool intended for use **on your own machine and network only**.
Do not use it to capture traffic on networks you do not own or have explicit permission to monitor.

---

## License

MIT
