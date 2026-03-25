# NetScope — Product Requirements

**Author:** Omar
**Started:** March 2026
**Status:** v1 complete

---

## What is this?

NetScope is a local network monitor I built to actually see what's happening on my machine in real time. It captures live packets, classifies them by protocol, and shows everything in a browser dashboard that updates as packets come in — no refresh needed.

I wanted something between `tcpdump` (too much raw output, not great for learning) and Wireshark (overkill, heavy). Something I could run, glance at, and immediately understand. Also wanted it as a portfolio piece that shows I understand networking at a practical level — not just theory.

---

## Why I built it

I kept running into situations where I wanted a quick answer to "what is my machine actually doing on the network right now?" and every tool either required too much setup, dumped walls of text, or had no visual component at all.

Also wanted hands-on experience with:
- Raw packet capture (Scapy + BPF)
- Real-time backend streaming (WebSockets)
- Building a dashboard without reaching for a frontend framework

---

## What it does

- Captures live packets from the local network interface
- Classifies each packet as TCP, UDP, ICMP, DNS, HTTP, or Other
- Streams them to a browser dashboard via WebSockets as they arrive
- Shows a live table of recent packets (timestamp, IPs, protocol, size, summary)
- Updates three charts in real time: protocol breakdown, packets/sec, top talkers
- Logs everything to `logs/packets.log.json` and `logs/packets.log.csv` automatically

---

## What it doesn't do (v1)

I intentionally kept scope tight. These are out for now:

- No deep packet inspection — just protocol classification
- No network-wide scanning, only the local machine's interface
- No auth, no multi-user, no remote deployment
- No frontend framework — vanilla JS only, keeping it simple
- No alerting or GeoIP (planning for v2)

---

## Who it's for

Mostly myself and other developers/students who want to see networking concepts working in practice. Also useful as a portfolio project for anyone interviewing in systems, backend, or security roles — it's a concrete demonstration that you understand what happens below the HTTP layer.

---

## Protocol support

| Protocol | How it's detected |
|---|---|
| DNS | UDP port 53 with a DNS layer |
| HTTP | TCP port 80 with raw payload inspection |
| ICMP | ICMP layer present |
| TCP | TCP layer (catch-all after DNS/HTTP/ICMP checks) |
| UDP | UDP layer (catch-all after DNS check) |
| Other | Anything that doesn't match the above |

For each packet I extract: timestamp, source IP, destination IP, protocol, packet length, and a short readable summary (e.g. `DNS Query: github.com`, `HTTP GET /index.html`, `TCP 192.168.1.1:443 → 10.0.0.5:52100`).

---

## Dashboard

Three charts, all updating live:

- **Protocol distribution** — doughnut chart, shows the breakdown of traffic by protocol over the session
- **Packets / second** — line chart, gives a sense of current network activity
- **Top talkers** — horizontal bar, top 5 source IPs by packet count

Plus a scrollable packet table capped at the last 200 packets, newest at the top, with colored protocol badges for quick scanning.

---

## Logging

Every packet gets written to disk automatically:
- `logs/packets.log.json` — one JSON object per line (NDJSON)
- `logs/packets.log.csv` — standard CSV with header

Files are created on first run. Logging is async (background thread + queue) so it doesn't slow down capture.

---

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Packet capture | Scapy | Best Python library for this, good protocol dissection |
| Backend | Flask + Flask-SocketIO | Simple, well-documented, easy to extend |
| Async worker | gevent | Required for SocketIO; eventlet has issues on Python 3.13 |
| Frontend charts | Chart.js (CDN) | No build step, good docs, looks decent |
| UI | Vanilla JS + CSS | Keeping it simple, no framework needed for this scope |

---

## Architecture

```
Scapy (background thread)
    │
    ▼
packet_parser.py  →  structured dict
    │
    ├──▶  logger.py  (async write to JSON + CSV)
    │
    └──▶  app.py (Flask-SocketIO)
              │
              ├──▶  emit("packet")   →  browser table
              └──▶  emit("stats")    →  browser charts (every 1s)
```

The sniffer runs in a daemon thread. Each packet goes through the parser, gets logged in the background, and is emitted over WebSocket. A separate gevent green thread computes and pushes stats every second.

---

## Configuration

Everything lives in `config.py` and can be overridden with environment variables:

- `NETSCOPE_INTERFACE` — which interface to sniff (default: auto)
- `NETSCOPE_FILTER` — BPF filter string (default: none, capture everything)
- `NETSCOPE_BUFFER_SIZE` — rolling packet buffer size (default: 200)
- `NETSCOPE_PORT` — server port (default: 5001, avoids macOS AirPlay on 5000)

---

## Things I want to add later

- **Suspicious port detection** — flag traffic on ports like 4444, 1337, 31337
- **ICMP spike alert** — if ICMP volume spikes suddenly, surface that visually
- **GeoIP** — resolve external IPs to country/city with a local MaxMind DB
- **Filtering from the UI** — let you filter the live table by protocol or IP without restarting
- **CSV export button** — download the current session's packets from the browser
- **Docker support** — run it in a container with `--net=host`

---

## Known constraints

- Needs `sudo` to run — Scapy requires raw socket access
- macOS and Linux only for v1. Windows needs WinPcap/Npcap and Scapy behaves differently
- On high-traffic interfaces the dashboard can feel a bit overwhelmed — the rolling buffer and 1Hz stats throttle help but it's not designed for production-scale capture

---

*This project is for personal/educational use on my own machine. Don't use it on networks you don't own.*
