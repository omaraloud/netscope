"""
NetScope — Entry Point
----------------------
Starts the Flask + SocketIO server, launches the Scapy sniffer thread,
and streams live packet data to the browser dashboard.

Usage:
    sudo python app.py
"""

from __future__ import annotations

import collections
import logging
import sys
import time
from threading import Lock

from gevent import monkey
monkey.patch_all()

from flask import Flask, render_template
from flask_socketio import SocketIO

import config
from parser.packet_parser import parse
from sniffing import capturer
from utils import logger as packet_logger

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("netscope")

# ---------------------------------------------------------------------------
# Flask + SocketIO
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "netscope-dev-secret"

socketio = SocketIO(
    app,
    async_mode="gevent",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)

# ---------------------------------------------------------------------------
# Shared packet buffer and stats state
# ---------------------------------------------------------------------------
_buffer: collections.deque[dict] = collections.deque(maxlen=config.BUFFER_SIZE)
_buffer_lock = Lock()

# Per-protocol packet counts (for the doughnut chart)
_proto_counts: dict[str, int] = collections.defaultdict(int)

# Per-IP packet counts (for top-talkers chart)
_ip_counts: dict[str, int] = collections.defaultdict(int)

# Packets captured in the last second (for packets/sec line chart)
_pps_window: collections.deque[float] = collections.deque()
_pps_lock = Lock()


# ---------------------------------------------------------------------------
# Packet callback — called by the sniffer thread for every raw packet
# ---------------------------------------------------------------------------
def _on_packet(raw_packet) -> None:
    """Parse, buffer, log, and emit a single captured packet."""
    parsed = parse(raw_packet)
    if parsed is None:
        return

    with _buffer_lock:
        _buffer.appendleft(parsed)
        _proto_counts[parsed["protocol"]] += 1
        _ip_counts[parsed["src_ip"]] += 1

    with _pps_lock:
        _pps_window.append(time.monotonic())

    # Log asynchronously
    packet_logger.log_packet(parsed)

    # Emit the packet to all connected browsers
    socketio.emit("packet", parsed)


# ---------------------------------------------------------------------------
# Stats emitter — runs every STATS_INTERVAL seconds inside an eventlet loop
# ---------------------------------------------------------------------------
def _emit_stats() -> None:
    """Periodically compute and broadcast aggregated stats."""
    import gevent
    while True:
        gevent.sleep(config.STATS_INTERVAL)

        now = time.monotonic()
        cutoff = now - 1.0

        with _pps_lock:
            # Drop timestamps older than 1 second
            while _pps_window and _pps_window[0] < cutoff:
                _pps_window.popleft()
            pps = len(_pps_window)

        with _buffer_lock:
            proto_snapshot = dict(_proto_counts)
            # Top 5 talkers by src_ip packet count
            top_talkers = sorted(
                _ip_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]

        socketio.emit("stats", {
            "protocol_counts": proto_snapshot,
            "packets_per_second": pps,
            "top_talkers": [{"ip": ip, "count": cnt} for ip, cnt in top_talkers],
        })


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# SocketIO events
# ---------------------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    log.info("Browser connected.")
    # Send the current buffer so a newly connected client sees recent packets
    with _buffer_lock:
        recent = list(_buffer)
    socketio.emit("history", recent)


@socketio.on("disconnect")
def on_disconnect():
    log.info("Browser disconnected.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log.info("Starting NetScope …")

    # Initialise async logger
    packet_logger.init(config.JSON_LOG_PATH, config.CSV_LOG_PATH)

    # Start Scapy capture in background thread
    capturer.start(
        callback=_on_packet,
        interface=config.INTERFACE,
        bpf_filter=config.CAPTURE_FILTER,
    )

    # Start the stats emitter as a gevent green thread
    socketio.start_background_task(_emit_stats)

    log.info(
        "Dashboard → http://%s:%d",
        config.FLASK_HOST,
        config.FLASK_PORT,
    )

    socketio.run(
        app,
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
    )
