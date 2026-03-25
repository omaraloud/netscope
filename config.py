"""
NetScope Configuration
----------------------
All runtime settings are controlled here. Override any value via environment variable.
"""

import os

# ---------------------------------------------------------------------------
# Network capture settings
# ---------------------------------------------------------------------------

# Network interface to sniff on.  None = let Scapy pick the default interface.
# Override: NETSCOPE_INTERFACE=en0 python app.py
INTERFACE: str | None = os.getenv("NETSCOPE_INTERFACE", None)

# Optional BPF filter string passed directly to Scapy's sniff().
# Example: "tcp port 80 or udp port 53"
CAPTURE_FILTER: str | None = os.getenv("NETSCOPE_FILTER", None)

# ---------------------------------------------------------------------------
# In-memory rolling buffer
# ---------------------------------------------------------------------------

# Maximum number of packets kept in the server-side ring buffer.
BUFFER_SIZE: int = int(os.getenv("NETSCOPE_BUFFER_SIZE", 200))

# ---------------------------------------------------------------------------
# Stats emission
# ---------------------------------------------------------------------------

# How often (seconds) the server pushes aggregated stats to the dashboard.
STATS_INTERVAL: float = float(os.getenv("NETSCOPE_STATS_INTERVAL", 1.0))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR: str = os.getenv("NETSCOPE_LOG_DIR", "logs")
JSON_LOG_PATH: str = os.path.join(LOG_DIR, "packets.log.json")
CSV_LOG_PATH: str = os.path.join(LOG_DIR, "packets.log.csv")

# ---------------------------------------------------------------------------
# Flask / SocketIO server
# ---------------------------------------------------------------------------

FLASK_HOST: str = os.getenv("NETSCOPE_HOST", "127.0.0.1")
FLASK_PORT: int = int(os.getenv("NETSCOPE_PORT", 5001))
FLASK_DEBUG: bool = os.getenv("NETSCOPE_DEBUG", "false").lower() == "true"
