"""
NetScope — Packet Logger
------------------------
Writes structured packet dicts to JSON and CSV log files in a non-blocking
way using a background queue so the capture thread is never held waiting
on disk I/O.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import queue
import threading
from typing import Any

log = logging.getLogger(__name__)

# Fields written to both JSON and CSV (order matters for CSV header).
_FIELDS = ["timestamp", "src_ip", "dst_ip", "protocol", "length", "info"]

# Internal write queue — packets are enqueued by the capture thread and
# drained by a dedicated writer thread.
_write_queue: queue.Queue[dict | None] = queue.Queue()
_writer_thread: threading.Thread | None = None


def init(json_path: str, csv_path: str) -> None:
    """
    Initialise the logger.  Creates the log directory and files if needed,
    then starts the background writer thread.  Safe to call more than once
    (idempotent after the first call).
    """
    global _writer_thread

    _ensure_files(json_path, csv_path)

    if _writer_thread is None or not _writer_thread.is_alive():
        _writer_thread = threading.Thread(
            target=_writer_loop,
            args=(json_path, csv_path),
            daemon=True,
            name="netscope-logger",
        )
        _writer_thread.start()
        log.info("Logger thread started — json=%s  csv=%s", json_path, csv_path)


def log_packet(packet: dict) -> None:
    """
    Enqueue a packet for async logging.  Returns immediately; disk I/O
    happens in the background writer thread.
    """
    _write_queue.put_nowait(packet)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_files(json_path: str, csv_path: str) -> None:
    """Create the log directory and seed the CSV header if the file is new."""
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    # Touch the JSON file so it exists even if no packets arrive yet.
    if not os.path.exists(json_path):
        with open(json_path, "w") as f:
            pass  # empty file; we append one JSON object per line (NDJSON)

    # Write CSV header only when creating a fresh file.
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_FIELDS)
            writer.writeheader()


def _writer_loop(json_path: str, csv_path: str) -> None:
    """Drain the write queue and flush packets to disk."""
    json_file = open(json_path, "a", buffering=1)   # line-buffered
    csv_file  = open(csv_path,  "a", newline="", buffering=1)
    csv_writer = csv.DictWriter(csv_file, fieldnames=_FIELDS, extrasaction="ignore")

    try:
        while True:
            packet: dict | None = _write_queue.get()
            if packet is None:          # sentinel value → clean shutdown
                break
            _write_json(json_file, packet)
            _write_csv(csv_writer, csv_file, packet)
    except Exception as exc:
        log.error("Logger writer loop crashed: %s", exc, exc_info=True)
    finally:
        json_file.close()
        csv_file.close()


def _write_json(file: Any, packet: dict) -> None:
    try:
        file.write(json.dumps(packet) + "\n")
    except Exception as exc:
        log.warning("JSON write error: %s", exc)


def _write_csv(writer: csv.DictWriter, file: Any, packet: dict) -> None:
    try:
        writer.writerow({k: packet.get(k, "") for k in _FIELDS})
        file.flush()
    except Exception as exc:
        log.warning("CSV write error: %s", exc)
