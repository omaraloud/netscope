"""
NetScope — Packet Capturer
--------------------------
Runs Scapy's sniffer in a dedicated background daemon thread.
Each captured packet is passed to a callback (supplied by app.py).
"""

from __future__ import annotations

import threading
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)


def start(
    callback: Callable[[Any], None],
    interface: str | None = None,
    bpf_filter: str | None = None,
) -> threading.Thread:
    """
    Spawn a background thread that runs Scapy's sniff() forever.

    Args:
        callback:   Called with each raw Scapy packet as it arrives.
        interface:  Network interface name (e.g. "en0", "eth0").
                    Pass None to let Scapy choose the default interface.
        bpf_filter: Optional Berkeley Packet Filter string.

    Returns:
        The running daemon thread (already started).

    Raises:
        SystemExit if Scapy is not installed.
    """
    thread = threading.Thread(
        target=_sniff_loop,
        args=(callback, interface, bpf_filter),
        daemon=True,
        name="netscope-sniffer",
    )
    thread.start()
    logger.info(
        "Sniffer thread started — interface=%s  filter=%s",
        interface or "default",
        bpf_filter or "none",
    )
    return thread


def _sniff_loop(
    callback: Callable[[Any], None],
    interface: str | None,
    bpf_filter: str | None,
) -> None:
    """Inner loop — runs inside the daemon thread."""
    try:
        from scapy.all import sniff, conf

        # Suppress Scapy's own verbose output so our logs stay clean.
        conf.verb = 0

        sniff_kwargs: dict[str, Any] = {
            "prn": callback,
            "store": False,   # Don't accumulate packets in memory
        }
        if interface:
            sniff_kwargs["iface"] = interface
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter

        logger.info("Scapy sniff() starting …")
        sniff(**sniff_kwargs)

    except PermissionError:
        logger.critical(
            "\n"
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  PERMISSION DENIED — packet capture requires root/sudo   ║\n"
            "║                                                          ║\n"
            "║  Re-run with elevated privileges:                        ║\n"
            "║      sudo python app.py                                  ║\n"
            "╚══════════════════════════════════════════════════════════╝"
        )
    except ImportError:
        logger.critical(
            "Scapy is not installed.  Run:  pip install scapy"
        )
    except Exception as exc:
        logger.error("Sniffer thread crashed: %s", exc, exc_info=True)
