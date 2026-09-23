"""
detectors/c2_beacon_detector.py
=================================
Detects C2 (Command & Control) beaconing behavior — a pattern where malware
repeatedly connects to the same IP:Port at regular intervals to receive commands
or exfiltrate data.

Detection strategy:
    Track all NETWORK::CONNECTED events per source PID.
    If the same (ip, port) pair appears >= threshold times within the time window,
    fire a CRITICAL alert.

Typical C2 beaconing:
    - Check-in every 30–300 seconds to a hardcoded IP:Port
    - Uses HTTP/HTTPS (port 80/443) or custom ports
    - Connects even when the server is down (repeated failed connections)

MITRE ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
"""

import time
import logging
from collections import defaultdict
from typing import Dict, List, Tuple

from bx2trace.core.models import (
    BaseDetector,
    TraceEvent,
    EventCategory,
    EventAction,
    Severity,
)

_log = logging.getLogger("bx2trace.detector.c2_beacon")

# Default thresholds
_DEFAULT_WINDOW_SEC   = 300.0   # 5-minute sliding window
_DEFAULT_COUNT_THRESH = 3       # 3 connections to same IP:Port = alert


class C2BeaconDetector(BaseDetector):
    """
    Fires when a process connects to the same IP:Port >= count_threshold times
    within window_sec seconds.

    State:
        _connections[pid][(ip, port)] = [(timestamp, event_id), ...]

    On each CONNECTED event the entry is updated and checked.
    If threshold is exceeded, a CRITICAL alert is emitted.
    Alert fires once per (pid, ip, port) pair (tracked in _alerted set)
    to avoid flooding — resets automatically when window expires.
    """

    name = "c2_beacon_detector"

    def __init__(
        self,
        window_sec:      float = _DEFAULT_WINDOW_SEC,
        count_threshold: int   = _DEFAULT_COUNT_THRESH,
    ):
        self._window    = window_sec
        self._threshold = count_threshold
        # {pid: {(ip, port): [(ts, event_id), ...]}}
        self._connections: Dict[int, Dict[Tuple, List]] = defaultdict(lambda: defaultdict(list))
        # Already-alerted keys — prevents flooding.
        # Cleaned up periodically by _prune_alerted() to prevent unbounded growth.
        self._alerted: set = set()

    def handles(self, event: TraceEvent) -> bool:
        return (
            event.category == EventCategory.NETWORK
            and event.action in (EventAction.CONNECTED, "CONNECTED")
        )

    def _prune_alerted(self, now: float) -> None:
        """Remove alert keys whose connection count has dropped back below
        threshold (window expired). Called on every process() invocation."""
        expired = set()
        for pid, ip, port in list(self._alerted):
            conn_list = self._connections.get(pid, {}).get((ip, port), [])
            active = [(ts, eid) for ts, eid in conn_list if (now - ts) <= self._window]
            if len(active) < self._threshold:
                expired.add((pid, ip, port))
        self._alerted -= expired
        if expired:
            _log.debug("C2BeaconDetector: pruned %d expired alert keys", len(expired))

    def process(self, event: TraceEvent) -> List[TraceEvent]:
        now     = time.monotonic()
        self._prune_alerted(now)  # periodic cleanup of stale alerts
        pid     = event.pid
        details = event.payload.get("details", {})
        ip      = details.get("ip")
        port    = details.get("port")

        # Only track events that have a parsed IP:Port
        if not ip or port is None:
            return []

        key = (ip, port)
        alert_key = (pid, ip, port)

        # Prune old entries outside the window
        conn_list = self._connections[pid][key]
        conn_list[:] = [
            (ts, eid) for ts, eid in conn_list
            if (now - ts) <= self._window
        ]

        # Add current connection
        conn_list.append((now, event.event_id))
        count = len(conn_list)

        _log.debug(
            "C2BeaconDetector: PID %d -> %s:%d | count=%d (threshold=%d)",
            pid, ip, port, count, self._threshold,
        )

        # Check if alert was already fired for this (pid, ip, port) combination
        if count >= self._threshold and alert_key not in self._alerted:
            self._alerted.add(alert_key)

            _log.warning(
                "C2BeaconDetector: BEACON DETECTED! PID %d -> %s:%d (%d times in %.0fs)",
                pid, ip, port, count, self._window,
            )

            # Calculate average interval between connections for context
            timestamps = [ts for ts, _ in conn_list]
            if len(timestamps) >= 2:
                intervals = [
                    timestamps[i+1] - timestamps[i]
                    for i in range(len(timestamps) - 1)
                ]
                avg_interval = sum(intervals) / len(intervals)
            else:
                avg_interval = 0.0

            alert = event.derive(
                source=self.name,
                action="C2_BEACON_DETECTED",
                category=EventCategory.NETWORK,
                severity=Severity.CRITICAL,
                payload={
                    "attacker_pid":       pid,
                    "target_ip":          ip,
                    "target_port":        port,
                    "connection_count":   count,
                    "window_sec":         self._window,
                    "avg_interval_sec":   round(avg_interval, 2),
                    "description": (
                        f"Process {pid} connected to {ip}:{port} {count} times "
                        f"within {self._window:.0f}s — possible C2 beaconing. "
                        "MITRE ATT&CK: T1071 / T1571."
                    ),
                },
            )
            return [alert]

        return []
