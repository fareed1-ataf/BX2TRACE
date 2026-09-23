"""
detectors/process_hollow_detector.py
======================================
Detects Process Hollowing and classic code injection patterns by correlating
two injection-related API calls targeting the same victim process.

Process Hollowing / DLL injection pattern (steps intercepted by api_hooker.py):
    1. VirtualAllocEx          -- allocate executable space in the victim
    2. WriteProcessMemory      -- write shellcode or a PE image into that space
    3. CreateRemoteThreadEx    -- start a new thread inside the victim to run the payload

This detector fires when steps 2 (WriteProcessMemory) and 3 (CreateRemoteThread)
both target the same victim process PID within a configurable time window.

Correlation key: target_pid (the actual Windows PID of the victim, resolved via
GetProcessId()). Using the PID instead of the raw HANDLE value prevents bypass:
openings the same process twice yields two different HANDLE values that both
refer to the same PID, so handle-based correlation would miss the match.

Severity: CRITICAL — legitimate software almost never injects into other processes.
"""

import time
import logging
from typing import Dict, List

from bx2trace.core.models import (
    BaseDetector,
    TraceEvent,
    EventCategory,
    Severity,
)

_log = logging.getLogger("bx2trace.detector.process_hollowing")

# Time window in seconds: if WriteProcessMemory and CreateRemoteThread
# target the same handle within this window, it's flagged as hollowing.
_CORRELATION_WINDOW_SEC = 30.0


class ProcessHollowingDetector(BaseDetector):
    """
    Correlates WriteProcessMemory + CreateRemoteThread[Ex] targeting the same
    victim process PID to detect process hollowing and DLL injection.

    State maintained per attacker PID (source_pid):
        _wpm_events: {source_pid: [(target_key, timestamp), ...]}
        _crt_events: {source_pid: [(target_key, timestamp), ...]}

    target_key is the resolved victim PID (int) from target_pid in the event
    payload (set by GetProcessId() in debug_thread.py). Falls back to
    target_handle hex string if target_pid is unavailable.

    When CreateRemoteThread arrives, _wpm_events is scanned for a matching
    target_key within _CORRELATION_WINDOW_SEC. A match fires a CRITICAL alert.
    """

    name = "process_hollowing_detector"

    def __init__(self, window_sec: float = _CORRELATION_WINDOW_SEC):
        self._window = window_sec
        # {source_pid -> list of (target_key, timestamp)}
        # target_key is the victim PID (int) or handle hex string as fallback
        self._wpm_events: Dict[int, List[tuple]] = {}
        self._crt_events: Dict[int, List[tuple]] = {}

    def handles(self, event: TraceEvent) -> bool:
        """Only interested in INJECTION category events."""
        return event.category == EventCategory.INJECTION

    def process(self, event: TraceEvent) -> List[TraceEvent]:
        now = time.monotonic()
        action = event.action
        pid    = event.pid
        details = event.payload.get("details", {})

        # Prune stale entries first to prevent unbounded growth
        self._prune(now)

        if action == "WRITE_PROCESS_MEMORY":
            # FIX-05: Key on target_pid (actual PID resolved from the handle via
            # GetProcessId). The old code keyed on target_handle (a hex string),
            # which changes with every OpenProcess call — opening the same process
            # twice yields two different handle values, defeating correlation.
            target_key = details.get("target_pid") or details.get("target_handle", "0x0")
            self._wpm_events.setdefault(pid, []).append((target_key, now))
            _log.debug(
                "ProcessHollowingDetector: recorded WPM from PID %d -> target %s",
                pid, target_key,
            )
            return []  # Not enough evidence yet — wait for CreateRemoteThread

        if action == "CREATE_REMOTE_THREAD":
            target_key = details.get("target_pid") or details.get("target_handle", "0x0")
            self._crt_events.setdefault(pid, []).append((target_key, now))

            # Check if there is a matching WriteProcessMemory in the window
            wpm_list = self._wpm_events.get(pid, [])
            matching_wpm = [
                (h, ts) for h, ts in wpm_list
                if h == target_key and (now - ts) <= self._window   # FIX-05
            ]

            if matching_wpm:
                _log.warning(
                    "ProcessHollowingDetector: HOLLOWING DETECTED! "
                    "PID %d -> target %s",
                    pid, target_key,
                )
                alert = event.derive(
                    source=self.name,
                    action="PROCESS_HOLLOWING_DETECTED",
                    category=EventCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    payload={
                        "attacker_pid":        pid,
                        "target_key":          target_key,
                        "wpm_count":           len(matching_wpm),
                        "wpm_timestamps":      [ts for _, ts in matching_wpm],
                        "detection_window_sec": self._window,
                        "description": (
                            "WriteProcessMemory followed by CreateRemoteThread "
                            "targeting the same process — strong indicator "
                            "of Process Hollowing or DLL injection."
                        ),
                    },
                )
                return [alert]

        return []

    def _prune(self, now: float) -> None:
        """Remove stale entries older than the correlation window."""
        cutoff = now - self._window
        for store in (self._wpm_events, self._crt_events):
            for pid in list(store.keys()):
                store[pid] = [(h, ts) for h, ts in store[pid] if ts >= cutoff]
                if not store[pid]:
                    del store[pid]
