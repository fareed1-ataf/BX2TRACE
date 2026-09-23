"""
core/memory_scanner.py
========================
A second independent Thread (completely separate from DebugThread) that scans the memory
of each tracked process periodically, and generates a TraceEvent for every new string that appears
compared to the previous scan. This is the implementation of "Layer 6" we agreed upon in planning —
simple and direct Polling, we leave it as is until we really need the optimization
with Breakpoint-Triggered Scanning (a later layer when actually needed).

⚠️ Concurrency: This Thread reads tracked_pids (a snapshot/copy passed to it by the
coordinator) but it does not write to any shared data structure with DebugThread —
all its outward communication is exclusively via the shared event_queue (which is already
Thread-safe by the nature of queue.Queue).
"""

import logging
import queue
import threading
import time
import os

try:
    import yara
except ImportError:
    yara = None

from bx2trace.core import constants as c
from bx2trace.core.models import Severity, TraceEvent, EventCategory, EventAction
from bx2trace.extractors.entropy import entropy_by_page
from bx2trace.extractors.strings import diff_new_strings, extract_strings
from bx2trace.memory.reader import read_committed_regions

_log = logging.getLogger("bx2trace.scanner")


class MemoryScannerThread(threading.Thread):
    def __init__(
            self,
            get_tracked_handles,
            event_queue,
            interval: float = 1.0,
            min_string_length: int = 6,
            entropy_threshold: float = 7.0,
            max_strings_per_event: int = 50,
            max_pages_per_event: int = 10,
            yara_rules_path: str | None = None,
            max_region_size_mb: int = 100,         # Skip regions larger than this (avoids huge memory mappings)
            rwx_string_threshold: int = 20,        # Min new strings in RWX region to trigger HIGH alert
    ):
        """
        get_tracked_handles: a parameterless function returning dict[pid, handle] —
        we require a callable (not a static dict) so we always read the latest state
        from DebugThread at scan time, not at creation.

        All threshold/limit parameters mirror the fields in EngineConfig so the
        engine can forward them without hardcoding values at this layer.
        """
        super().__init__(daemon=True, name="bx2trace-scanner")
        self._get_tracked_handles = get_tracked_handles
        self.event_queue = event_queue
        self.interval = interval
        self._min_string_length = min_string_length
        self._entropy_threshold = entropy_threshold
        self._max_strings_per_event = max_strings_per_event
        self._max_pages_per_event = max_pages_per_event
        self._max_region_size_mb = max_region_size_mb
        self._rwx_string_threshold = rwx_string_threshold
        self._stop_event = threading.Event()
        self._previous_strings: dict[int, list[str]] = {}
        self._previous_rwx_strings: dict[int, list[str]] = {}  # Tracks strings in RWX pages separately

        self.yara_rules = self._load_yara_rules(yara_rules_path)

    def _load_yara_rules(self, path: str | None):
        if not yara or not path:
            return None
        try:
            if os.path.isfile(path):
                rules = yara.compile(filepath=path)
                _log.info("YARA rules loaded from file: %s", path)
                return rules
            elif os.path.isdir(path):
                # Compile all .yar/.yara files found in the directory (recursive)
                filepaths = {}
                for root, _, files in os.walk(path):
                    for file in files:
                        if file.endswith((".yar", ".yara")):
                            namespace = file.replace(".", "_")
                            filepaths[namespace] = os.path.join(root, file)
                if filepaths:
                    rules = yara.compile(filepaths=filepaths)
                    _log.info("YARA rules loaded from directory: %s (%d files)", path, len(filepaths))
                    return rules
                else:
                    _log.warning("No .yar/.yara files found in directory: %s", path)
        except Exception as e:
            _log.error("Failed to compile YARA rules from %s: %s", path, e)
        return None

    def request_stop(self):
        self._stop_event.set()

    def run(self):
        while not self._stop_event.wait(self.interval):
            # .wait(interval) returns True immediately if a stop is requested,
            # unlike sleep() which forces us to wait the full timeout.
            try:
                self._scan_once()
            except Exception as exc:  # noqa: BLE001
                # A single scan error (e.g. process terminated mid-scan) must not
                # stop the entire scanner — log and continue.
                _log.warning("Error in periodic scanner: %s", exc)

    def _scan_once(self):
        tracked = self._get_tracked_handles()

        # Remove stale PIDs (processes that have exited) from both caches.
        stale_pids = set(self._previous_strings) - set(tracked)
        for pid in stale_pids:
            del self._previous_strings[pid]
            self._previous_rwx_strings.pop(pid, None)  # Remove from RWX cache along with the main cache

        for pid, handle in tracked.items():
            regions = read_committed_regions(
                handle,
                c.PROTECTIONS_OF_INTEREST,
                max_region_size_mb=self._max_region_size_mb,
            )
            current_strings: list[str] = []
            rwx_strings: list[str] = []        # Strings found in executable+writable pages
            high_entropy_pages: list[dict] = []
            yara_matches: list[dict] = []

            for base_address, protect, data in regions:
                extracted = extract_strings(data, min_length=self._min_string_length)
                current_strings.extend(extracted)
                if protect == c.PAGE_EXECUTE_READWRITE:
                    rwx_strings.extend(extracted)

                # YARA Scanning
                if self.yara_rules:
                    try:
                        matches = self.yara_rules.match(data=data)
                        for m in matches:
                            yara_matches.append({
                                "rule": m.rule,
                                "tags": m.tags,
                                "address": hex(base_address),
                                "meta": m.meta
                            })
                    except Exception as e:
                        _log.debug("YARA match error at %x: %s", base_address, e)

                # Compute per-page entropy to detect encrypted/packed regions
                for offset, score in entropy_by_page(data):
                    if score >= self._entropy_threshold:
                        high_entropy_pages.append({
                            "address": hex(base_address + offset),
                            "entropy": round(score, 3),
                        })

            if yara_matches:
                yara_event = TraceEvent(
                    source="memory_scanner",
                    # Use EventCategory enum for type safety and IDE autocompletion
                    category=EventCategory.YARA,
                    action=EventAction.MATCH_FOUND,
                    pid=pid,
                    severity=Severity.HIGH,
                    payload={
                        "matches": yara_matches,
                        "match_count": len(yara_matches),
                        # Include high-entropy context alongside YARA hit for richer analysis
                        "high_entropy_pages": high_entropy_pages[:self._max_pages_per_event],
                    }
                )
                try:
                    self.event_queue.put_nowait(yara_event)
                except queue.Full:
                    _log.warning(
                        "Scanner queue full — YARA event dropped for PID %d (%d matches lost)",
                        pid, len(yara_matches),
                    )

            previous = self._previous_strings.get(pid, [])
            new_strings = diff_new_strings(previous, current_strings)

            if new_strings:
                event = TraceEvent(
                    source="memory_scanner",
                    category=EventCategory.MEMORY,
                    action=EventAction.STRING_FOUND,
                    pid=pid,
                    severity=Severity.SUSPICIOUS,
                    payload={
                        "count": len(new_strings),
                        "strings": new_strings[:self._max_strings_per_event],
                        "high_entropy_pages": high_entropy_pages[:self._max_pages_per_event],
                    },
                )
                try:
                    self.event_queue.put_nowait(event)
                except queue.Full:
                    _log.warning(
                        "Scanner queue full — memory event dropped for PID %d (%d strings lost)",
                        pid, len(new_strings),
                    )

            # Emit a HIGH-severity alert when new strings appear in RWX (executable+writable)
            # memory regions. RWX pages are the primary staging area for shellcode unpacking;
            # a sudden appearance of new strings there is a strong indicator of a packer
            # or dropper that has just decrypted its payload.
            prev_rwx = self._previous_rwx_strings.get(pid, [])
            new_rwx = diff_new_strings(prev_rwx, rwx_strings)
            if len(new_rwx) >= self._rwx_string_threshold:
                rwx_event = TraceEvent(
                    source="memory_scanner",
                    category=EventCategory.MEMORY,
                    action="RWX_STRINGS_DETECTED",
                    pid=pid,
                    severity=Severity.HIGH,
                    payload={
                        "count": len(new_rwx),
                        "strings": new_rwx[:self._max_strings_per_event],
                        "threshold": self._rwx_string_threshold,
                        "note": "New strings appeared in RWX memory — possible shellcode unpack",
                    },
                )
                try:
                    self.event_queue.put_nowait(rwx_event)
                except queue.Full:
                    _log.warning(
                        "Scanner queue full — RWX event dropped for PID %d", pid
                    )
            self._previous_rwx_strings[pid] = rwx_strings

            self._previous_strings[pid] = current_strings
