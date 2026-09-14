"""
core/models.py
===============
All common data types shared between project components. This file is the "common language" —
every other file communicates via these types, not via random dictionaries.

The most important architectural decision here: TraceEvent is designed with a few fixed fields +
a free payload, so we can add new event types (like function tracing in the future) without
any modification to this file itself or to any code that consumes events.
"""

import json as _json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional


class EventCategory:
    PROCESS = "PROCESS"
    MEMORY = "MEMORY"
    DLL = "DLL"
    THREAD = "THREAD"
    EXCEPTION = "EXCEPTION"
    SECURITY = "SECURITY"
    API = "API"
    NETWORK = "NETWORK"
    OTHER = "OTHER"


class EventAction:
    CREATED = "CREATED"
    EXITED = "EXITED"
    LOADED = "LOADED"
    UNLOADED = "UNLOADED"
    STRING_FOUND = "STRING_FOUND"
    CALLED = "CALLED"
    CONNECTED = "CONNECTED"


class TraceMode(Enum):
    MONITOR_ONLY = auto()  # Track events only (processes/DLLs) — without touching memory at all
    MEMORY_DUMP = auto()  # Dump memory from an already running process (no new CreateProcess)
    FULL_TRACE = auto()  # Default: full trace + periodic memory scan + extraction


class Severity(Enum):
    INFO = "INFO"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"


CURRENT_SCHEMA_VERSION = 1


@dataclass
class TraceEvent:
    """
    The unified format for any event in the project, regardless of its source.

    Fixed fields (not deleted and their meaning not changed without a very strong reason —
    any legacy code depends on them):
    """
    source: str  # "debug_loop" | "memory_scanner" | "api_hook" | name of any Detector
    category: str  # "PROCESS" | "MEMORY" | "DLL" | "THREAD" | "EXCEPTION" | "SECURITY" | "OTHER"
    action: str  # The specific action: "CREATED" | "STRING_FOUND" | "VirtualAlloc_CALLED"
    pid: int
    tid: int = 0
    severity: Severity = Severity.INFO
    payload: dict[str, Any] = field(default_factory=dict)

    # Automatically populated fields — usually not passed manually
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    schema_version: int = CURRENT_SCHEMA_VERSION

    def __post_init__(self):
        # Eagerly validate payload is JSON-serialisable so the error is caught at creation
        # time with a useful stack trace — not silently at write time inside flush().
        try:
            _json.dumps(self.payload, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"TraceEvent payload is not JSON-serialisable: {exc}"
            ) from exc

    def derive(
            self,
            source: str,
            action: str,
            payload: dict,
            severity: "Severity | None" = None,
            category: str = "SECURITY",
    ) -> "TraceEvent":
        """
        Create a child event that inherits pid and tid from this event.
        Designed for use inside Detectors to reduce repetitive boilerplate.

        Example::

            return [event.derive(
                source=self.name,
                action="SHELLCODE_DETECTED",
                payload={"evidence": matched_strings},
            )]
        """
        return TraceEvent(
            source=source,
            category=category,
            action=action,
            pid=self.pid,
            tid=self.tid,
            severity=severity or Severity.HIGH,
            payload={**payload, "parent_event_id": self.event_id},
        )


@dataclass
class EngineConfig:
    target_path: str
    mode: TraceMode = TraceMode.FULL_TRACE
    on_event: Optional[Callable[[TraceEvent], None]] = None
    memory_scan_interval: float = 1.5
    max_tracked_processes: int = 50
    # ↑ Maximum limit — protects TraceBox itself from crashing if the target generates
    #   processes quickly (intentionally or by mistake), instead of consuming resources limitlessly.
    event_queue_maxsize: int = 2000
    # ↑ Backpressure limit — full-queue behaviour handled inside engine.py.
    yara_rules_path: Optional[str] = None  # Path to a .yar file or directory

    # --- Configurable thresholds (moved from hardcoded values inside detectors/launcher) ---
    rwx_string_threshold: int = 20
    # ↑ Minimum number of new strings appearing in an RWX region to trigger a HIGH alert.
    max_region_size_mb: int = 100
    # ↑ Upper cap for a single memory region read — ignores abnormally huge regions.
    create_new_console: bool = True
    # ↑ Whether the target process is spawned with its own console window.
    entropy_alert_threshold: float = 7.0
    # ↑ Shannon entropy score (0.0–8.0) above which a page is considered encrypted/compressed.
    min_string_length: int = 6
    # ↑ Minimum printable-character run length to consider a byte sequence a "string".
    max_strings_per_event: int = 50
    # ↑ Maximum number of new strings included in a single NEW_STRINGS_FOUND event payload.
    max_pages_per_event: int = 10
    # ↑ Maximum number of high-entropy page records included per event.
    hw_breakpoints: list[int] = field(default_factory=list)

    # ↑ List of virtual addresses to set Hardware Breakpoints (DR0-DR3)

    def __post_init__(self):
        if self.memory_scan_interval <= 0:
            raise ValueError("memory_scan_interval must be > 0")
        if self.max_tracked_processes <= 0:
            raise ValueError("max_tracked_processes must be > 0")
        if not (0.0 < self.entropy_alert_threshold <= 8.0):
            raise ValueError("entropy_alert_threshold must be between 0.0 and 8.0")
        if self.rwx_string_threshold < 1:
            raise ValueError("rwx_string_threshold must be >= 1")
        if self.min_string_length < 1:
            raise ValueError("min_string_length must be >= 1")
        if self.max_strings_per_event < 1:
            raise ValueError("max_strings_per_event must be >= 1")
        if self.max_pages_per_event < 1:
            raise ValueError("max_pages_per_event must be >= 1")


class BaseDetector:
    """
    Every new analysis feature (Detector) inherits from this class only.
    Adding a feature = a new detectors/file.py inheriting this class, and a single registration line
    in engine.py. Zero modifications to any legacy code.
    """

    name: str = "base_detector"

    def handles(self, event: TraceEvent) -> bool:
        """Does this event concern me?"""
        raise NotImplementedError

    def process(self, event: TraceEvent) -> list[TraceEvent]:
        """Return zero or more new events derived from this event."""
        raise NotImplementedError
