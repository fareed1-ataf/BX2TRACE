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
from typing import Any, Optional


class EventCategory(str, Enum):
    """
    str + Enum: Each value is a string and an enum member.
    Regular string comparison works:
        event.category == "PROCESS"              -> True
        event.category == EventCategory.PROCESS  -> True
    While maintaining type safety and IDE autocompletion.
    """

    PROCESS = "PROCESS"
    MEMORY = "MEMORY"
    DLL = "DLL"
    THREAD = "THREAD"
    EXCEPTION = "EXCEPTION"
    SECURITY = "SECURITY"
    API = "API"
    NETWORK = "NETWORK"
    YARA = "YARA"        # YARA scanning results
    FILE = "FILE"        # File system operations
    INJECTION = "INJECTION"  # Code injection attempts
    REGISTRY = "REGISTRY"   # Registry operations
    OTHER = "OTHER"
    SCRIPT = "SCRIPT"       # PowerShell, CMD, WScript
    PRIVILEGE = "PRIVILEGE" # Privilege escalation and token manipulation
    CRYPTO = "CRYPTO"       # Encryption/decryption operations
    SERVICE = "SERVICE"     # Windows services creation/modification
    ANTI_DEBUG = "ANTI_DEBUG" # Anti-analysis and sandbox evasion
    COM = "COM"             # COM object instantiation
    PIPE = "PIPE"           # Named pipes communication
    CLIPBOARD = "CLIPBOARD" # Clipboard read/write
    SCREENSHOT = "SCREENSHOT" # Screen capture attempts
    KEYLOG = "KEYLOG"       # Keyboard hooking


class EventAction(str, Enum):
    """
    Event Actions — str + Enum for compatibility with string-based checks.
    """

    CREATED = "CREATED"
    EXITED = "EXITED"
    LOADED = "LOADED"
    UNLOADED = "UNLOADED"
    STRING_FOUND = "STRING_FOUND"
    CALLED = "CALLED"
    CONNECTED = "CONNECTED"
    IGNORED = "IGNORED"      # Process exceeded tracking limit
    OPENED = "OPENED"        # File opened
    WRITTEN = "WRITTEN"      # File written
    DELETED = "DELETED"      # File deleted
    MOVED = "MOVED"          # File moved
    MATCH_FOUND = "MATCH_FOUND"  # YARA match
    PE_FOUND = "PE_FOUND"    # PE header detected in memory
    SHELL_EXECUTE = "SHELL_EXECUTE"
    TOKEN_ADJUST = "TOKEN_ADJUST"
    HOOK_INSTALLED = "HOOK_INSTALLED"
    CLIPBOARD_READ = "CLIPBOARD_READ"
    CLIPBOARD_WRITE = "CLIPBOARD_WRITE"
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    KEY_GENERATED = "KEY_GENERATED"
    SERVICE_CREATED = "SERVICE_CREATED"
    SERVICE_STARTED = "SERVICE_STARTED"
    PIPE_CREATED = "PIPE_CREATED"
    COM_CREATED = "COM_CREATED"
    DEBUGGER_CHECK = "DEBUGGER_CHECK"
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"


class TraceMode(Enum):
    MONITOR_ONLY = auto()  # Track events only (processes/DLLs) — no memory scanning
    MEMORY_DUMP = auto()   # Dump memory from an already-running process (no CreateProcess)
    FULL_TRACE = auto()    # Default: full trace + periodic memory scan + string extraction


class Severity(Enum):
    INFO = "INFO"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"  # Maximum danger level — injection, shellcode, RAT


CURRENT_SCHEMA_VERSION = 1


@dataclass
class TraceEvent:
    """
    The unified format for any event in the project, regardless of its source.

    Fixed fields are stable by design — downstream consumers rely on them.
    New information goes into the free-form `payload` dict.
    """

    source: str      # "debug_loop" | "memory_scanner" | "api_hook" | detector name
    category: str    # EventCategory value
    action: str      # EventAction value or a free-form action string
    pid: int
    tid: int = 0
    severity: Severity = Severity.INFO
    payload: dict[str, Any] = field(default_factory=dict)

    # Auto-populated — do not pass manually
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    schema_version: int = CURRENT_SCHEMA_VERSION

    def __post_init__(self):
        # Validate payload is JSON-serialisable at creation time so errors surface
        # immediately with a useful stack trace, not silently at write time.
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
        Designed for use inside Detectors to reduce boilerplate.

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

    # --- Launch Parameters ---
    mode: TraceMode = TraceMode.FULL_TRACE
    cmd_args: str = ""                  # Command-line arguments for the target process
    create_new_console: bool = True     # Spawn the target in a new console window
    enable_stealth: bool = True         # Patch PEB to hide the debugger from the target

    # --- Event Settings ---
    event_queue_maxsize: int = 2000
    # ↑ Backpressure limit — events are dropped (not blocked) when the queue is full.
    max_tracked_processes: int = 50
    # ↑ Safety cap — prevents unbounded resource use if the target spawns many children.

    # --- Memory Scanner Settings ---
    memory_scan_interval: float = 1.5
    min_string_length: int = 6
    # ↑ Minimum printable-character run to be considered a string.
    max_strings_per_event: int = 50
    # ↑ Maximum new strings per STRING_FOUND event.
    max_pages_per_event: int = 10
    # ↑ Maximum high-entropy page records per event.
    max_region_size_mb: int = 100
    # ↑ Upper cap for a single memory region read — skips abnormally large regions.
    entropy_alert_threshold: float = 7.0
    # ↑ Shannon entropy score (0.0–8.0) above which a page is flagged as encrypted/packed.
    rwx_string_threshold: int = 20
    # ↑ Minimum new strings in an RWX region to trigger a HIGH-severity alert.

    # --- YARA ---
    yara_rules_path: Optional[str] = None  # Path to a .yar file or directory

    # --- Hardware Breakpoints ---
    hw_breakpoints: list[int] = field(default_factory=list)
    # ↑ Virtual addresses for Hardware Breakpoints (DR0–DR3).

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
    Base class for all behavioral detectors.

    To add a new detection capability:
    1. Create a new file in bx2trace/detectors/.
    2. Inherit from BaseDetector and implement handles() and process().
    3. Register the instance: engine.register(MyDetector()).

    No modifications to any existing code are required.
    """

    name: str = "base_detector"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Warn if a subclass forgets to override `name` — otherwise all logs
        # will show "base_detector" which makes debugging impossible.
        if cls.name == "base_detector":
            import warnings
            warnings.warn(
                f"Detector '{cls.__name__}' does not override the 'name' class attribute. "
                f"Set a unique name to identify it in logs and alerts.",
                stacklevel=2,
            )

    def handles(self, event: TraceEvent) -> bool:
        """Return True if this detector wants to inspect this event."""
        raise NotImplementedError

    def process(self, event: TraceEvent) -> list[TraceEvent]:
        """Return zero or more new alert events derived from this event."""
        raise NotImplementedError
