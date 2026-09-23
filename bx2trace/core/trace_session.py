"""
core/trace_session.py
=====================
TraceSession — the unified public entry point for the bx2trace library.

Responsibility:
    - Accepts a single EngineConfig object.
    - Internally wires DebugThread + MemoryScannerThread + a shared Queue.
    - Exposes a clean, minimal API: start / stop / join / get_event / is_alive.
    - Exposes a DetectorEngine instance the caller can configure freely.

The caller never needs to know about Queue, DebugThread, or MemoryScannerThread.

Usage::

    from bx2trace import TraceSession, EngineConfig, TraceMode

    config = EngineConfig(target_path=r"C:\\sample.exe", mode=TraceMode.FULL_TRACE)

    session = TraceSession(config)
    session.engine.load_defaults()           # built-in detectors
    session.engine.register(MyDetector())    # optional: add your own on top
    session.start()

    while session.is_alive:
        event = session.get_event()
        if event is None:
            continue
        for alert in session.engine.process(event):
            print(f"[{alert.severity}] {alert.action}")

    session.join()
"""

import queue
import logging
from typing import Optional

from bx2trace.core.models import EngineConfig, TraceEvent
from bx2trace.core.debug_thread import DebugThread
from bx2trace.core.memory_scanner import MemoryScannerThread
from bx2trace.core.detector_engine import DetectorEngine

_log = logging.getLogger("bx2trace.trace_session")

# Sentinel returned by get_event() when the queue is empty within the timeout.
_EMPTY = None


class TraceSession:
    """
    Unified entry point for the bx2trace analysis pipeline.

    Wires all internal components together based on a single EngineConfig.
    The caller interacts only with this class and the DetectorEngine.

    Attributes:
        engine (DetectorEngine): Configure this before calling start().
            Use engine.load_defaults() for built-in detectors,
            or engine.register(...) for custom ones.
    """

    def __init__(self, config: EngineConfig) -> None:
        if not isinstance(config, EngineConfig):
            raise TypeError(
                f"config must be an EngineConfig instance, got {type(config).__name__}"
            )
        self._config = config

        # Internal event pipeline — hidden from the caller.
        self._event_queue: queue.Queue[TraceEvent] = queue.Queue(
            maxsize=config.event_queue_maxsize
        )

        # Threads — created in start(), not here.
        self._debug_thread: Optional[DebugThread] = None
        self._scanner_thread: Optional[MemoryScannerThread] = None

        # Public: the caller configures this before start().
        self.engine = DetectorEngine()

        _log.debug("TraceSession created for target: %s", config.target_path)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Launches the DebugThread and MemoryScannerThread.
        Blocks until the debugger signals it is ready (up to 10 seconds).

        Raises:
            RuntimeWarning: if the debugger fails to initialize within timeout.
        """
        cfg = self._config

        # 1. Launch the debug loop.
        self._debug_thread = DebugThread(
            exe_path=cfg.target_path,
            cmd_args=cfg.cmd_args,
            mode=cfg.mode,
            raw_event_queue=self._event_queue,
            max_tracked_processes=cfg.max_tracked_processes,
            create_new_console=cfg.create_new_console,
            hw_breakpoints=cfg.hw_breakpoints if cfg.hw_breakpoints else None,
            enable_stealth=cfg.enable_stealth,
        )
        self._debug_thread.start()

        # Wait for the debug loop to attach and be ready.
        # RuntimeError (not RuntimeWarning) is the correct exception here because
        # RuntimeWarning is a Warning subclass that is NOT caught by bare 'except Exception'.
        if not self._debug_thread.started_ok.wait(timeout=10):
            raise RuntimeError(
                "DebugThread timed out: no response within 10 seconds. "
                "Verify the target path exists and you have Administrator privileges."
            )

        # started_ok is also set when the launch fails (to unblock waiters),
        # so check startup_error explicitly to distinguish success from failure.
        if self._debug_thread.startup_error is not None:
            raise RuntimeError(
                f"DebugThread failed to launch the target process: "
                f"{self._debug_thread.startup_error}"
            ) from self._debug_thread.startup_error

        # 2. Launch the memory scanner.
        # Uses a lambda so it always reflects the live tracked-process map
        # (new child processes are picked up automatically).
        self._scanner_thread = MemoryScannerThread(
            get_tracked_handles=lambda: {
                p.pid: p.handle for p in self._debug_thread.tracked.values()
            },
            event_queue=self._event_queue,
            interval=cfg.memory_scan_interval,
            yara_rules_path=cfg.yara_rules_path,
            min_string_length=cfg.min_string_length,
            max_strings_per_event=cfg.max_strings_per_event,
            max_pages_per_event=cfg.max_pages_per_event,
            entropy_threshold=cfg.entropy_alert_threshold,
            max_region_size_mb=cfg.max_region_size_mb,
            rwx_string_threshold=cfg.rwx_string_threshold,
        )
        self._scanner_thread.start()

        _log.info(
            "TraceSession started — target: %s | mode: %s",
            self._config.target_path,
            self._config.mode,
        )

    def stop(self) -> None:
        """Requests both threads to stop gracefully. Does not block."""
        if self._scanner_thread:
            self._scanner_thread.request_stop()
        if self._debug_thread:
            self._debug_thread.request_stop()
        _log.info("TraceSession stop requested.")

    def join(self, timeout: float = 5.0) -> None:
        """Waits for both threads to finish. Call after stop()."""
        if self._scanner_thread:
            self._scanner_thread.join(timeout=timeout)
        if self._debug_thread:
            self._debug_thread.join(timeout=timeout)

    # ------------------------------------------------------------------
    # Event consumption
    # ------------------------------------------------------------------

    def get_event(self, timeout: float = 1.0) -> Optional[TraceEvent]:
        """
        Retrieves one event from the internal queue.

        Returns:
            A TraceEvent if one arrived within `timeout` seconds, else None.

        Typical usage in a consumer loop::

            while session.is_alive:
                event = session.get_event()
                if event is None:
                    continue          # nothing arrived this tick
                alerts = session.engine.process(event)
                ...
        """
        try:
            return self._event_queue.get(timeout=timeout)
        except queue.Empty:
            return _EMPTY

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def is_alive(self) -> bool:
        """True while the target process is still running and being monitored."""
        return bool(
            (self._debug_thread and self._debug_thread.is_alive())
            or (self._scanner_thread and self._scanner_thread.is_alive())
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"TraceSession("
            f"target={self._config.target_path!r}, "
            f"alive={self.is_alive}, "
            f"detectors={self.engine.detector_names})"
        )
