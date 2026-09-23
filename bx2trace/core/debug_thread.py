"""
core/debug_thread.py
======================
Runs the Windows Debug API event loop inside a dedicated background thread.

Responsibility:
    Consume every raw debug event (process creation, DLL loads, thread events,
    exceptions, API breakpoint hits) and emit a structured TraceEvent into the
    shared queue.  It does NOT analyze, classify, or extract strings — that is
    the job of the DetectorEngine and MemoryScannerThread consuming from the queue.

Concurrency contract:
    self.tracked (PID → TrackedProcess) is read and written ONLY from inside
    run(). Never touch it from another thread. This eliminates the need for
    locks on the hot path and prevents race conditions entirely.

API Hook lifecycle:
    On CREATE_PROCESS_DEBUG_EVENT and every LOAD_DLL_DEBUG_EVENT:
        → _setup_initial_hooks() plants INT3 (0xCC) at the entry of each
          configured API function.
    On EXCEPTION_BREAKPOINT (our hook fires):
        → _handle_api_hook() reads CPU registers (RCX/RDX/R8/R9) to capture
          the function's arguments, emits a TraceEvent, then calls
          _resume_from_hook() which restores the original byte, sets the
          Trap Flag (TF) for single-step, and adds tid to pending_single_steps.
    On EXCEPTION_SINGLE_STEP (one instruction after the hook):
        → _handle_rehook() re-plants the 0xCC so the next call is also caught.
"""

import ctypes
import logging
import queue
import os
import socket as _socket
import threading
import uuid as _uuid
from ctypes import wintypes
from typing import Dict, Any

from bx2trace.core import constants as c
from bx2trace.core.models import Severity, TraceEvent, EventCategory, EventAction
from bx2trace.core.process_launcher import create_process_debug
from bx2trace.core.win_structs import DEBUG_EVENT, CONTEXT
from bx2trace.core.api_hooker import HookManager

kernel32 = ctypes.windll.kernel32
_log = logging.getLogger("bx2trace.debug")


kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE


class TrackedProcess:
    """
    Holds all information bx2trace needs about a single monitored process.

    Attributes:
        pid     -- Windows process ID.
        handle  -- Open HANDLE with PROCESS_ALL_ACCESS (from CREATE_PROCESS_DEBUG_INFO).
                   Used by the memory scanner and hook manager.
                   Closed in _cleanup() when the process exits.
        path    -- Full executable path resolved via GetFinalPathNameByHandleW.
                   "Unknown" if resolution fails.
        is_root -- True for the primary target launched by bx2trace.
                   False for any child processes spawned by the target.
    """

    __slots__ = ("pid", "handle", "path", "is_root")

    def __init__(self, pid: int, handle, path: str, is_root: bool):
        self.pid = pid
        self.handle = handle
        self.path = path
        self.is_root = is_root


class DebugThread(threading.Thread):
    def __init__(
            self,
            exe_path: str,
            mode,
            raw_event_queue: "queue.Queue[TraceEvent]",
            max_tracked_processes: int = 50,
            create_new_console: bool = True,
            hw_breakpoints: list[int] | None = None,
            cmd_args: str = "",
            # Controlled externally via EngineConfig so callers can disable PEB patching
            # when analyzing trusted software where stealth is unnecessary overhead.
            enable_stealth: bool = True,
    ):
        super().__init__(daemon=True, name=f"bx2trace-debug-{_uuid.uuid4().hex[:8]}")
        self.exe_path = exe_path
        self.cmd_args = cmd_args
        self.mode = mode
        self.raw_event_queue = raw_event_queue
        self.max_tracked_processes = max_tracked_processes
        self.create_new_console = create_new_console
        self.hw_breakpoints = hw_breakpoints or []
        self.enable_stealth = enable_stealth
        self.hook_manager = HookManager()
        self.pending_single_steps: Dict[int, int] = {}  # tid -> address to re-hook

        # Read and written ONLY from inside run() — without any exceptions
        self.tracked: dict[int, TrackedProcess] = {}
        self.root_pid: int | None = None

        self._stop_event = threading.Event()
        self.startup_error: Exception | None = None
        self.started_ok = threading.Event()  # Signaled after successful launch

    def request_stop(self):
        """Called from another Thread (e.g., on Ctrl+C) to request a clean stop."""
        self._stop_event.set()

    def _put_event(
            self,
            source: str,
            category: str,
            action: str,
            pid: int,
            tid: int = 0,
            severity=Severity.INFO,
            **payload,
    ):
        event = TraceEvent(
            source=source,
            category=category,
            action=action,
            pid=pid,
            tid=tid,
            severity=severity,
            payload=payload,
        )
        try:
            self.raw_event_queue.put_nowait(event)
        except queue.Full:
            # Backpressure: The queue is full because the consumer is slower than the producer.
            # We drop this event instead of freezing the Debug loop (if we used regular
            # put(), it might wait forever and freeze the monitoring of a physically live process).
            # We print a warning instead of failing completely silently.
            _log.warning("Queue full, event dropped: %s/%s", category, action)

    def run(self):
        _log.info("Starting DebugThread for target: %s", self.exe_path)
        try:
            proc_info = create_process_debug(
                self.exe_path, self.mode, self.create_new_console, cmd_args=self.cmd_args
            )
        except Exception as exc:  # noqa: BLE001 — we want to catch any launch failure
            _log.error("Failed to launch process: %s", exc)
            self.startup_error = exc
            self.started_ok.set()  # Release anyone waiting, even with failure
            return

        self.root_pid = proc_info.dwProcessId
        _log.info("Root process launched. PID: %d", self.root_pid)
        self.tracked[self.root_pid] = TrackedProcess(
            pid=self.root_pid,
            handle=proc_info.hProcess,
            path=self.exe_path,
            is_root=True,
        )
        self.started_ok.set()

        debug_event = DEBUG_EVENT()

        while not self._stop_event.is_set():
            got_event = kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 200)
            # 200ms timeout — gives the loop a chance to check _stop_event
            # without blocking the immediate reception of real events.
            if not got_event:
                continue  # Timeout — no event right now, check again

            # _handle_event returns the correct continue status:
            # DBG_CONTINUE for our own hooks, DBG_EXCEPTION_NOT_HANDLED for genuine crashes.
            # Using the return value (rather than always passing DBG_CONTINUE) prevents the
            # OS from silently swallowing unhandled exceptions inside the target.
            continue_status = self._handle_event(debug_event)
            if continue_status is None:
                continue_status = c.DBG_CONTINUE

            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId, debug_event.dwThreadId, continue_status
            )

            if not self.tracked:
                break  # All processes (parent and children) terminated

        self._cleanup()

    def _handle_event(self, debug_event: DEBUG_EVENT) -> int:
        """
        Dispatches one raw Windows debug event and returns the continue status
        for ContinueDebugEvent().

        Return values:
          DBG_CONTINUE (0x00010002)         -- We handled the event (INT3 hook,
                                               single-step after hook).
          DBG_EXCEPTION_NOT_HANDLED (0x80010001) -- Genuine program exception;
                                               pass it back to the program's
                                               own exception handler.
          None                              -- All other events (DLL load, thread
                                               create/exit, process exit, etc.).
                                               run() treats None as DBG_CONTINUE.
        """
        code = debug_event.dwDebugEventCode
        pid = debug_event.dwProcessId
        tid = debug_event.dwThreadId
        name = c.EVENT_CODE_NAMES.get(code, f"UNKNOWN({code})")

        if code == c.CREATE_PROCESS_DEBUG_EVENT:
            self._on_create_process(debug_event, pid)

        elif code == c.LOAD_DLL_DEBUG_EVENT:
            info = debug_event.u.LoadDll
            path = self._resolve_handle_path(info.hFile)
            if info.hFile:
                kernel32.CloseHandle(info.hFile)  # Prevent file lock on disk

            # lpBaseOfDll is a ctypes LPVOID — cast to int before storing in the event
            # payload because LPVOID is not JSON-serialisable.
            base_addr = int(info.lpBaseOfDll or 0)

            self._put_event(
                "debug_loop",
                "DLL",
                "LOADED",
                pid=pid,
                tid=tid,
                path=path,
                base_address=base_addr,
                base_address_hex=hex(base_addr),
            )

            tracked = self.tracked.get(pid)
            if tracked and tracked.handle:
                # When a DLL is loaded, try to hook its functions
                dll_name = path.split('\\')[-1] if path and path != "Unknown" else ""
                if dll_name:
                    self._setup_initial_hooks(tracked.handle, pid, target_dll=dll_name)

        elif code == c.CREATE_THREAD_DEBUG_EVENT:
            self._put_event("debug_loop", "THREAD", "CREATED", pid=pid, tid=tid)

        elif code == c.EXIT_THREAD_DEBUG_EVENT:
            info = debug_event.u.ExitThread
            # If the thread exits while a single-step is pending (i.e., the thread died
            # after hitting an INT3 hook but before EXCEPTION_SINGLE_STEP was received),
            # the tid would remain in pending_single_steps forever, leaking memory.
            # Pop it defensively to keep the dict bounded.
            removed = self.pending_single_steps.pop(tid, None)
            if removed is not None:
                _log.debug("Pruned dangling single-step entry for exited thread %d", tid)
            self._put_event(
                "debug_loop",
                "THREAD",
                "EXITED",
                pid=pid,
                tid=tid,
                exit_code=info.dwExitCode,
            )

        elif code == c.EXIT_PROCESS_DEBUG_EVENT:
            info = debug_event.u.ExitProcess
            tracked = self.tracked.pop(pid, None)
            self._put_event(
                "debug_loop",
                "PROCESS",
                "EXITED",
                pid=pid,
                tid=tid,
                exit_code=info.dwExitCode,
                is_root=(tracked.is_root if tracked else None),
            )
            if tracked and tracked.handle:
                kernel32.CloseHandle(tracked.handle)

        elif code == c.EXCEPTION_DEBUG_EVENT:
            info     = debug_event.u.Exception
            exc_code = info.ExceptionRecord.ExceptionCode
            exc_addr = info.ExceptionRecord.ExceptionAddress

            # Explicit returns here are propagated back to run() via _handle_event.
            # 1. Our Hook (INT3) — we handled it, tell OS to continue
            if exc_code == c.EXCEPTION_BREAKPOINT and self.hook_manager.is_our_hook(exc_addr, pid):
                self._handle_api_hook(pid, tid, exc_addr)
                return c.DBG_CONTINUE   # <- We handled it

            # 2. Single-step after hook — restore hook and tell OS to continue
            if exc_code == c.EXCEPTION_SINGLE_STEP and tid in self.pending_single_steps:
                self._handle_rehook(pid, tid)
                return c.DBG_CONTINUE   # <- We handled it

            # 3. Genuine exception from the program — log it and pass it to the program
            sev = Severity.SUSPICIOUS if info.dwFirstChance else Severity.INFO
            # EXCEPTION_ACCESS_VIOLATION deserves HIGH — frequently points to shellcode
            if exc_code == c.EXCEPTION_ACCESS_VIOLATION:
                sev = Severity.HIGH

            self._put_event(
                "debug_loop",
                "EXCEPTION",
                name,
                pid=pid,
                tid=tid,
                severity=sev,
                exception_code=hex(exc_code),
                first_chance=bool(info.dwFirstChance),
                address=int(info.ExceptionRecord.ExceptionAddress or 0),
            )
            return c.DBG_EXCEPTION_NOT_HANDLED  # <- Give it to the program

        elif code == c.UNLOAD_DLL_DEBUG_EVENT:
            info = debug_event.u.UnloadDll
            base_addr = int(info.lpBaseOfDll or 0)  # LPVOID is not JSON-serialisable
            self._put_event(
                "debug_loop",
                "DLL",
                "UNLOADED",
                pid=pid,
                tid=tid,
                base_address=base_addr,
                base_address_hex=hex(base_addr),
            )

        else:
            if code == c.OUTPUT_DEBUG_STRING_EVENT:
                self._handle_debug_string(debug_event, pid, tid)
            else:
                # RIP event — rare but log it
                self._put_event("debug_loop", "OTHER", name, pid=pid, tid=tid)

        return None  # run() will treat this as DBG_CONTINUE

    def _on_create_process(self, debug_event: DEBUG_EVENT, pid: int):
        info = debug_event.u.CreateProcessInfo
        tid = debug_event.dwThreadId
        is_root = pid == self.root_pid
        path = self._resolve_handle_path(info.hFile)

        _log.info("Process created: PID %d, Path: %s (Root: %s)", pid, path, is_root)

        # PEB Patching — hide the debugger from the program
        # Note: enable_stealth is controlled externally via EngineConfig (Phase 1)
        if self.enable_stealth:
            from bx2trace.memory.reader import patch_peb_stealth
            if patch_peb_stealth(info.hProcess):
                _log.info("Stealth patches applied to PID %d", pid)
            else:
                _log.warning("Stealth patches failed for PID %d", pid)
        else:
            _log.debug("Stealth patching disabled for PID %d (enable_stealth=False)", pid)

        # Apply API Hooks
        self._setup_initial_hooks(info.hProcess, pid)

        # Hardware Breakpoints on the main thread if requested
        if self.hw_breakpoints:
            self._set_hw_breakpoints(info.hThread)

        if info.hFile:
            kernel32.CloseHandle(info.hFile)

        if not is_root:
            if len(self.tracked) >= self.max_tracked_processes:
                # Emit an IGNORED event so the consumer knows why this child is absent
                # from subsequent events. Silent discard would make debugging very hard.
                _log.warning(
                    "Max tracked processes (%d) exceeded, ignoring PID %d",
                    self.max_tracked_processes, pid,
                )
                self._put_event(
                    "debug_loop", "PROCESS", "IGNORED",
                    pid=pid,
                    reason="max_tracked_processes_exceeded",
                    limit=self.max_tracked_processes,
                    path=path,
                )
                return  # Do not add to tracked

            self.tracked[pid] = TrackedProcess(
                pid=pid, handle=info.hProcess, path=path, is_root=False
            )

        # Include parent_pid so consumers can reconstruct the full process tree.
        parent_pid = self.root_pid if not is_root else None
        self._put_event(
            "debug_loop", "PROCESS", "CREATED",
            pid=pid,
            path=path,
            is_root=is_root,
            parent_pid=parent_pid,
        )

    def _handle_debug_string(self, debug_event: DEBUG_EVENT, pid: int, tid: int):
        """
        Read the actual string content from the target process memory.
        OutputDebugString is commonly used by malware to signal internal state;
        capturing it is valuable for analysis.
        """
        info = debug_event.u.DebugString
        tracked = self.tracked.get(pid)
        if not tracked or not tracked.handle:
            return
        size = min(info.nDebugStringLength, 4096)  # cap at 4KB
        if size == 0:
            return
        from bx2trace.memory.reader import read_region
        data = read_region(tracked.handle, info.lpDebugStringData, size)
        if data:
            encoding = "utf-16-le" if info.fUnicode else "ascii"
            text = data.decode(encoding, errors="ignore").strip("\x00").strip()
            if text:
                self._put_event(
                    "debug_loop", "OTHER", "OUTPUT_DEBUG_STRING",
                    pid=pid, tid=tid, message=text,
                )

    def _resolve_handle_path(self, h_file) -> str:
        if not h_file:
            return "Unknown"
        buf = ctypes.create_unicode_buffer(1024)
        result = kernel32.GetFinalPathNameByHandleW(h_file, buf, 1024, 0)
        if result > 0:
            path = buf.value
            return path[4:] if path.startswith("\\\\?\\") else path
        return "Unknown"

    def _set_hw_breakpoints(self, h_thread: wintypes.HANDLE):
        """Sets hardware breakpoints on the given thread."""
        ctx = CONTEXT()
        ctx.ContextFlags = 0x00100000 | 0x00000010  # CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS
        if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
            _log.error("Failed to get thread context for HW BP")
            return

        # Enable DR0-DR3 as needed
        for i, addr in enumerate(self.hw_breakpoints[:4]):
            setattr(ctx, f"Dr{i}", addr)
            # Enable locally for the thread (even bits in DR7: 0, 2, 4, 6)
            ctx.Dr7 |= (1 << (i * 2))
            # Set condition: 00 (execute), Size: 00 (1 byte) -> this is default

        if not kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)):
            _log.error("Failed to set thread context for HW BP")
        else:
            _log.info("Hardware breakpoints applied to thread %s", h_thread)

    def _cleanup(self):
        """Close all remaining Handles — we leave no dangling handles."""
        for tracked in self.tracked.values():
            if tracked.handle:
                kernel32.CloseHandle(tracked.handle)
        self.tracked.clear()

    # --- API Hooking Engine ---

    def _setup_initial_hooks(self, h_process: wintypes.HANDLE, pid: int, target_dll: str = None):
        """
        Plants INT3 hooks for all monitored APIs in the given process.

        Called in two situations:
          1. On CREATE_PROCESS_DEBUG_EVENT (target_dll=None): attempts to hook
             all APIs across all DLLs. Hooks may silently fail for DLLs not yet
             loaded at this point — they will be re-attempted when the DLL loads.
          2. On LOAD_DLL_DEBUG_EVENT (target_dll=<dll_name>): hooks only the
             APIs exported by the newly loaded DLL, catching DLLs that load late.
        """
        # Define APIs to hook grouped by category for readability.
        # Format: (dll_name, function_name)
        for dll, func in c.APIS_TO_HOOK:
            # If target_dll is specified (called from LOAD_DLL handler), only hook
            # functions exported by that specific DLL. When called from
            # CREATE_PROCESS handler (target_dll=None), all DLLs are attempted.
            if target_dll and dll.lower() != target_dll.lower():
                continue

            addr = self.hook_manager.resolve_api(dll, func)
            if addr:
                if self.hook_manager.apply_hook(h_process, addr, func, pid):
                    _log.info("Successfully hooked %s!%s at 0x%X in PID %d", dll, func, addr, pid)
                    self._put_event("hooker", EventCategory.SECURITY, "HOOK_PLACED", pid=pid,
                                    message=f"Placed hook on {dll}!{func} at {hex(addr)}")
                else:
                    # Normal to fail if DLL not yet loaded in the target process
                    pass


    def _handle_api_hook(self, pid: int, tid: int, address: int):
        """
        Called when an INT3 breakpoint fires on a hooked API.

        Reads the x64 calling convention argument registers (RCX, RDX, R8, R9)
        from the current thread context and dispatches to API-specific parsing
        logic that reads string / struct arguments from the target process memory.
        Emits the appropriate TraceEvent then calls _resume_from_hook() to
        restore the original byte and set the Trap Flag for single-step re-hooking.
        """
        api_name = self.hook_manager.get_api_name(address)
        tracked = self.tracked.get(pid)
        if not tracked or not tracked.handle:
            return

        # Open the faulting thread with permissions required to read/set its context.
        # Flags: THREAD_GET_CONTEXT (0x0008) | THREAD_SET_CONTEXT (0x0010)
        #        | THREAD_SUSPEND_RESUME (0x0002) | THREAD_QUERY_INFORMATION (0x0040)
        h_thread = kernel32.OpenThread(0x0018 | 0x0002 | 0x0040, False, tid)
        if not h_thread:
            _log.warning("Failed to open thread %d for API hook handling", tid)
            return

        try:
            ctx = CONTEXT()
            ctx.ContextFlags = c.CONTEXT_CONTROL | c.CONTEXT_INTEGER
            if kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                # x64 Calling Convention: RCX, RDX, R8, R9
                args = {
                    "rcx": ctx.Rcx,
                    "rdx": ctx.Rdx,
                    "r8": ctx.R8,
                    "r9": ctx.R9,
                }

                payload = {"api": api_name, "address": hex(address), "args": {k: hex(v) for k, v in args.items()}}

                # Heuristic: Resolve some strings if possible
                if "CreateProcess" in api_name:
                    # RCX is ApplicationName, RDX is CommandLine
                    # CreateProcessW uses LPWSTR, CreateProcessA uses LPSTR
                    is_wide = api_name.endswith("W")
                    if is_wide:
                        app_name = self._read_wstring(tracked.handle, ctx.Rcx)
                        cmd_line = self._read_wstring(tracked.handle, ctx.Rdx)
                    else:
                        app_name = self._read_astring(tracked.handle, ctx.Rcx)
                        cmd_line = self._read_astring(tracked.handle, ctx.Rdx)
                    payload["details"] = {"app_name": app_name, "command_line": cmd_line}

                elif api_name in ("connect", "WSAConnect"):
                    # RDX points to a sockaddr structure (PSOCKADDR)
                    # Read 28 bytes to cover both AF_INET (16 bytes) and AF_INET6 (28 bytes)
                    sockaddr_data = self._read_bytes(tracked.handle, ctx.Rdx, 28)
                    if sockaddr_data and len(sockaddr_data) >= 4:
                        try:
                            family = int.from_bytes(sockaddr_data[:2], 'little')

                            if family == _socket.AF_INET and len(sockaddr_data) >= 8:
                                # IPv4: port at [2:4] big-endian, IP at [4:8]
                                port = int.from_bytes(sockaddr_data[2:4], 'big')
                                ip = _socket.inet_ntoa(sockaddr_data[4:8])
                                payload["details"] = {
                                    "ip": ip, "port": port, "family": "IPv4"
                                }
                                self._put_event(
                                    "api_hook", EventCategory.NETWORK, EventAction.CONNECTED,
                                    pid, tid, severity=Severity.HIGH, **payload
                                )
                                self._resume_from_hook(h_thread, ctx, address, pid)
                                return

                            elif family == _socket.AF_INET6 and len(sockaddr_data) >= 28:
                                # IPv6: port at [2:4] big-endian, IP at [8:24] (16 bytes)
                                port = int.from_bytes(sockaddr_data[2:4], 'big')
                                ip = _socket.inet_ntop(
                                    _socket.AF_INET6, sockaddr_data[8:24]
                                )
                                payload["details"] = {
                                    "ip": ip, "port": port, "family": "IPv6"
                                }
                                self._put_event(
                                    "api_hook", EventCategory.NETWORK, EventAction.CONNECTED,
                                    pid, tid, severity=Severity.HIGH, **payload
                                )
                                self._resume_from_hook(h_thread, ctx, address, pid)
                                return

                        except Exception:
                            # Fallback: emit as generic NETWORK event with raw bytes
                            payload.setdefault("details", {"raw_sockaddr": sockaddr_data.hex() if sockaddr_data else "null"})
                            self._put_event(
                                "api_hook", EventCategory.NETWORK, EventAction.CONNECTED,
                                pid, tid, severity=Severity.SUSPICIOUS, **payload
                            )
                            self._resume_from_hook(h_thread, ctx, address, pid)
                            return

                elif "RegSetValueEx" in api_name:
                    # RegSetValueExW/A signature:
                    # RCX = hKey (HKEY handle)
                    # RDX = lpValueName (LPCWSTR / LPCSTR)
                    # R8  = Reserved (must be 0)
                    # R9  = dwType (DWORD)
                    is_wide = api_name.endswith("W")
                    val_name = (
                        self._read_wstring(tracked.handle, ctx.Rdx)
                        if is_wide
                        else self._read_astring(tracked.handle, ctx.Rdx)
                    )
                    reg_type = ctx.R9
                    type_name = c.REG_TYPE_NAMES.get(reg_type, f"UNKNOWN({reg_type})")

                    hkey_str = c._HKEY_NAMES.get(ctx.Rcx, hex(ctx.Rcx))

                    # Resolve the full registry key path via NtQueryKey so the
                    # RegistryPersistenceDetector can match it against known persistence
                    # paths (e.g. "software\microsoft\windows\currentversion\run").
                    # Without this, only the root key name and value name are available,
                    # which is insufficient for accurate path matching.
                    key_path = self._resolve_registry_key_path(ctx.Rcx)

                    payload["details"] = {
                        "hkey":       hkey_str,
                        "value_name": val_name,
                        "type":       type_name,
                        "key_path":   key_path,   # Full subkey path for persistence matching
                    }
                    self._put_event(
                        "api_hook", EventCategory.REGISTRY, "VALUE_SET",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif "RegDeleteValue" in api_name or "RegDeleteKey" in api_name:
                    # RCX = hKey, RDX = lpValueName / lpSubKey
                    is_wide = api_name.endswith("W")
                    key_name = (
                        self._read_wstring(tracked.handle, ctx.Rdx)
                        if is_wide
                        else self._read_astring(tracked.handle, ctx.Rdx)
                    )
                    hkey_str = c._HKEY_NAMES.get(ctx.Rcx, hex(ctx.Rcx))
                    payload["details"] = {
                        "hkey": hkey_str,
                        "key_or_value": key_name,
                    }
                    self._put_event(
                        "api_hook", EventCategory.REGISTRY, "VALUE_DELETED",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                # --- Network (extended Winsock handlers) ---

                elif api_name == "WSASend":
                    # RCX = SOCKET, RDX = LPWSABUF, R8 = dwBufferCount
                    # WSABUF layout (x64): ULONG len (4 bytes) + padding (4 bytes) + CHAR* buf (8 bytes)
                    wsabuf_data = self._read_bytes(tracked.handle, ctx.Rdx, 16)
                    send_len = 0
                    buf_preview = None
                    if wsabuf_data and len(wsabuf_data) >= 8:
                        send_len = int.from_bytes(wsabuf_data[:4], 'little')
                        # Read the actual buffer pointer (bytes 8-16 on x64)
                        if len(wsabuf_data) >= 16:
                            buf_ptr = int.from_bytes(wsabuf_data[8:16], 'little')
                            if buf_ptr:
                                raw = self._read_bytes(tracked.handle, buf_ptr, min(256, send_len or 256))
                                if raw:
                                    buf_preview = raw.decode('ascii', errors='replace').replace('\x00', '.')
                    payload["details"] = {
                        "socket":        hex(ctx.Rcx),
                        "buffer_count":  ctx.R8,
                        "bytes_to_send": send_len,
                    }
                    if buf_preview:
                        payload["details"]["buffer_preview"] = buf_preview[:128]
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, "DATA_SENT",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("getaddrinfo", "GetAddrInfoW", "gethostbyname"):
                    # RCX = pNodeName (hostname string)
                    if api_name == "GetAddrInfoW":
                        hostname = self._read_wstring(tracked.handle, ctx.Rcx)
                    else:
                        hostname = self._read_astring(tracked.handle, ctx.Rcx)
                    payload["details"] = {"hostname": hostname}
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, "DNS_LOOKUP",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("InternetConnectW", "InternetConnectA", "WinHttpConnect"):
                    # InternetConnect: RCX=hInternet, RDX=lpszServerName, R8=nServerPort
                    # WinHttpConnect:  RCX=hSession,  RDX=pswzServerName, R8=nServerPort
                    if api_name == "InternetConnectA":
                        hostname = self._read_astring(tracked.handle, ctx.Rdx)
                    else:
                        hostname = self._read_wstring(tracked.handle, ctx.Rdx)
                    port = ctx.R8
                    payload["details"] = {"hostname": hostname, "port": port, "protocol": "HTTP/HTTPS"}
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, "CONNECTED",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("WinHttpOpenRequest", "HttpOpenRequestW"):
                    # WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, ...)
                    # HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, ...)
                    # RCX=hConnect, RDX=Verb, R8=ObjectName, R9=Version
                    verb = self._read_wstring(tracked.handle, ctx.Rdx) if ctx.Rdx else "GET"
                    path = self._read_wstring(tracked.handle, ctx.R8) if ctx.R8 else ""
                    version = self._read_wstring(tracked.handle, ctx.R9) if ctx.R9 else "HTTP/1.1"
                    
                    payload["details"] = {
                        "method": verb,
                        "path": path,
                        "version": version
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, EventAction.HTTP_REQUEST,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "WinHttpSendRequest":
                    # WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength,
                    #                    lpOptional, dwOptionalLength, dwTotalLength, dwContext)
                    # RCX=hRequest, RDX=lpszHeaders, R8=dwHeadersLength,
                    # R9=lpOptional (POST body ptr), [RSP+0x28]=dwOptionalLength (DWORD)
                    headers = self._read_wstring(tracked.handle, ctx.Rdx) if ctx.Rdx else ""

                    post_len_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x28, 4)
                    post_len = int.from_bytes(post_len_bytes, 'little') if post_len_bytes else 0

                    post_body = ""
                    if ctx.R9 and post_len > 0:
                        raw_body = self._read_bytes(tracked.handle, ctx.R9, min(post_len, 256))
                        if raw_body:
                            post_body = raw_body.decode('ascii', errors='replace').replace('\x00', '.')

                    payload["details"] = {
                        "headers": headers,
                        "post_data_preview": post_body,
                        "post_data_length": post_len,
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, EventAction.HTTP_REQUEST,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("HttpSendRequestW", "HttpSendRequestA"):
                    # HttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
                    # RCX=hRequest, RDX=lpszHeaders, R8=dwHeadersLength (DWORD),
                    # R9=lpOptional (POST body ptr), [RSP+0x28]=dwOptionalLength (DWORD)
                    # NOTE: Unlike WinHttp, there is NO 6th or 7th arg — RSP+0x28 is already OptionalLength
                    is_wide = api_name.endswith("W")
                    headers = ""
                    if ctx.Rdx:
                        headers = self._read_wstring(tracked.handle, ctx.Rdx) if is_wide else self._read_astring(tracked.handle, ctx.Rdx)

                    post_len_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x28, 4)
                    post_len = int.from_bytes(post_len_bytes, 'little') if post_len_bytes else 0

                    post_body = ""
                    if ctx.R9 and post_len > 0:
                        raw_body = self._read_bytes(tracked.handle, ctx.R9, min(post_len, 256))
                        if raw_body:
                            post_body = raw_body.decode('ascii', errors='replace').replace('\x00', '.')

                    payload["details"] = {
                        "headers": headers,
                        "post_data_preview": post_body,
                        "post_data_length": post_len,
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, EventAction.HTTP_REQUEST,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("WinHttpReadData", "InternetReadFile"):
                    # WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)
                    # InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)
                    # RCX=handle, RDX=lpBuffer, R8=dwNumberOfBytesToRead, R9=lpdwNumberOfBytesRead
                    # Pre-hook: buffer is empty. We can only log that a read is happening.
                    payload["details"] = {
                        "bytes_requested": ctx.R8,
                        "buffer_ptr": hex(ctx.Rdx) if ctx.Rdx else None
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, EventAction.HTTP_RESPONSE,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "send":
                    # int send(SOCKET s, const char *buf, int len, int flags)
                    # RCX = SOCKET, RDX = buf pointer, R8 = len
                    send_len = ctx.R8
                    buf_preview = None
                    if ctx.Rdx and send_len > 0:
                        raw = self._read_bytes(tracked.handle, ctx.Rdx, min(256, send_len))
                        if raw:
                            buf_preview = raw.decode('ascii', errors='replace').replace('\x00', '.')
                    payload["details"] = {
                        "socket":        hex(ctx.Rcx),
                        "bytes_to_send": send_len,
                    }
                    if buf_preview:
                        payload["details"]["buffer_preview"] = buf_preview[:128]
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, "DATA_SENT",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "recv":
                    # int recv(SOCKET s, char *buf, int len, int flags)
                    # RCX = SOCKET, R8 = buffer capacity
                    payload["details"] = {
                        "socket":           hex(ctx.Rcx),
                        "buffer_capacity":  ctx.R8,
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, "DATA_RECEIVED",
                        pid, tid, severity=Severity.INFO, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                # --- File System Handlers ---

                elif api_name in ("CreateFileW", "CreateFileA"):
                    # RCX = lpFileName (LPCWSTR / LPCSTR)
                    # RDX = dwDesiredAccess (DWORD)
                    if api_name == "CreateFileW":
                        file_path = self._read_wstring(tracked.handle, ctx.Rcx)
                    else:
                        file_path = self._read_astring(tracked.handle, ctx.Rcx)

                    access = ctx.Rdx
                    # Decode access flags to named constants (winnt.h)
                    access_flags = [name for mask, name in c._ACCESS_MAP.items() if access & mask]
                    if not access_flags:
                        access_flags = [f"0x{access:08X}"]

                    payload["details"] = {
                        "path":   file_path,
                        "access": access_flags,
                    }
                    is_write = any(f in access_flags for f in ("GENERIC_WRITE", "FILE_WRITE_DATA", "FILE_APPEND_DATA"))
                    sev = Severity.SUSPICIOUS if is_write else Severity.INFO
                    self._put_event(
                        "api_hook", EventCategory.FILE, EventAction.OPENED,
                        pid, tid, severity=sev, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "WriteFile":
                    # RCX = hFile (HANDLE), RDX = lpBuffer, R8 = nNumberOfBytesToWrite
                    bytes_to_write = ctx.R8
                    is_pe = False
                    header_preview = None
                    if ctx.Rdx and bytes_to_write > 0:
                        header = self._read_bytes(tracked.handle, ctx.Rdx, 16)
                        if header and len(header) >= 2:
                            # MZ header (0x4D 0x5A) = Windows PE executable
                            is_pe = (header[0] == 0x4D and header[1] == 0x5A)
                            header_preview = header.hex()
                    payload["details"] = {
                        "bytes_count":    bytes_to_write,
                        "handle":         hex(ctx.Rcx),
                        "is_pe":          is_pe,
                    }
                    if header_preview:
                        payload["details"]["header_hex"] = header_preview
                    # PE file drop is a critical dropper indicator
                    sev = Severity.CRITICAL if is_pe else Severity.INFO
                    self._put_event(
                        "api_hook", EventCategory.FILE, EventAction.WRITTEN,
                        pid, tid, severity=sev, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("DeleteFileW", "DeleteFileA"):
                    # RCX = lpFileName
                    if api_name == "DeleteFileW":
                        file_path = self._read_wstring(tracked.handle, ctx.Rcx)
                    else:
                        file_path = self._read_astring(tracked.handle, ctx.Rcx)
                    payload["details"] = {"path": file_path}
                    self._put_event(
                        "api_hook", EventCategory.FILE, EventAction.DELETED,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "MoveFileExW":
                    # RCX = lpExistingFileName, RDX = lpNewFileName
                    src = self._read_wstring(tracked.handle, ctx.Rcx)
                    dst = self._read_wstring(tracked.handle, ctx.Rdx)
                    payload["details"] = {"source": src, "destination": dst}
                    self._put_event(
                        "api_hook", EventCategory.FILE, EventAction.MOVED,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                # --- Code Injection Handlers ---

                elif api_name == "VirtualAllocEx":
                    # RCX = hProcess (target), RDX = lpAddress, R8 = dwSize, R9 = flAllocationType
                    target_handle = ctx.Rcx
                    alloc_size    = ctx.R8
                    target_pid    = self._get_pid_from_handle(target_handle)  # Resolve PID for stable cross-event correlation
                    payload["details"] = {
                        "target_handle":  hex(target_handle),
                        "target_pid":     target_pid,   # Actual PID of the victim process
                        "alloc_size":     alloc_size,
                        "alloc_size_hex": hex(alloc_size),
                    }
                    self._put_event(
                        "api_hook", EventCategory.INJECTION, "VIRTUAL_ALLOC_EX",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "WriteProcessMemory":
                    # RCX = hProcess (target), RDX = lpBaseAddress, R8 = lpBuffer, R9 = nSize
                    target_handle = ctx.Rcx
                    target_addr   = ctx.Rdx
                    write_size    = ctx.R9
                    target_pid    = self._get_pid_from_handle(target_handle)  # Resolve PID for stable cross-event correlation
                    payload["details"] = {
                        "target_handle":  hex(target_handle),
                        "target_pid":     target_pid,      # Actual PID of the victim process
                        "target_address": hex(target_addr),
                        "write_size":     write_size,
                    }
                    self._put_event(
                        "api_hook", EventCategory.INJECTION, "WRITE_PROCESS_MEMORY",
                        pid, tid, severity=Severity.CRITICAL, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("CreateRemoteThread", "CreateRemoteThreadEx"):
                    # RCX = hProcess (target), RDX = lpThreadAttributes,
                    # R8  = dwStackSize,        R9  = lpStartAddress (entry point)
                    target_handle = ctx.Rcx
                    start_address = ctx.R9
                    target_pid    = self._get_pid_from_handle(target_handle)
                    payload["details"] = {
                        "target_handle": hex(target_handle),
                        "target_pid":    target_pid,
                        "start_address": hex(start_address),
                    }
                    self._put_event(
                        "api_hook", EventCategory.INJECTION, "CREATE_REMOTE_THREAD",
                        pid, tid, severity=Severity.CRITICAL, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "NtCreateUserProcess":
                    # Low-level NT process creation — used to bypass CreateProcessW hooks.
                    # RCX = ProcessHandle*, RDX = ThreadHandle*, R8 = ProcessDesiredAccess,
                    # R9  = ThreadDesiredAccess — actual path is in a RTL_USER_PROCESS_PARAMETERS
                    # structure that is too complex to parse here safely.
                    # We emit what we can to ensure it appears in the report.
                    payload["details"] = {
                        "note": "Direct NT-layer process creation — bypasses Win32 CreateProcess.",
                        "process_access": hex(ctx.R8),
                        "thread_access":  hex(ctx.R9),
                    }
                    self._put_event(
                        "api_hook", EventCategory.INJECTION, "NT_CREATE_PROCESS",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("ShellExecuteW", "ShellExecuteA", "ShellExecuteExW"):
                    is_wide = api_name.endswith("W")
                    if "Ex" in api_name:
                        p_exec_info = ctx.Rcx
                        file_ptr_bytes = self._read_bytes(tracked.handle, p_exec_info + 0x18, 8)
                        file_ptr = int.from_bytes(file_ptr_bytes, 'little') if file_ptr_bytes else 0
                        file_name = self._read_wstring(tracked.handle, file_ptr) if file_ptr else ""
                        
                        param_ptr_bytes = self._read_bytes(tracked.handle, p_exec_info + 0x20, 8)
                        param_ptr = int.from_bytes(param_ptr_bytes, 'little') if param_ptr_bytes else 0
                        params = self._read_wstring(tracked.handle, param_ptr) if param_ptr else ""
                        
                        dir_ptr_bytes = self._read_bytes(tracked.handle, p_exec_info + 0x28, 8)
                        dir_ptr = int.from_bytes(dir_ptr_bytes, 'little') if dir_ptr_bytes else 0
                        working_dir = self._read_wstring(tracked.handle, dir_ptr) if dir_ptr else ""
                        
                        show_cmd_bytes = self._read_bytes(tracked.handle, p_exec_info + 0x30, 4)
                        show_cmd = int.from_bytes(show_cmd_bytes, 'little') if show_cmd_bytes else 0
                        operation = "<from_ex>"
                    else:
                        operation = self._read_wstring(tracked.handle, ctx.Rdx) if is_wide else self._read_astring(tracked.handle, ctx.Rdx)
                        file_name = self._read_wstring(tracked.handle, ctx.R8) if is_wide else self._read_astring(tracked.handle, ctx.R8)
                        params = self._read_wstring(tracked.handle, ctx.R9) if is_wide else self._read_astring(tracked.handle, ctx.R9)
                        
                        dir_ptr_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x28, 8)
                        dir_ptr = int.from_bytes(dir_ptr_bytes, 'little') if dir_ptr_bytes else 0
                        working_dir = self._read_wstring(tracked.handle, dir_ptr) if is_wide else self._read_astring(tracked.handle, dir_ptr)
                        
                        show_cmd_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x30, 4)
                        show_cmd = int.from_bytes(show_cmd_bytes, 'little') if show_cmd_bytes else 0

                    is_hidden = (show_cmd == 0)
                    file_lower = file_name.lower()
                    is_known = any(interpreter in file_lower for interpreter in c._KNOWN_INTERPRETERS)

                    if is_known:
                        severity = Severity.CRITICAL
                    elif is_hidden:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.SUSPICIOUS

                    payload["details"] = {
                        "operation": operation,
                        "file": file_name,
                        "parameters": params,
                        "working_dir": working_dir,
                        "show_cmd": show_cmd,
                        "is_hidden": is_hidden,
                        "interpreter_match": is_known
                    }
                    self._put_event(
                        "api_hook", EventCategory.SCRIPT, EventAction.SHELL_EXECUTE,
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "LdrLoadDll":
                    # Manual DLL loading — used by reflective loaders and process hollowing.
                    # R8 = ModuleFileName (PUNICODE_STRING: Length(2) + MaxLength(2) + pad(4) + Buffer*(8))
                    dll_name = None
                    try:
                        if ctx.R8:
                            us_data = self._read_bytes(tracked.handle, ctx.R8, 16)
                            if us_data and len(us_data) >= 16:
                                buf_ptr = int.from_bytes(us_data[8:16], 'little')
                                str_len = int.from_bytes(us_data[:2], 'little')
                                if buf_ptr and str_len > 0:
                                    raw = self._read_bytes(tracked.handle, buf_ptr, min(str_len, 512))
                                    if raw:
                                        dll_name = raw.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    except Exception as e:
                        _log.debug("LdrLoadDll: failed to parse UNICODE_STRING at R8=0x%X: %s", ctx.R8, e)
                    payload["details"] = {
                        "dll_name": dll_name or "<unresolved>",
                    }
                    self._put_event(
                        "api_hook", EventCategory.DLL, "MANUAL_LOAD",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "SetWindowsHookExW":
                    # SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId)
                    # RCX = idHook (int), RDX = lpfn (callback), R8 = hmod, R9 = dwThreadId
                    # dwThreadId == 0 means a GLOBAL hook — highest danger because it intercepts ALL processes.
                    hook_id   = ctx.Rcx & 0xFFFFFFFF  # Treat as signed int; mask to DWORD
                    hook_id   = hook_id if hook_id <= 0x7FFFFFFF else hook_id - 0x100000000
                    callback  = ctx.Rdx
                    thread_id = ctx.R9 & 0xFFFFFFFF

                    hook_name    = c._HOOK_TYPE_NAMES.get(hook_id, f"UNKNOWN({hook_id})")
                    is_global    = (thread_id == 0)
                    is_dangerous = hook_id in c._SURVEILLANCE_HOOKS

                    if is_dangerous and is_global:
                        severity = Severity.CRITICAL
                    elif is_dangerous:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.SUSPICIOUS

                    payload["details"] = {
                        "hook_id":       hook_id,
                        "hook_name":     hook_name,
                        "callback":      hex(callback),
                        "thread_id":     thread_id,
                        "is_global":     is_global,
                        "is_dangerous":  is_dangerous,
                    }
                    self._put_event(
                        "api_hook", EventCategory.KEYLOG, EventAction.HOOK_INSTALLED,
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "GetClipboardData":
                    # GetClipboardData(uFormat)
                    # RCX = uFormat (UINT) — clipboard format ID
                    fmt = ctx.Rcx & 0xFFFFFFFF
                    payload["details"] = {
                        "format_id":   fmt,
                        "format_name": c._CF_NAMES.get(fmt, f"CF_UNKNOWN({fmt})"),
                    }
                    self._put_event(
                        "api_hook", EventCategory.CLIPBOARD, EventAction.CLIPBOARD_READ,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "SetClipboardData":
                    # SetClipboardData(uFormat, hMem)
                    # RCX = uFormat, RDX = hMem (handle to clipboard data)
                    fmt = ctx.Rcx & 0xFFFFFFFF
                    payload["details"] = {
                        "format_id":   fmt,
                        "format_name": c._CF_NAMES.get(fmt, f"CF_UNKNOWN({fmt})"),
                        "handle":      hex(ctx.Rdx),
                    }
                    self._put_event(
                        "api_hook", EventCategory.CLIPBOARD, EventAction.CLIPBOARD_WRITE,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent"):
                    # IsDebuggerPresent()        — no args; returns BOOL
                    # CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent) — RCX=hProcess, RDX=pbDebuggerPresent*
                    # Both calls indicate the target is probing its execution environment.
                    # We only capture the call (pre-return) — the return value itself requires
                    # a post-call hook (out-of-scope for Phase 4; future work).
                    payload["details"] = {
                        "api":                  api_name,
                        "anti_analysis":        True,
                        "note":                 "Process is checking for a debugger — possible sandbox evasion.",
                    }
                    if api_name == "CheckRemoteDebuggerPresent":
                        target_pid = self._get_pid_from_handle(ctx.Rcx)
                        payload["details"]["target_pid"] = target_pid

                    self._put_event(
                        "api_hook", EventCategory.ANTI_DEBUG, EventAction.DEBUGGER_CHECK,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "URLDownloadToFileW":
                    # URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB)
                    # RCX = pCaller (IUnknown* — usually NULL)
                    # RDX = szURL   (LPCWSTR)
                    # R8  = szFileName (LPCWSTR — local destination path)
                    # R9  = dwReserved (must be 0)
                    url       = self._read_wstring(tracked.handle, ctx.Rdx)
                    dest_path = self._read_wstring(tracked.handle, ctx.R8)
                    payload["details"] = {
                        "url":            url,
                        "destination":    dest_path,
                        "note":           "Direct HTTP-to-disk download — dropper/downloader signature.",
                    }
                    self._put_event(
                        "api_hook", EventCategory.NETWORK, EventAction.FILE_DOWNLOAD,
                        pid, tid, severity=Severity.CRITICAL, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "AdjustTokenPrivileges":
                    # AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLen, ...)
                    # RCX = TokenHandle (HANDLE)
                    # RDX = DisableAllPrivileges (BOOL) — TRUE = strip all privileges
                    # R8  = NewState (PTOKEN_PRIVILEGES pointer)
                    #
                    # TOKEN_PRIVILEGES layout (x64):
                    #   DWORD PrivilegeCount        [0:4]
                    #   LUID_AND_ATTRIBUTES[]:
                    #     LUID  LowPart (DWORD)     [4:8]
                    #     LUID  HighPart (LONG)      [8:12]
                    #     DWORD Attributes           [12:16]  (SE_PRIVILEGE_ENABLED=0x2)
                    #
                    # We use LookupPrivilegeNameW (local syscall, not target memory) to
                    # resolve the LUID to a human-readable privilege name. This is correct
                    # because the LUID values for standard privileges are identical across
                    # all sessions on the same machine (they come from the LSA).

                    disable_all = bool(ctx.Rdx & 0xFFFFFFFF)
                    new_state_ptr = ctx.R8
                    privilege_names: list[str] = []
                    attributes_list: list[int] = []

                    if not disable_all and new_state_ptr:
                        try:
                            raw_count = self._read_bytes(tracked.handle, new_state_ptr, 4)
                            count = int.from_bytes(raw_count, 'little') if raw_count else 0
                            count = min(count, 16)  # Safety cap — avoid runaway reads
                            for i in range(count):
                                entry_offset = new_state_ptr + 4 + i * 12
                                entry_raw = self._read_bytes(tracked.handle, entry_offset, 12)
                                if not entry_raw or len(entry_raw) < 12:
                                    continue
                                luid_low  = int.from_bytes(entry_raw[0:4], 'little')
                                luid_high = int.from_bytes(entry_raw[4:8], 'little')
                                attrs     = int.from_bytes(entry_raw[8:12], 'little')

                                # Resolve LUID → privilege name via local advapi32 call
                                advapi32 = ctypes.windll.advapi32
                                name_buf  = ctypes.create_unicode_buffer(128)
                                name_size = wintypes.DWORD(128)
                                luid_buf  = (ctypes.c_uint32 * 2)(luid_low, luid_high)
                                if advapi32.LookupPrivilegeNameW(None, luid_buf, name_buf, ctypes.byref(name_size)):
                                    privilege_names.append(name_buf.value)
                                else:
                                    privilege_names.append(f"LUID({luid_low:#010x},{luid_high:#010x})")
                                attributes_list.append(attrs)
                        except Exception as e:
                            _log.debug("AdjustTokenPrivileges: failed to parse TOKEN_PRIVILEGES: %s", e)

                    is_dangerous = any(p in c._DANGEROUS_PRIVILEGES for p in privilege_names)
                    enabled_flags = [(a & 0x2) != 0 for a in attributes_list]

                    if is_dangerous and any(enabled_flags):
                        severity = Severity.CRITICAL
                    elif is_dangerous:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.SUSPICIOUS

                    payload["details"] = {
                        "disable_all":       disable_all,
                        "privileges":        privilege_names,
                        "enabled_flags":     enabled_flags,
                        "is_dangerous":      is_dangerous,
                    }
                    self._put_event(
                        "api_hook", EventCategory.PRIVILEGE, EventAction.TOKEN_ADJUST,
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("DuplicateToken", "DuplicateTokenEx"):
                    # DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)
                    # RCX = ExistingTokenHandle
                    # RDX = ImpersonationLevel (SECURITY_IMPERSONATION_LEVEL)
                    # R8  = DuplicateTokenHandle*
                    #
                    # DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpAttr, ImpersonationLevel,
                    #                  TokenType, phNewToken)
                    # RCX = hExistingToken
                    # RDX = dwDesiredAccess (DWORD — TOKEN_* access flags)
                    # R8  = lpTokenAttributes (LPSECURITY_ATTRIBUTES)
                    # R9  = ImpersonationLevel (SECURITY_IMPERSONATION_LEVEL)
                    # [RSP+0x28] = TokenType (TOKEN_PRIMARY=1, TOKEN_IMPERSONATION=2)

                    if api_name == "DuplicateToken":
                        imp_level_raw = ctx.Rdx & 0xFFFFFFFF
                        desired_access = None
                        token_type_raw = None
                    else:
                        desired_access = ctx.Rdx & 0xFFFFFFFF
                        imp_level_raw  = ctx.R9 & 0xFFFFFFFF
                        ttype_bytes    = self._read_bytes(tracked.handle, ctx.Rsp + 0x28, 4)
                        token_type_raw = int.from_bytes(ttype_bytes, 'little') if ttype_bytes else None

                    imp_level_name = c._IMPERSONATION_LEVELS.get(imp_level_raw, f"UNKNOWN({imp_level_raw})")
                    token_type_name = {1: "TOKEN_PRIMARY", 2: "TOKEN_IMPERSONATION"}.get(token_type_raw, str(token_type_raw)) if token_type_raw is not None else None

                    # Delegation level grants network-wide impersonation — most dangerous.
                    severity = Severity.CRITICAL if imp_level_raw >= 3 else Severity.HIGH

                    payload["details"] = {
                        "api":                api_name,
                        "impersonation_level": imp_level_name,
                        "token_type":         token_type_name,
                        "desired_access":     hex(desired_access) if desired_access is not None else None,
                    }
                    self._put_event(
                        "api_hook", EventCategory.PRIVILEGE, EventAction.TOKEN_ADJUST,
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "ImpersonateLoggedOnUser":
                    # ImpersonateLoggedOnUser(hToken)
                    # RCX = hToken (HANDLE to a logged-on user token)
                    # After this call, the current thread runs with the identity of the token owner.
                    # Used in token relay attacks (e.g. RottenPotato, PrintSpoofer).
                    payload["details"] = {
                        "token_handle": hex(ctx.Rcx),
                        "note":         "Thread will impersonate the token owner — identity theft vector.",
                    }
                    self._put_event(
                        "api_hook", EventCategory.PRIVILEGE, EventAction.TOKEN_ADJUST,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("CryptEncrypt", "CryptDecrypt"):
                    # CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
                    # RCX=hKey, RDX=hHash, R8=Final, R9=dwFlags, [RSP+0x28]=pbData, [RSP+0x30]=pdwDataLen, [RSP+0x38]=dwBufLen
                    action = EventAction.ENCRYPT if api_name == "CryptEncrypt" else EventAction.DECRYPT
                    
                    data_len_ptr_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x30, 8)
                    data_len_ptr = int.from_bytes(data_len_ptr_bytes, 'little') if data_len_ptr_bytes else 0
                    
                    data_len = 0
                    if data_len_ptr:
                        len_bytes = self._read_bytes(tracked.handle, data_len_ptr, 4)
                        if len_bytes:
                            data_len = int.from_bytes(len_bytes, 'little')
                            
                    payload["details"] = {
                        "api": api_name,
                        "data_length": data_len,
                        "is_final": bool(ctx.R8),
                    }
                    self._put_event(
                        "api_hook", EventCategory.CRYPTO, action,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "CryptGenKey":
                    # CryptGenKey(hProv, Algid, dwFlags, phKey)
                    # RCX=hProv, RDX=Algid (ALG_ID), R8=dwFlags, R9=phKey
                    alg_id = ctx.Rdx & 0xFFFFFFFF
                    alg_name = c._CRYPT_ALG_NAMES.get(alg_id, f"UNKNOWN({hex(alg_id)})")
                    
                    payload["details"] = {
                        "algorithm_id": hex(alg_id),
                        "algorithm_name": alg_name,
                    }
                    self._put_event(
                        "api_hook", EventCategory.CRYPTO, EventAction.KEY_GENERATED,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "CryptImportKey":
                    # CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey)
                    # RCX=hProv, RDX=pbData, R8=dwDataLen, R9=hPubKey
                    payload["details"] = {
                        "key_data_length": ctx.R8,
                    }
                    self._put_event(
                        "api_hook", EventCategory.CRYPTO, "KEY_IMPORTED",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("BCryptEncrypt", "BCryptDecrypt"):
                    # BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags)
                    # BCryptDecrypt is identical
                    # RCX=hKey, RDX=pbInput, R8=cbInput
                    action = EventAction.ENCRYPT if api_name == "BCryptEncrypt" else EventAction.DECRYPT
                    payload["details"] = {
                        "api": api_name,
                        "data_length": ctx.R8,
                    }
                    self._put_event(
                        "api_hook", EventCategory.CRYPTO, action,
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "OpenSCManagerW":
                    # OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess)
                    payload["details"] = {
                        "desired_access": hex(ctx.R8) if ctx.R8 else None,
                        "note": "Accessing Service Control Manager"
                    }
                    self._put_event(
                        "api_hook", EventCategory.SERVICE, EventAction.CALLED,
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("CreateServiceW", "CreateServiceA"):
                    # CreateService(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, 
                    #               dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, ...)
                    # RCX, RDX, R8, R9
                    # [RSP+0x28] = dwServiceType
                    # [RSP+0x30] = dwStartType
                    # [RSP+0x38] = dwErrorControl
                    # [RSP+0x40] = lpBinaryPathName
                    
                    is_wide = api_name.endswith("W")
                    if is_wide:
                        service_name = self._read_wstring(tracked.handle, ctx.Rdx)
                        display_name = self._read_wstring(tracked.handle, ctx.R8)
                    else:
                        service_name = self._read_astring(tracked.handle, ctx.Rdx)
                        display_name = self._read_astring(tracked.handle, ctx.R8)
                        
                    start_type_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x30, 4)
                    start_type = int.from_bytes(start_type_bytes, 'little') if start_type_bytes else None
                    
                    bin_path_ptr_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x40, 8)
                    bin_path_ptr = int.from_bytes(bin_path_ptr_bytes, 'little') if bin_path_ptr_bytes else 0
                    
                    binary_path = ""
                    if bin_path_ptr:
                        binary_path = self._read_wstring(tracked.handle, bin_path_ptr) if is_wide else self._read_astring(tracked.handle, bin_path_ptr)

                    severity = Severity.HIGH
                    if binary_path:
                        lower_path = binary_path.lower()
                        if not ("system32" in lower_path or "syswow64" in lower_path):
                            severity = Severity.CRITICAL

                    payload["details"] = {
                        "service_name": service_name,
                        "display_name": display_name,
                        "start_type": start_type,
                        "binary_path": binary_path
                    }
                    self._put_event(
                        "api_hook", EventCategory.SERVICE, "SERVICE_CREATED",
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name in ("StartServiceW", "StartServiceA"):
                    # StartService(hService, dwNumServiceArgs, lpServiceArgVectors)
                    # RCX=hService (cannot easily get name without tracking hService, but we know a service started)
                    payload["details"] = {
                        "service_handle": hex(ctx.Rcx),
                    }
                    self._put_event(
                        "api_hook", EventCategory.SERVICE, "SERVICE_STARTED",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "ChangeServiceConfigW":
                    # ChangeServiceConfigW(hService, dwServiceType, dwStartType, dwErrorControl, 
                    #                      lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, 
                    #                      lpServiceStartName, lpPassword, lpDisplayName)
                    # [RSP+0x28] = lpBinaryPathName
                    bin_path_ptr_bytes = self._read_bytes(tracked.handle, ctx.Rsp + 0x28, 8)
                    bin_path_ptr = int.from_bytes(bin_path_ptr_bytes, 'little') if bin_path_ptr_bytes else 0
                    
                    binary_path = ""
                    if bin_path_ptr:
                        binary_path = self._read_wstring(tracked.handle, bin_path_ptr)

                    payload["details"] = {
                        "service_handle": hex(ctx.Rcx),
                        "new_binary_path": binary_path
                    }
                    self._put_event(
                        "api_hook", EventCategory.SERVICE, "SERVICE_CONFIG_CHANGED",
                        pid, tid, severity=Severity.HIGH, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "CreateNamedPipeW":
                    # CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances,
                    #                  nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttr)
                    # RCX=lpName, RDX=dwOpenMode, R8=dwPipeMode, R9=nMaxInstances
                    pipe_name = self._read_wstring(tracked.handle, ctx.Rcx) if ctx.Rcx else ""
                    open_mode_raw = ctx.Rdx & 0xFFFFFFFF
                    access_mode = c._PIPE_ACCESS_MODES.get(open_mode_raw & 0x3, f"MODE({hex(open_mode_raw)})")

                    # Known C2 framework default pipe name patterns (Cobalt Strike, Metasploit, etc.)
                    c2_pipe_patterns = ("msagent_", "postex_", "mojo.", "spoolss", "chrome.",
                                        "ntsvcs", "lsarpc", "samr", "epmapper")
                    is_c2_pattern = any(p in pipe_name.lower() for p in c2_pipe_patterns)
                    severity = Severity.CRITICAL if is_c2_pattern else Severity.HIGH

                    payload["details"] = {
                        "pipe_name":         pipe_name,
                        "access_mode":       access_mode,
                        "max_instances":     ctx.R9,
                        "c2_pattern_match":  is_c2_pattern,
                    }
                    self._put_event(
                        "api_hook", EventCategory.PIPE, "PIPE_CREATED",
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "ConnectNamedPipe":
                    # ConnectNamedPipe(hNamedPipe, lpOverlapped)
                    # RCX=hNamedPipe, RDX=lpOverlapped (NULL = synchronous)
                    payload["details"] = {
                        "pipe_handle": hex(ctx.Rcx),
                        "is_async":    bool(ctx.Rdx),
                    }
                    self._put_event(
                        "api_hook", EventCategory.PIPE, "PIPE_CONNECTED",
                        pid, tid, severity=Severity.SUSPICIOUS, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                elif api_name == "CoCreateInstance":
                    # CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)
                    # RCX=rclsid pointer (16-byte GUID struct in target memory)
                    # RDX=pUnkOuter, R8=dwClsContext (CLSCTX_*)
                    clsid_str = ""
                    if ctx.Rcx:
                        # GUID layout: DWORD(4) + WORD(2) + WORD(2) + BYTE[8]
                        raw = self._read_bytes(tracked.handle, ctx.Rcx, 16)
                        if raw and len(raw) == 16:
                            d1 = int.from_bytes(raw[0:4], 'little')
                            d2 = int.from_bytes(raw[4:6], 'little')
                            d3 = int.from_bytes(raw[6:8], 'little')
                            d4 = raw[8:16]
                            clsid_str = (
                                f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
                                f"{d4[0]:02X}{d4[1]:02X}-"
                                f"{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}"
                                f"{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}}}"
                            )

                    known_name = c._DANGEROUS_CLSIDS.get(clsid_str, "")
                    severity = Severity.CRITICAL if known_name else Severity.SUSPICIOUS

                    payload["details"] = {
                        "clsid":        clsid_str,
                        "known_object": known_name or "UNKNOWN",
                        "cls_context":  ctx.R8,
                    }
                    self._put_event(
                        "api_hook", EventCategory.COM, "COM_CREATED",
                        pid, tid, severity=severity, **payload
                    )
                    self._resume_from_hook(h_thread, ctx, address, pid)
                    return

                self._put_event("api_hook", EventCategory.API, EventAction.CALLED, pid, tid, **payload)
                self._resume_from_hook(h_thread, ctx, address, pid)


        finally:
            kernel32.CloseHandle(h_thread)

    def _read_wstring(self, h_process, address, max_len=512) -> str:
        """Read a null-terminated UTF-16-LE string from process memory."""
        if not address:
            return "NULL"
        from bx2trace.memory.reader import read_region
        # Progressive fallback for page-boundary reads:
        # Reading max_len*2 bytes when the address is near a page boundary may
        # cross into an unreadable guard page and fail entirely.
        # Retry with smaller sizes so we always return whatever we can read.
        for byte_size in (max_len * 2, 256, 64):
            data = read_region(h_process, address, byte_size)
            if data:
                break
        if not data:
            return "ErrorReadingMemory"
        try:
            return data.decode("utf-16-le").split("\0")[0]
        except Exception:
            return "DecodeError"

    def _read_astring(self, h_process, address, max_len=512) -> str:
        """Read a null-terminated ASCII/ANSI string from process memory."""
        if not address:
            return "NULL"
        from bx2trace.memory.reader import read_region
        data = read_region(h_process, address, max_len)
        if not data:
            return "ErrorReadingMemory"
        try:
            return data.split(b"\x00")[0].decode("ascii", errors="replace")
        except Exception:
            return "DecodeError"

    def _read_bytes(self, h_process, address, size) -> bytes | None:
        """Read raw bytes from process memory."""
        if not address:
            return None
        from bx2trace.memory.reader import read_region
        return read_region(h_process, address, size)

    def _resume_from_hook(self, h_thread, ctx, address, pid):
        """Restores the original byte, single-steps, and prepares to re-hook."""
        tracked = self.tracked.get(pid)
        if not tracked: return

        # 1. Restore original byte
        self.hook_manager.remove_hook(tracked.handle, address, pid)

        # 2. Reset RIP to the instruction start (it's at address+1 after INT3)
        ctx.Rip = address

        # 3. Set Trap Flag (TF) in EFlags (0x100) to single-step
        ctx.EFlags |= 0x100

        kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))

        # 4. Mark that we need to re-hook this address after the next step
        tid = kernel32.GetThreadId(h_thread)
        self.pending_single_steps[tid] = address

    def _get_pid_from_handle(self, handle_value: int) -> int | None:
        """
        Converts a process HANDLE value to the actual Windows PID via GetProcessId().

        Using the PID as a correlation key (instead of the raw handle integer) is
        essential for accurate injection detection: a process can be opened multiple
        times, each time producing a different handle value that all refer to the same
        PID. Handle-based correlation would therefore miss injection events that use
        separate handles for WriteProcessMemory and CreateRemoteThread.

        Returns None if the handle is 0 / invalid or if GetProcessId() fails.
        """
        if not handle_value:
            return None
        try:
            pid = kernel32.GetProcessId(ctypes.c_void_p(handle_value))
            return int(pid) if pid else None
        except Exception:
            return None

    def _resolve_registry_key_path(self, hkey_value: int) -> str:
        """
        Resolves the full registry subkey path for an open HKEY handle.

        Uses NtQueryKey(KeyNameInformation=3) which returns the complete NT object
        manager path (e.g. "\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Run").
        The NT prefix is stripped to produce the relative subkey path that can be
        compared directly against known persistence locations.

        Predefined root keys (HKLM, HKCU, etc.) are returned by name without a syscall.
        Returns hex(hkey) as a safe fallback if the query fails.
        """
        # Use module-level c._HKEY_NAMES for predefined root key handles
        if hkey_value in c._HKEY_NAMES:
            return c._HKEY_NAMES[hkey_value]

        try:
            import ctypes as _ct
            ntdll = _ct.windll.ntdll
            # KeyNameInformation = 3; layout: ULONG Length + WCHAR Name[]
            buf_size = 1024
            buf = _ct.create_string_buffer(buf_size)
            result_len = _ct.c_ulong(0)
            status = ntdll.NtQueryKey(
                _ct.c_void_p(hkey_value), 3,
                buf, buf_size, _ct.byref(result_len)
            )
            if status == 0:  # STATUS_SUCCESS
                name_len = int.from_bytes(buf.raw[:4], "little")
                raw_name = buf.raw[4: 4 + name_len]
                full_path = raw_name.decode("utf-16-le", errors="ignore")
                # Strip well-known NT prefixes to get the relative subkey path
                for prefix in (
                    r"\Registry\Machine\\",
                    r"\Registry\User\\",
                    r"\Registry\Machine",
                    r"\Registry\User",
                ):
                    if full_path.lower().startswith(prefix.lower()):
                        return full_path[len(prefix):].lower()
                return full_path.lower()
        except Exception:
            pass
        return hex(hkey_value)

    def _handle_rehook(self, pid: int, tid: int):
        """Re-applies the hook after a single step."""
        address = self.pending_single_steps.pop(tid, None)
        if not address: return

        tracked = self.tracked.get(pid)
        if not tracked or not tracked.handle: return

        api_name = self.hook_manager.get_api_name(address)
        self.hook_manager.apply_hook(tracked.handle, address, api_name, pid)
