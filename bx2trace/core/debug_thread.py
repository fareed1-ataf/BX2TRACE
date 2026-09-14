"""
core/debug_thread.py
======================
This file runs the WaitForDebugEvent loop inside a completely separate Thread
(pure sync, no relation to asyncio — refer to the architectural decision we discussed:
WaitForDebugEvent blocks the Thread and there is no real benefit from
asyncio here because there is no concurrent I/O in a way that benefits it).

Its only responsibility: "Produce a clean TraceEvent for each raw event, and put it in the queue."
It does not process, does not analyze, does not extract strings — all of that is the responsibility
of other layers consuming from the queue.

Critical concurrency rule: tracked_processes (PID→Handle dictionary) is read
and written ONLY from inside this Thread. Do not touch it from any other Thread —
this prevents Race Conditions entirely instead of dealing with them using complex locks.
"""

import ctypes
import logging
import queue
import os
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
    """Information for a single process we are monitoring — parent or any child."""

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
    ):
        super().__init__(daemon=True, name=f"bx2trace-debug-{_uuid.uuid4().hex[:8]}")
        self.exe_path = exe_path
        self.cmd_args = cmd_args
        self.mode = mode
        self.raw_event_queue = raw_event_queue
        self.max_tracked_processes = max_tracked_processes
        self.create_new_console = create_new_console
        self.hw_breakpoints = hw_breakpoints or []
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
            # ↑ 200ms timeout instead of INFINITE: this doesn't slow down monitoring (the event
            #   arrives immediately if it happens), but it gives us a chance to check _stop_event
            #   periodically instead of waiting forever if the user requested a stop
            #   and the target program is "quiet" (no new events right now).
            if not got_event:
                continue  # Timeout expired without an event — normal, check again

            self._handle_event(debug_event)

            continue_status = c.DBG_CONTINUE
            code = debug_event.dwDebugEventCode
            if code == c.EXCEPTION_DEBUG_EVENT:
                # By default, we pass every exception to the program's own handler, unless
                # it was an exception we expected (Hardware Breakpoint in the future).
                # This prevents crashing programs that use exceptions as a legitimate mechanism
                # (many Packers do this).
                continue_status = c.DBG_EXCEPTION_NOT_HANDLED

            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId, debug_event.dwThreadId, continue_status
            )

            if not self.tracked:
                break  # All processes (parent and children) terminated

        self._cleanup()

    def _handle_event(self, debug_event: DEBUG_EVENT):
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
            self._put_event(
                "debug_loop",
                "DLL",
                "LOADED",
                pid=pid,
                tid=tid,
                path=path,
                base_address=info.lpBaseOfDll,
            )

            tracked = self.tracked.get(pid)
            if tracked and tracked.handle:
                # When a DLL is loaded, check if it's one we want to hook
                dll_name = path.split('\\')[-1] if path else ""
                self._setup_initial_hooks(tracked.handle, pid, target_dll=dll_name)

        elif code == c.CREATE_THREAD_DEBUG_EVENT:
            self._put_event("debug_loop", "THREAD", "CREATED", pid=pid, tid=tid)

        elif code == c.EXIT_THREAD_DEBUG_EVENT:
            info = debug_event.u.ExitThread
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
            info = debug_event.u.Exception
            exc_code = info.ExceptionRecord.ExceptionCode
            exc_addr = info.ExceptionRecord.ExceptionAddress

            # 1. Check if it's our API Hook (INT3)
            if exc_code == c.EXCEPTION_BREAKPOINT and self.hook_manager.is_our_hook(exc_addr, pid):
                self._handle_api_hook(pid, tid, exc_addr)
                return c.DBG_CONTINUE

            # 2. Check if it's our Single Step (TF) for re-hooking
            if exc_code == c.EXCEPTION_SINGLE_STEP and tid in self.pending_single_steps:
                self._handle_rehook(pid, tid)
                return c.DBG_CONTINUE

            severity = (
                Severity.SUSPICIOUS
                if info.dwFirstChance and exc_code not in (c.EXCEPTION_BREAKPOINT,)
                else Severity.INFO
            )
            self._put_event(
                "debug_loop",
                "EXCEPTION",
                name,
                pid=pid,
                tid=tid,
                severity=severity,
                exception_code=hex(exc_code),
                first_chance=bool(info.dwFirstChance),
                address=info.ExceptionRecord.ExceptionAddress,
            )

        elif code == c.UNLOAD_DLL_DEBUG_EVENT:
            info = debug_event.u.UnloadDll
            self._put_event(
                "debug_loop",
                "DLL",
                "UNLOADED",
                pid=pid,
                tid=tid,
                base_address=info.lpBaseOfDll,
            )

        else:
            if code == c.OUTPUT_DEBUG_STRING_EVENT:
                # Read the actual debug message from process memory
                self._handle_debug_string(debug_event, pid, tid)
            else:
                # RIP event — rare but log it instead of silently ignoring
                self._put_event("debug_loop", "OTHER", name, pid=pid, tid=tid)

    def _on_create_process(self, debug_event: DEBUG_EVENT, pid: int):
        info = debug_event.u.CreateProcessInfo
        tid = debug_event.dwThreadId
        is_root = pid == self.root_pid
        path = self._resolve_handle_path(info.hFile)

        _log.info("Process created: PID %d, Path: %s (Root: %s)", pid, path, is_root)

        # Apply PEB Patching for Stealth
        from bx2trace.memory.reader import patch_peb_stealth
        if patch_peb_stealth(info.hProcess):
            _log.info("Successfully applied stealth patches to PID %d", pid)
        else:
            _log.warning("Failed to apply stealth patches to PID %d", pid)

        # Apply API Hooks
        self._setup_initial_hooks(info.hProcess, pid)

        # Apply Hardware Breakpoints to the main thread
        if self.hw_breakpoints:
            self._set_hw_breakpoints(info.hThread)

        if info.hFile:
            kernel32.CloseHandle(info.hFile)

        if not is_root:
            if len(self.tracked) >= self.max_tracked_processes:
                # Protection limit: Prevent TraceBox resource exhaustion if the target
                # spawns processes at an abnormal rate (intentional or a bug in the target).
                _log.warning(
                    "Max tracked processes (%d) exceeded, ignoring PID %d",
                    self.max_tracked_processes, pid,
                )
                return
            # ⚠️ We store the correct handle specific to this particular process —
            #   this fixes the vulnerability that was in the original code (using the root
            #   process handle for all children).
            self.tracked[pid] = TrackedProcess(
                pid=pid, handle=info.hProcess, path=path, is_root=False
            )

        self._put_event(
            "debug_loop", "PROCESS", "CREATED", pid=pid, path=path, is_root=is_root
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
        """Resolves and applies initial hooks for analysis."""
        # Define APIs to hook (DLL, Function)
        apis_to_hook = [
            ("kernel32.dll", "CreateProcessW"),
            ("kernel32.dll", "CreateProcessA"),
            ("ws2_32.dll", "connect"),
            ("ws2_32.dll", "send"),
            ("ws2_32.dll", "recv"),
            ("advapi32.dll", "RegSetValueExW"),
            ("advapi32.dll", "RegSetValueExA"),
            ("ntdll.dll", "NtCreateUserProcess"),
            ("ntdll.dll", "LdrLoadDll"),
        ]

        for dll, func in apis_to_hook:
            # If target_dll is specified, only hook functions in that DLL
            if target_dll and dll.lower() != target_dll.lower():
                continue

            addr = self.hook_manager.resolve_api(dll, func)
            if addr:
                if self.hook_manager.apply_hook(h_process, addr, func, pid):
                    _log.info("Successfully hooked %s!%s at 0x%X in PID %d", dll, func, addr, pid)
                    # Force event for hook placement verification
                    self._put_event("hooker", EventCategory.SECURITY, "HOOK_PLACED", pid=pid,
                                    message=f"Placed hook on {dll}!{func} at {hex(addr)}")
                else:
                    # It's normal to fail if the address is not in this process's context yet
                    pass

    def _handle_api_hook(self, pid: int, tid: int, address: int):
        """Extracts arguments from a hooked API and fires an event."""
        api_name = self.hook_manager.get_api_name(address)
        tracked = self.tracked.get(pid)
        if not tracked or not tracked.handle:
            return

        # Use THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION
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
                    # RCX is ApplicationName (LPWSTR), RDX is CommandLine (LPWSTR)
                    app_name = self._read_wstring(tracked.handle, ctx.Rcx)
                    cmd_line = self._read_wstring(tracked.handle, ctx.Rdx)
                    payload["details"] = {"app_name": app_name, "command_line": cmd_line}

                elif api_name in ("connect", "WSAConnect"):
                    # RDX is sockaddr structure (PSOCKADDR)
                    # We can try to read the IP and Port
                    sockaddr_data = self._read_bytes(tracked.handle, ctx.Rdx, 16)
                    if sockaddr_data:
                        import socket
                        try:
                            # Simple IPv4 parsing (Family is first 2 bytes)
                            family = int.from_bytes(sockaddr_data[:2], 'little')
                            if family == 2:  # AF_INET
                                port = int.from_bytes(sockaddr_data[2:4], 'big')
                                ip = socket.inet_ntoa(sockaddr_data[4:8])
                                payload["details"] = {"ip": ip, "port": port}
                                self._put_event("api_hook", EventCategory.NETWORK, EventAction.CONNECTED, pid, tid,
                                                severity=Severity.HIGH, **payload)
                                # Skip general API event if it's already a NETWORK event
                                self._resume_from_hook(h_thread, ctx, address, pid)
                                return
                        except:
                            pass

                elif "RegSetValueEx" in api_name:
                    # RDX is ValueName (LPWSTR)
                    val_name = self._read_wstring(tracked.handle, ctx.Rdx)
                    payload["details"] = {"value_name": val_name}

                self._put_event("api_hook", EventCategory.API, EventAction.CALLED, pid, tid, **payload)
                self._resume_from_hook(h_thread, ctx, address, pid)
        finally:
            kernel32.CloseHandle(h_thread)

    def _read_wstring(self, h_process, address, max_len=512) -> str:
        if not address: return "NULL"
        from bx2trace.memory.reader import read_region
        data = read_region(h_process, address, max_len * 2)
        if not data: return "ErrorReadingMemory"
        try:
            return data.decode("utf-16-le").split("\0")[0]
        except:
            return "DecodeError"

    def _read_bytes(self, h_process, address, size) -> bytes | None:
        if not address: return None
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

    def _handle_rehook(self, pid: int, tid: int):
        """Re-applies the hook after a single step."""
        address = self.pending_single_steps.pop(tid, None)
        if not address: return

        tracked = self.tracked.get(pid)
        if not tracked or not tracked.handle: return

        api_name = self.hook_manager.get_api_name(address)
        self.hook_manager.apply_hook(tracked.handle, address, api_name, pid)
