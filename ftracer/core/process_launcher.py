"""
core/process_launcher.py
==========================
Single responsibility: "Give me an executable path and a run mode, return a running process
under official Windows monitoring." This file knows nothing about the event loop
that comes after it — that is the responsibility of core/debug_thread.py.
"""

import ctypes
import os
from ctypes import wintypes

from ftracer.core import constants as c
from ftracer.core.win_structs import PROCESS_INFORMATION, STARTUPINFO

kernel32 = ctypes.windll.kernel32

# --- Explicitly set parameter types (mandatory on 64-bit, otherwise silent crashes) ---
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL


class ArchitectureMismatchError(Exception):
    """Raised when we detect an architecture mismatch (32-bit target under a 64-bit monitor)."""

    pass


def _check_architecture_compat(process_handle: wintypes.HANDLE) -> None:
    """
    Explicit WOW64 check — without this check, reading memory later on a 32-bit process
    from a 64-bit monitor yields corrupt addresses and structures "silently" without any
    obvious error. We refuse to proceed rather than returning unreliable results.
    """
    is_wow64 = wintypes.BOOL()
    if not kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64)):
        # The check itself failed — we don't prevent execution, but we warn (maybe older Windows)
        return
    if is_wow64.value:
        raise ArchitectureMismatchError(
            "The target process is 32-bit (WOW64) and this monitor is built for 64-bit. "
            "Memory reading will not be reliable with the current version. "
            "Workaround: use a 32-bit Python version to run TraceBox, "
            "or add explicit WOW64 support in memory/reader.py before continuing."
        )


def create_process_debug(
        exe_path: str,
        mode: "TraceMode",  # noqa: F821  (avoid circular import — type for documentation only)
        create_new_console: bool = True,
        cmd_args: str = "",
) -> PROCESS_INFORMATION:
    """
    Launches exe_path under the appropriate Debug mode based on mode, and returns
    PROCESS_INFORMATION (PID + Handles) upon success.

    Raises FileNotFoundError if the path doesn't exist (early check is clearer than
    letting Windows return an obscure error code).
    Raises OSError with a message containing the GetLastError code on CreateProcessW failure.
    """
    if not os.path.isfile(exe_path):
        raise FileNotFoundError(f"File not found: {exe_path}")

    from ftracer.core.models import TraceMode  # local import to avoid circular dependency

    creation_flags = c.DEBUG_PROCESS  # ← Automatically monitors children
    if create_new_console and mode != TraceMode.MONITOR_ONLY:
        # FIX: original code used `=` (overwrite) at MONITOR_ONLY branch, silently
        # discarding CREATE_NEW_CONSOLE. We now gate the flag addition here instead.
        creation_flags |= c.CREATE_NEW_CONSOLE
    # In MONITOR_ONLY we intentionally leave creation_flags = DEBUG_PROCESS only.

    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(STARTUPINFO)
    process_info = PROCESS_INFORMATION()

    # FIX: Wrap exe_path in double-quotes so CreateProcessW treats paths that
    # contain spaces (e.g. C:\Program Files\app.exe) as a single argument.
    # Without quotes, Windows splits on the first space and fails silently.
    cmd_line = f'"{exe_path}"'
    if cmd_args:
        cmd_line += f" {cmd_args}"

    cmdline_buffer = ctypes.create_unicode_buffer(cmd_line)

    success = kernel32.CreateProcessW(
        None,  # lpApplicationName — leave it None, rely on lpCommandLine
        cmdline_buffer,  # lpCommandLine
        None,
        None,  # Security attributes for process and thread (default)
        False,  # bInheritHandles — always False here; True leaks
        # any Handle open in TraceBox itself to the target process
        creation_flags,
        None,  # Environment — inherits current TraceBox environment
        os.path.dirname(exe_path) or None,  # Working directory = file's own directory
        # ↑ Important: many programs look for side-by-side files (DLLs, settings)
        #   in their own directory. If we leave it None, it inherits TraceBox's directory instead of
        #   the target's directory, and the target might fail to find its files.
        ctypes.byref(startup_info),
        ctypes.byref(process_info),
    )

    if not success:
        error_code = kernel32.GetLastError()
        raise OSError(
            f"CreateProcessW failed on '{exe_path}'. Error code: {error_code} "
            f"(0x{error_code:08X}). Common reasons: insufficient privileges, "
            f"protected process (PPL), or running TraceBox without Administrator privileges."
        )

    try:
        _check_architecture_compat(process_info.hProcess)
    except ArchitectureMismatchError:
        # Close everything and terminate the target process instead of leaving it suspended under a failed monitor
        kernel32.TerminateProcess(process_info.hProcess, 1)
        kernel32.CloseHandle(process_info.hThread)
        kernel32.CloseHandle(process_info.hProcess)
        raise

    return process_info
