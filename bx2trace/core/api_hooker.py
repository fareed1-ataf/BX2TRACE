"""
core/api_hooker.py
==================
Manages software INT3 (0xCC) breakpoints on Windows API functions inside a
debugged process.

Responsibilities:
  - Resolve API addresses using GetModuleHandleW / LoadLibraryExW + GetProcAddress.
  - Write a single 0xCC byte at the function's entry point (INT3 hook).
  - Backup the original byte so it can be restored after the hook fires.
  - Manage page protection (VirtualProtectEx) to make the code page writable
    before writing and restore it afterward.
  - Flush the CPU instruction cache (FlushInstructionCache) after every write
    so all cores see the updated byte immediately.
  - Verify each write by reading back the planted 0xCC.
  - Track hooks per (pid, address) pair to support multi-process sessions
    where different child processes share the same DLL base addresses.

Note: Address resolution via GetModuleHandleW works reliably for system DLLs
(kernel32, ntdll, advapi32, ws2_32) because Windows maps them at the same
virtual address across all processes in a single boot session (Shared ASLR).
Custom/private DLLs require PE analysis to resolve addresses accurately.
"""

import ctypes
from ctypes import wintypes
from typing import Dict, Optional, Tuple


class HookManager:
    """
    Manages API hooks for a debugged process.
    Handles address resolution, INT3 placement, and original byte tracking.
    """

    def __init__(self):
        self.hooks = {}  # (pid, addr) -> byte  # Address -> Original Byte
        self.api_names: Dict[int, str] = {}  # Address -> API Name
        self.kernel32 = ctypes.windll.kernel32

        # Explicit argtypes and restype declarations for kernel32 functions.
        # MANDATORY on 64-bit Windows: without these, ctypes defaults to returning
        # C int (32-bit), which silently truncates 64-bit HANDLE / LPVOID values
        # causing hook bytes to land at the wrong address and crash the target.
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype  = wintypes.HMODULE

        self.kernel32.LoadLibraryExW.argtypes = [
            wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD,
        ]
        self.kernel32.LoadLibraryExW.restype = wintypes.HMODULE

        self.kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
        self.kernel32.FreeLibrary.restype  = wintypes.BOOL

        self.kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        self.kernel32.GetProcAddress.restype  = wintypes.LPVOID

        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL

        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL

        self.kernel32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.VirtualProtectEx.restype = wintypes.BOOL

        self.kernel32.FlushInstructionCache.argtypes = [
            wintypes.HANDLE, wintypes.LPCVOID, ctypes.c_size_t,
        ]
        self.kernel32.FlushInstructionCache.restype = wintypes.BOOL
        # ─────────────────────────────────────────────────────────────────────

    def resolve_api(self, dll_name: str, function_name: str) -> Optional[int]:
        """
        Resolve the virtual address of a function exported by a system DLL.

        Resolution strategy:
        1. GetModuleHandleW: If the DLL is already loaded in the bx2trace process
           (which is always the case for system DLLs like kernel32.dll), returns its
           handle without any disk I/O.
        2. LoadLibraryExW with LOAD_LIBRARY_AS_DATAFILE: Loads the DLL as a data
           file — DllMain is NOT executed, no side effects. Used only if step 1 fails.
           The handle is freed immediately after GetProcAddress returns.

        This works for system DLLs because Windows uses Shared ASLR: they are mapped
        at the same base address in bx2trace as in the monitored process within the
        same boot session.

        Returns the integer virtual address, or None if resolution fails.
        """
        LOAD_LIBRARY_AS_DATAFILE = 0x00000002  # Does not execute DllMain — safe
        try:
            h_module = self.kernel32.GetModuleHandleW(dll_name)
            if h_module:
                # DLL is already loaded in bx2trace — use handle directly
                addr = self.kernel32.GetProcAddress(h_module, function_name.encode('ascii'))
                return int(addr) if addr else None

            # Do not use old LoadLibraryW because it loads DLL and executes DllMain
            # Instead: LOAD_LIBRARY_AS_DATAFILE = reads addresses without execution
            h_temp = self.kernel32.LoadLibraryExW(dll_name, None, LOAD_LIBRARY_AS_DATAFILE)
            if not h_temp:
                return None

            try:
                addr = self.kernel32.GetProcAddress(h_temp, function_name.encode('ascii'))
                return int(addr) if addr else None
            finally:
                # Immediate cleanup — we don't want to keep the handle
                self.kernel32.FreeLibrary(h_temp)

        except Exception:
            return None

    def apply_hook(self, process_handle: int, address: int, api_name: str, pid: int) -> bool:
        """
        Plants an INT3 (0xCC) breakpoint at the function entry point.

        Steps:
          1. Read the current byte at `address` — bail out if the read fails.
          2. If the byte is already 0xCC (e.g., another debugger is also present),
             record the hook entry without writing.
          3. Change page protection to PAGE_EXECUTE_READWRITE via VirtualProtectEx.
          4. Write 0xCC via WriteProcessMemory.
          5. Restore the original page protection.
          6. Flush the instruction cache so all CPU cores see the new byte.
          7. Verify the write by reading back the byte — fail if it is not 0xCC.

        Returns True on success, False on any failure.
        Calling apply_hook on an already-hooked (pid, address) is a no-op (returns True).
        """
        if (pid, address) in self.hooks:
            return True  # Already hooked

        try:
            # Read original byte
            old_byte = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()
            if not self.kernel32.ReadProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(old_byte),
                    1,
                    ctypes.byref(bytes_read)
            ) or bytes_read.value != 1:
                return False

            # Check if it's already 0xCC (maybe another debugger or already hooked)
            if old_byte.value == 0xCC:
                # Still store it so we can handle the breakpoint if it's hit
                if (pid, address) not in self.hooks:
                    self.hooks[(pid, address)] = 0xCC  # We don't know original, but we track it
                    self.api_names[address] = api_name
                return True

            # Ensure memory is writable (VirtualProtectEx)
            old_protect = wintypes.DWORD()
            PAGE_EXECUTE_READWRITE = 0x40
            if not self.kernel32.VirtualProtectEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    1,
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
            ):
                return False

            # Write 0xCC (INT3)
            int3 = ctypes.c_ubyte(0xCC)
            bytes_written = ctypes.c_size_t()

            success = self.kernel32.WriteProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(int3),
                1,
                ctypes.byref(bytes_written)
            ) and bytes_written.value == 1

            # Restore protection
            temp_protect = wintypes.DWORD()
            self.kernel32.VirtualProtectEx(
                process_handle,
                ctypes.c_void_p(address),
                1,
                old_protect,
                ctypes.byref(temp_protect)
            )

            if not success:
                return False

            self.hooks[(pid, address)] = old_byte.value
            self.api_names[address] = api_name

            # Flush instruction cache
            self.kernel32.FlushInstructionCache(process_handle, ctypes.c_void_p(address), 1)

            # Verify write
            verify_byte = ctypes.c_ubyte()
            self.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), ctypes.byref(verify_byte), 1,
                                            None)
            if verify_byte.value != 0xCC:
                # print(f"Verification failed at {hex(address)}: expected 0xCC, got {hex(verify_byte.value)}")
                return False

            return True
        except Exception:
            return False

    def remove_hook(self, process_handle: int, address: int, pid: int) -> bool:
        """
        Restores the original byte at `address`, removing the INT3 breakpoint.

        Steps mirror apply_hook in reverse:
          1. Change page protection to PAGE_EXECUTE_READWRITE.
          2. Write the saved original byte back via WriteProcessMemory.
          3. Restore original page protection.
          4. Flush the instruction cache.
          5. Remove the (pid, address) entry from self.hooks.
          6. Remove the address from self.api_names only if no other PID still
             has an active hook at that address (system DLLs are shared).

        Returns False if no hook is registered for (pid, address).
        """
        if (pid, address) not in self.hooks:
            return False

        try:
            # Ensure memory is writable (VirtualProtectEx)
            old_protect = wintypes.DWORD()
            PAGE_EXECUTE_READWRITE = 0x40
            if not self.kernel32.VirtualProtectEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    1,
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
            ):
                return False

            original_byte = ctypes.c_ubyte(self.hooks[(pid, address)])
            bytes_written = ctypes.c_size_t()

            success = self.kernel32.WriteProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(original_byte),
                1,
                ctypes.byref(bytes_written)
            ) and bytes_written.value == 1

            # Restore protection
            temp_protect = wintypes.DWORD()
            self.kernel32.VirtualProtectEx(
                process_handle,
                ctypes.c_void_p(address),
                1,
                old_protect,
                ctypes.byref(temp_protect)
            )

            if not success:
                return False

            self.kernel32.FlushInstructionCache(process_handle, ctypes.c_void_p(address), 1)

            del self.hooks[(pid, address)]

            # We DO NOT delete from self.api_names here.
            # During a single-step (re-hooking), we need the API name to survive.
            # Since system DLL addresses are static for the session, keeping them is safe.

            return True
        except Exception:
            return False

    def is_our_hook(self, address: int, pid: int) -> bool:
        """Checks if the breakpoint hit is one of our hooks."""
        return (pid, address) in self.hooks

    def get_api_name(self, address: int) -> str:
        """Returns the name of the API at the hooked address."""
        return self.api_names.get(address, "UnknownAPI")
