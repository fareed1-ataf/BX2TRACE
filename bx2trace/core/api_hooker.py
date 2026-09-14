"""
core/api_hooker.py
==================
Management of API hooks using the INT3 (0xCC) software breakpoint method.
Provides resolution of API addresses and management of the original bytes.
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

    def resolve_api(self, dll_name: str, function_name: str) -> Optional[int]:
        """
        Resolves the address of an API in the target process.
        Since system DLLs are loaded at the same address across processes (ASLR),
        we can resolve it locally.
        """
        try:
            h_module = self.kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = self.kernel32.LoadLibraryW(dll_name)

            if not h_module:
                return None

            addr = self.kernel32.GetProcAddress(h_module, function_name.encode('ascii'))
            if addr == 0:
                return None

            # Check for JMP/Forwarder (simple check)
            first_byte = ctypes.c_ubyte()
            ctypes.memmove(ctypes.byref(first_byte), addr, 1)
            if first_byte.value == 0xE9:  # JMP
                # This is a jump, we might be hitting a hot-patch point or a wrapper
                pass

            return addr
        except Exception:
            return None

    def apply_hook(self, process_handle: int, address: int, api_name: str, pid: int) -> bool:
        """
        Places an INT3 (0xCC) hook at the specified address.
        Backups the original byte for restoration later.
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
        Restores the original byte at the specified address.
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
            return True
        except Exception:
            return False

    def is_our_hook(self, address: int, pid: int) -> bool:
        """Checks if the breakpoint hit is one of our hooks."""
        return (pid, address) in self.hooks

    def get_api_name(self, address: int) -> str:
        """Returns the name of the API at the hooked address."""
        return self.api_names.get(address, "UnknownAPI")
