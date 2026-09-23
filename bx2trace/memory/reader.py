"""
memory/reader.py
==================
Single responsibility: Take a process Handle + address + size, and return raw bytes or
None. Simple sync functions — called either directly (by a separate command line tool
for experimentation) or from within a periodic scanner (core/memory_scanner.py later).

⚠️ This file uses the already-ready Handle from the Debug Loop (hProcess from
CREATE_PROCESS_DEBUG_INFO), and does not open a new OpenProcess for processes we are already
monitoring — because the Debugger already has full access automatically. We only open
OpenProcess in MEMORY_DUMP mode (an already running process we are not debugging).
"""

import ctypes
from ctypes import wintypes

from bx2trace.core.win_structs import MEMORY_BASIC_INFORMATION

kernel32 = ctypes.windll.kernel32

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE


def open_process_for_dump(pid: int):
    """Used only in MEMORY_DUMP mode — an already running process, we are not its Debugger."""
    from bx2trace.core.constants import PROCESS_DUMP_ACCESS
    handle = kernel32.OpenProcess(PROCESS_DUMP_ACCESS, False, pid)
    if not handle:
        error_code = kernel32.GetLastError()
        raise OSError(f"Failed to open process {pid} for reading. Error code: {error_code}")
    return handle


def enumerate_regions(process_handle) -> list[MEMORY_BASIC_INFORMATION]:
    """
    Enumerates all memory regions in the process address space via successive calls
    to VirtualQueryEx, each time jumping to the address (BaseAddress + RegionSize).
    """
    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while True:
        result = kernel32.VirtualQueryEx(
            process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size
        )
        if result == 0:
            break  # Reached the end of the valid address space

        regions.append(MEMORY_BASIC_INFORMATION(
            BaseAddress=mbi.BaseAddress, AllocationBase=mbi.AllocationBase,
            AllocationProtect=mbi.AllocationProtect, RegionSize=mbi.RegionSize,
            State=mbi.State, Protect=mbi.Protect, Type=mbi.Type,
        ))

        next_address = (mbi.BaseAddress or 0) + mbi.RegionSize
        if next_address <= address:
            # Handle potential overflow or same-address reporting to prevent infinite loops
            break
        address = next_address

    return regions


def read_region(process_handle, address: int, size: int, buffer: ctypes.Array | None = None) -> bytes | None:
    """
    Reads a memory region. Returns None upon complete failure, or bytes of the actual
    read size.
    If 'buffer' is provided, it must be a ctypes.create_string_buffer(size).
    """
    if buffer is None:
        buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
    )

    if not success and bytes_read.value == 0:
        return None

    return bytes(buffer.raw[: bytes_read.value])


def read_committed_regions(
        process_handle,
        protections_filter: set[int] | None = None,
        max_region_size_mb: int = 100,
) -> list[tuple[int, int, bytes]]:
    """
    Combines enumerate + read in one convenient function.
    """
    from bx2trace.core.constants import MEM_COMMIT

    _max_bytes = max_region_size_mb * 1024 * 1024
    results = []

    # Pre-allocate a 1MB buffer to reuse for small-to-medium regions
    # to reduce allocation overhead during heavy scanning.
    shared_buffer_size = 1024 * 1024
    shared_buffer = ctypes.create_string_buffer(shared_buffer_size)

    for region in enumerate_regions(process_handle):
        if region.State != MEM_COMMIT:
            continue
        if protections_filter and region.Protect not in protections_filter:
            continue
        if region.RegionSize <= 0 or region.RegionSize > _max_bytes:
            continue

        buffer = shared_buffer if region.RegionSize <= shared_buffer_size else None
        data = read_region(process_handle, region.BaseAddress or 0, region.RegionSize, buffer=buffer)
        if data:
            results.append((region.BaseAddress or 0, region.Protect, data))

    return results


def patch_peb_stealth(process_handle: wintypes.HANDLE) -> bool:
    """
    Patches the PEB (Process Environment Block) to hide the debugger presence.
    Clears 'BeingDebugged' and 'NtGlobalFlag' fields.
    Returns True on success.
    """
    from bx2trace.core.win_structs import PROCESS_BASIC_INFORMATION, ntdll
    import logging
    log = logging.getLogger("bx2trace.stealth")

    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = wintypes.DWORD()
    status = ntdll.NtQueryInformationProcess(
        process_handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
    )

    if status != 0:
        log.warning("NtQueryInformationProcess failed with status: 0x%08X", status)
        return False

    peb_addr = pbi.PebBaseAddress
    if not peb_addr:
        return False

    # BeingDebugged is at offset 2
    # NtGlobalFlag is at offset 0xBC (64-bit)
    # Clear BeingDebugged (offset 2)
    zero = ctypes.c_byte(0)
    written = ctypes.c_size_t(0)
    ok_being_debugged = bool(
        kernel32.WriteProcessMemory(
            process_handle, ctypes.c_void_p(peb_addr + 2),
            ctypes.byref(zero), 1, ctypes.byref(written)
        ) and written.value == 1
    )

    # Clear NtGlobalFlag (offset 0xBC on x64)
    zero_dword = wintypes.DWORD(0)
    ok_nt_flag = bool(
        kernel32.WriteProcessMemory(
            process_handle, ctypes.c_void_p(peb_addr + 0xBC),
            ctypes.byref(zero_dword), 4, ctypes.byref(written)
        ) and written.value == 4
    )

    # Verify each field individually and log the outcome.
    # The two writes are independent; either can fail on a hardened system.
    if ok_being_debugged and ok_nt_flag:
        log.info("PEB stealth: BeingDebugged=0, NtGlobalFlag=0 applied successfully.")
        return True
    else:
        log.warning(
            "PEB stealth partial failure — BeingDebugged=%s NtGlobalFlag=%s",
            ok_being_debugged, ok_nt_flag,
        )
        return False
