"""
core/constants.py
==================
All raw Windows API constants in one place.
Rule: Any magic number in the code is written here only once, and the rest of the files import it by name.

Reference source for all these values: winbase.h / winnt.h (Official Microsoft Documentation).
Do not modify a value here unless verified against official documentation — any error here fails silently
in a completely different place from this file.
"""

# ============================================================
# Process Creation Flags (Passed to CreateProcessW)
# ============================================================

# ⚠️ CRITICAL FIX: The following two values are easily inverted by mistake because they are numerically sequential.
DEBUG_PROCESS = 0x00000001
# ↑ Monitors the launched process + every child process it spawns (via CreateProcess internally)
#   automatically, without any extra effort. This is the correct choice for our project.

DEBUG_ONLY_THIS_PROCESS = 0x00000002
# ↑ Monitors only the launched process. Any child process it spawns runs completely free
#   without any monitoring or reporting. Only use this if you intentionally want to ignore children.

CREATE_NEW_CONSOLE = 0x00000010
CREATE_SUSPENDED = 0x00000004
# ↑ Useful in the future: starts the process "frozen" before executing any instruction, giving you a chance
#   to set Hardware Breakpoints before anything runs at all.

# ============================================================
# ContinueDebugEvent — How we respond to each event
# ============================================================

DBG_CONTINUE = 0x00010002
# ↑ "Handle this exception as if it didn't happen" — we use this for our own events
#   (like Single-Step from a Hardware Breakpoint we set).

DBG_EXCEPTION_NOT_HANDLED = 0x80010001
# ↑ "Pass this exception to the target program's own exception handler"
#   This is the correct default for any exception we didn't intentionally cause — many Packers
#   use intentional exceptions as part of their unpacking mechanism, and if you accidentally
#   reply DBG_CONTINUE, the target program crashes because its internal handler
#   never received the exception it was expecting.

INFINITE = 0xFFFFFFFF

# ============================================================
# Debug Event Type Codes (DEBUG_EVENT.dwDebugEventCode)
# ============================================================

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EVENT_CODE_NAMES = {
    EXCEPTION_DEBUG_EVENT: "EXCEPTION",
    CREATE_THREAD_DEBUG_EVENT: "CREATE_THREAD",
    CREATE_PROCESS_DEBUG_EVENT: "CREATE_PROCESS",
    EXIT_THREAD_DEBUG_EVENT: "EXIT_THREAD",
    EXIT_PROCESS_DEBUG_EVENT: "EXIT_PROCESS",
    LOAD_DLL_DEBUG_EVENT: "LOAD_DLL",
    UNLOAD_DLL_DEBUG_EVENT: "UNLOAD_DLL",
    OUTPUT_DEBUG_STRING_EVENT: "OUTPUT_DEBUG_STRING",
    RIP_EVENT: "RIP",
}

# ============================================================
# Common Exception Codes (EXCEPTION_RECORD.ExceptionCode)
# ============================================================

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
# ↑ We receive this code after any Hardware Breakpoint we set (DR0-DR3) —
#   important for the future "function tracing" feature.
EXCEPTION_ACCESS_VIOLATION = 0xC0000005

# ============================================================
# CONTEXT Flags (x64)
# ============================================================
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS

# ============================================================
# Memory Protections (VirtualQueryEx / VirtualProtect)
# ============================================================

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
# ↑ This specific combination (Executable + Writable at the same time) is the most important
#   "Red Flag" for catching self-unpacking moments — very few legitimate programs
#   need a page with this combination during normal execution.

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000

PROTECTIONS_OF_INTEREST = {
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
    PAGE_EXECUTE_READ,
}

# ============================================================
# OpenProcess Access Rights (Used in MEMORY_DUMP mode only — already running process)
# ============================================================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_DUMP_ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
