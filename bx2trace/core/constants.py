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

# ============================================================
# Registry Value Types (winnt.h)
# ============================================================

REG_NONE                = 0   # No value type
REG_SZ                  = 1   # Null-terminated string (UTF-16)
REG_EXPAND_SZ           = 2   # Null-terminated string with env vars
REG_BINARY              = 3   # Free-form binary data
REG_DWORD               = 4   # 32-bit number
REG_DWORD_BIG_ENDIAN    = 5   # 32-bit number, big-endian
REG_LINK                = 6   # Symbolic link (Unicode)
REG_MULTI_SZ            = 7   # Multiple null-terminated strings
REG_QWORD               = 11  # 64-bit number

REG_TYPE_NAMES = {
    REG_NONE:           "REG_NONE",
    REG_SZ:             "REG_SZ",
    REG_EXPAND_SZ:      "REG_EXPAND_SZ",
    REG_BINARY:         "REG_BINARY",
    REG_DWORD:          "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK:           "REG_LINK",
    REG_MULTI_SZ:       "REG_MULTI_SZ",
    REG_QWORD:          "REG_QWORD",
}

# Known persistence registry key paths (Run/RunOnce/Services/Winlogon etc.)
# Used by registry_persistence_detector to flag suspicious writes.
# Note: These are RELATIVE paths (after the root key). The detector matches
# against them regardless of whether the root is HKLM or HKCU.
# FIX-10: Removed duplicated entries that were silently ignored by the set.
REGISTRY_PERSISTENCE_KEYS = {
    # Auto-run on every login (highest risk)
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    # Services (malware often installs as a service)
    r"system\currentcontrolset\services",
    # Winlogon (used by bootkits / advanced persistence)
    r"software\microsoft\windows nt\currentversion\winlogon",
    # AppInit_DLLs (loaded into every process)
    r"software\microsoft\windows nt\currentversion\windows",
    # Image File Execution Options (debugger hijacking)
    r"software\microsoft\windows nt\currentversion\image file execution options",
    # Shell extensions
    r"software\microsoft\windows\currentversion\explorer\shellexecutehooks",
}

_HKEY_NAMES = {
    0x80000000: 'HKEY_CLASSES_ROOT',
    0x80000001: 'HKEY_CURRENT_USER',
    0x80000002: 'HKEY_LOCAL_MACHINE',
    0x80000003: 'HKEY_USERS',
    0x80000005: 'HKEY_CURRENT_CONFIG',
}

_ACCESS_MAP = {
    0x80000000: 'GENERIC_READ',
    0x40000000: 'GENERIC_WRITE',
    0x20000000: 'GENERIC_EXECUTE',
    0x10000000: 'GENERIC_ALL',
    0x00100000: 'SYNCHRONIZE',
    0x00020000: 'DELETE',
    0x00040000: 'READ_CONTROL',
    0x00000001: 'FILE_READ_DATA',
    0x00000002: 'FILE_WRITE_DATA',
    0x00000004: 'FILE_APPEND_DATA',
    0x00000020: 'FILE_EXECUTE',
}

_KNOWN_INTERPRETERS = {
    'powershell.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'regsvr32.exe',
    'rundll.exe',
    'rundll32.exe',
}

_HOOK_TYPE_NAMES = {
    0:  'WH_MSGFILTER',
    1:  'WH_JOURNALRECORD',
    2:  'WH_JOURNALPLAYBACK',
    3:  'WH_KEYBOARD',
    4:  'WH_GETMESSAGE',
    5:  'WH_CALLWNDPROC',
    6:  'WH_CBT',
    7:  'WH_SYSMSGFILTER',
    8:  'WH_MOUSE',
    9:  'WH_HARDWARE',
    10: 'WH_DEBUG',
    11: 'WH_SHELL',
    12: 'WH_FOREGROUNDIDLE',
    13: 'WH_CALLWNDPROCRET',
    14: 'WH_KEYBOARD_LL',
    15: 'WH_MOUSE_LL',
}

_SURVEILLANCE_HOOKS = {14, 15, 1, 2, 3, 8}

_DANGEROUS_PRIVILEGES = {
    'SeDebugPrivilege',
    'SeTcbPrivilege',
    'SeLoadDriverPrivilege',
    'SeTakeOwnershipPrivilege',
    'SeAssignPrimaryTokenPrivilege',
    'SeImpersonatePrivilege',
    'SeCreateTokenPrivilege',
    'SeTrustedCredManAccessPrivilege',
}

_IMPERSONATION_LEVELS = {
    0: 'SecurityAnonymous',
    1: 'SecurityIdentification',
    2: 'SecurityImpersonation',
    3: 'SecurityDelegation',
}

_CRYPT_ALG_NAMES = {
    0x00006602: 'RC2',
    0x00006801: 'RC4',
    0x00006601: 'DES',
    0x00006603: '3DES',
    0x00006611: 'AES_128',
    0x0000660E: 'AES_192',
    0x00006610: 'AES_256',
    0x0000a400: 'RSA_SIGN',
    0x0000a401: 'RSA_KEYX',
    0x00008004: 'SHA1',
    0x0000800c: 'SHA256',
}

_DANGEROUS_CLSIDS = {
    '{72C24DD5-D70A-438B-8A42-98424B88AFB8}': 'WScript.Shell',
    '{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}': 'WScript.Shell (alt)',
    '{0D43FE01-F093-11CF-8940-00A0C9054228}': 'FileSystemObject',
    '{4991D34B-80A1-4291-83B6-3328366B9097}': 'BITS (Background Intelligent Transfer)',
    '{1A6B69BB-1F8A-11D2-8B0E-00C04F990F4C}': 'BITS Manager',
    '{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}': 'IWebBrowser2',
    '{8BC3F05E-D86B-11D0-A075-00C04FB68820}': 'WbemLocator (WMI)',
    '{76A64158-CB41-11D1-8B02-00600806D9B6}': 'WbemScripting',
    '{F2A6F4F0-A3BB-11D5-B932-000102A0C14D}': 'ITaskService (Task Scheduler)',
    '{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}': 'Task Scheduler v1.1',
    '{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}': 'Task Scheduler v1.2',
}

_PIPE_ACCESS_MODES = {
    0x00000001: 'PIPE_ACCESS_INBOUND',
    0x00000002: 'PIPE_ACCESS_OUTBOUND',
    0x00000003: 'PIPE_ACCESS_DUPLEX',
}

_CF_NAMES = {
    1:  'CF_TEXT',
    2:  'CF_BITMAP',
    7:  'CF_OEMTEXT',
    13: 'CF_UNICODETEXT',
    15: 'CF_HDROP',
    16: 'CF_LOCALE',
}

APIS_TO_HOOK = [
    # --- Process Spawning ---
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "CreateProcessA"),
    ("ntdll.dll",    "NtCreateUserProcess"),
    ("ntdll.dll",    "LdrLoadDll"),

    # --- Script Execution / Process Spawning via Shell ---
    ("shell32.dll", "ShellExecuteW"),
    ("shell32.dll", "ShellExecuteA"),
    ("shell32.dll", "ShellExecuteExW"),

    # --- Network ---
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "WSASend"),
    ("ws2_32.dll", "WSAConnect"),
    ("ws2_32.dll", "getaddrinfo"),
    ("ws2_32.dll", "GetAddrInfoW"),
    ("ws2_32.dll", "gethostbyname"),

    # High-level HTTP APIs
    ("wininet.dll", "InternetConnectW"),
    ("wininet.dll", "InternetConnectA"),
    ("winhttp.dll", "WinHttpConnect"),
    ("winhttp.dll", "WinHttpOpenRequest"),
    ("winhttp.dll", "WinHttpSendRequest"),
    ("winhttp.dll", "WinHttpReadData"),
    ("wininet.dll", "HttpOpenRequestW"),
    ("wininet.dll", "HttpSendRequestW"),
    ("wininet.dll", "HttpSendRequestA"),
    ("wininet.dll", "InternetReadFile"),

    # --- Registry ---
    ("advapi32.dll", "RegSetValueExW"),
    ("advapi32.dll", "RegSetValueExA"),
    ("advapi32.dll", "RegDeleteValueW"),
    ("advapi32.dll", "RegDeleteKeyExW"),

    # --- File System ---
    ("kernel32.dll", "CreateFileW"),
    ("kernel32.dll", "CreateFileA"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "DeleteFileW"),
    ("kernel32.dll", "DeleteFileA"),
    ("kernel32.dll", "MoveFileExW"),

    # --- Code Injection ---
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "CreateRemoteThreadEx"),

    # --- Surveillance & Keylogging ---
    ("user32.dll", "SetWindowsHookExW"),
    ("user32.dll", "GetClipboardData"),
    ("user32.dll", "SetClipboardData"),

    # --- Anti-Debug / Anti-Analysis ---
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),

    # --- File Download ---
    ("urlmon.dll", "URLDownloadToFileW"),

    # --- Privilege & Token Manipulation ---
    ("advapi32.dll", "AdjustTokenPrivileges"),
    ("advapi32.dll", "DuplicateToken"),
    ("advapi32.dll", "DuplicateTokenEx"),
    ("advapi32.dll", "ImpersonateLoggedOnUser"),

    # --- Cryptography (Ransomware / Data Theft) ---
    ("advapi32.dll", "CryptEncrypt"),
    ("advapi32.dll", "CryptDecrypt"),
    ("advapi32.dll", "CryptGenKey"),
    ("advapi32.dll", "CryptImportKey"),
    ("bcrypt.dll",   "BCryptEncrypt"),
    ("bcrypt.dll",   "BCryptDecrypt"),

    # --- Windows Services (Persistence) ---
    ("advapi32.dll", "OpenSCManagerW"),
    ("advapi32.dll", "CreateServiceW"),
    ("advapi32.dll", "CreateServiceA"),
    ("advapi32.dll", "StartServiceW"),
    ("advapi32.dll", "StartServiceA"),
    ("advapi32.dll", "ChangeServiceConfigW"),

    # --- Named Pipes (C2 / Lateral Movement) ---
    ("kernel32.dll", "CreateNamedPipeW"),
    ("kernel32.dll", "ConnectNamedPipe"),

    # --- COM Object Creation (LOLBins / Code Execution) ---
    ("ole32.dll", "CoCreateInstance"),
]
