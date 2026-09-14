# bx2trace - Windows Process Tracer & Live Memory Extractor
# =========================================================

# Core contracts & data types
from bx2trace.core.models import (
    TraceEvent,
    TraceMode,
    Severity,
    EngineConfig,
    BaseDetector,
    CURRENT_SCHEMA_VERSION,
)

# Execution engines
from bx2trace.core.debug_thread import DebugThread, TrackedProcess
from bx2trace.core.memory_scanner import MemoryScannerThread
from bx2trace.core.process_launcher import (
    create_process_debug,
    ArchitectureMismatchError,
)

# Raw memory access
from bx2trace.memory.reader import (
    open_process_for_dump,
    enumerate_regions,
    read_region,
    read_committed_regions,
)

# Extractors (platform-agnostic)
from bx2trace.extractors.strings import (
    extract_strings,
    extract_ascii_strings,
    extract_utf16le_strings,
    diff_new_strings,
    URL_PATTERN,
    IPV4_PATTERN,
)
from bx2trace.extractors.entropy import (
    shannon_entropy,
    entropy_by_page,
)

# Useful constants
from bx2trace.core.constants import (
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PAGE_READONLY,
    MEM_COMMIT,
    PROTECTIONS_OF_INTEREST,
)

__version__ = "0.1.0"
__author__ = "bx2trace contributors"

__all__ = [
    "TraceEvent", "TraceMode", "Severity", "EngineConfig", "BaseDetector",
    "CURRENT_SCHEMA_VERSION",
    "DebugThread", "TrackedProcess", "MemoryScannerThread",
    "create_process_debug", "ArchitectureMismatchError",
    "open_process_for_dump", "enumerate_regions",
    "read_region", "read_committed_regions",
    "extract_strings", "extract_ascii_strings", "extract_utf16le_strings",
    "diff_new_strings", "URL_PATTERN", "IPV4_PATTERN",
    "shannon_entropy", "entropy_by_page",
    "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READ",
    "PAGE_READWRITE", "PAGE_READONLY",
    "MEM_COMMIT", "PROTECTIONS_OF_INTEREST",
]
