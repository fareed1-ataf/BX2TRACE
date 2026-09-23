# bx2trace - Windows Process Tracer & Live Memory Extractor
# =========================================================

# Core contracts & data types
from bx2trace.core.models import (
    TraceEvent,
    TraceMode,
    Severity,
    EngineConfig,
    BaseDetector,
    EventCategory,
    EventAction,
    CURRENT_SCHEMA_VERSION,
)

# Detection pipeline
from bx2trace.core.detector_engine import DetectorEngine

# Unified session entry point (wraps DebugThread + MemoryScanner + DetectorEngine)
from bx2trace.core.trace_session import TraceSession

# Built-in detectors
from bx2trace.detectors.process_hollow_detector import ProcessHollowingDetector
from bx2trace.detectors.registry_persistence_detector import RegistryPersistenceDetector
from bx2trace.detectors.c2_beacon_detector import C2BeaconDetector
from bx2trace.detectors import ALL_DETECTORS

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
    classify_strings,
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

__version__ = "1.1.0"
__author__ = "bx2trace contributors"

__all__ = [
    # Data models
    "TraceEvent", "TraceMode", "Severity", "EngineConfig",
    "BaseDetector", "EventCategory", "EventAction",
    "CURRENT_SCHEMA_VERSION",
    # Detection pipeline
    "DetectorEngine",
    # Unified session entry point
    "TraceSession",
    # Built-in detectors
    "ProcessHollowingDetector",
    "RegistryPersistenceDetector",
    "C2BeaconDetector",
    "ALL_DETECTORS",
    # Execution engines
    "DebugThread", "TrackedProcess", "MemoryScannerThread",
    "create_process_debug", "ArchitectureMismatchError",
    # Memory access
    "open_process_for_dump", "enumerate_regions",
    "read_region", "read_committed_regions",
    # Extractors
    "extract_strings", "extract_ascii_strings", "extract_utf16le_strings",
    "diff_new_strings", "URL_PATTERN", "IPV4_PATTERN", "classify_strings",
    "shannon_entropy", "entropy_by_page",
    # Constants
    "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READ",
    "PAGE_READWRITE", "PAGE_READONLY",
    "MEM_COMMIT", "PROTECTIONS_OF_INTEREST",
]
