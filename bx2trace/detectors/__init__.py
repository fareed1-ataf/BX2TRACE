# bx2trace/detectors/__init__.py
# Detectors package — each file implements one BaseDetector.
#
# ALL_DETECTORS: a list of all built-in detector *classes* (not instances).
# Useful for advanced users who want to iterate or inspect what is available.
#
# For simple usage, prefer: engine.load_defaults()

from bx2trace.detectors.process_hollow_detector import ProcessHollowingDetector
from bx2trace.detectors.registry_persistence_detector import RegistryPersistenceDetector
from bx2trace.detectors.c2_beacon_detector import C2BeaconDetector

ALL_DETECTORS = [
    ProcessHollowingDetector,
    RegistryPersistenceDetector,
    C2BeaconDetector,
]

