"""
detectors/registry_persistence_detector.py
============================================
Detects malware attempting to establish persistence by writing to well-known
auto-run registry keys (Run, RunOnce, Services, Winlogon, AppInit_DLLs, etc.).

Persistence via registry is one of the most common malware techniques (MITRE ATT&CK T1547).
Any write to these paths during dynamic analysis is highly suspicious.

Severity:
    CRITICAL — writes to Run/RunOnce (direct execution on login)
    HIGH     — writes to Services, Winlogon, AppInit_DLLs
    SUSPICIOUS — writes to other tracked paths
"""

import logging
from typing import List

from bx2trace.core import constants as c
from bx2trace.core.models import (
    BaseDetector,
    TraceEvent,
    EventCategory,
    Severity,
)

_log = logging.getLogger("bx2trace.detector.registry_persistence")

# Paths that guarantee execution at login — the most dangerous tier
_CRITICAL_PATHS = {
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
}

# Paths that allow code execution with elevated privileges or across all users
_HIGH_PATHS = {
    r"system\currentcontrolset\services",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows nt\currentversion\windows",          # AppInit_DLLs
    r"software\microsoft\windows nt\currentversion\image file execution options",  # Debugger hijacking
    r"software\microsoft\windows\currentversion\explorer\shellexecutehooks",
}


class RegistryPersistenceDetector(BaseDetector):
    """
    Watches REGISTRY::VALUE_SET events and fires an alert when the target
    key path matches a known persistence location.

    Key path matching is case-insensitive substring matching against the
    value_name field — this catches both HKLM and HKCU variants because
    the persistence key set contains the path suffix only.
    """

    name = "registry_persistence_detector"

    def handles(self, event: TraceEvent) -> bool:
        return (
            event.category == EventCategory.REGISTRY
            and event.action == "VALUE_SET"
        )

    def process(self, event: TraceEvent) -> List[TraceEvent]:
        details  = event.payload.get("details", {})
        hkey     = details.get("hkey", "").lower()
        val_name = details.get("value_name", "").lower()

        # Use the resolved key_path (populated by NtQueryKey in debug_thread.py).
        # key_path is the relative subkey path, e.g.:
        #   "software\microsoft\windows\currentversion\run"
        # The old naive code built full_context from root_name + value_name, which never
        # contained the intermediate subkey path and therefore never matched.
        key_path = details.get("key_path", "").lower()

        # Build the matching context: prefer key_path (precise), fall back to hkey
        if key_path and not key_path.startswith("hkey_"):  # not a root-only placeholder
            full_context = f"{key_path}\\{val_name}"
        else:
            # Fallback for predefined root handles without a subkey path
            full_context = f"{hkey}\\{val_name}"

        matched_path = None
        severity     = None

        # Check most dangerous paths first
        for path in _CRITICAL_PATHS:
            if path in full_context or path in key_path:
                matched_path = path
                severity     = Severity.CRITICAL
                break

        if not matched_path:
            for path in _HIGH_PATHS:
                if path in full_context or path in key_path:
                    matched_path = path
                    severity     = Severity.HIGH
                    break

        if not matched_path:
            # Check broader list from constants
            for path in c.REGISTRY_PERSISTENCE_KEYS:
                if path in full_context or path in key_path:
                    matched_path = path
                    severity     = Severity.SUSPICIOUS
                    break

        if not matched_path:
            return []

        _log.warning(
            "RegistryPersistenceDetector: PERSISTENCE KEY WRITE detected! "
            "PID %d | hkey=%s | value=%s | matched_path=%s",
            event.pid, hkey, val_name, matched_path,
        )

        alert = event.derive(
            source=self.name,
            action="REGISTRY_PERSISTENCE_DETECTED",
            category=EventCategory.REGISTRY,
            severity=severity,
            payload={
                "attacker_pid":  event.pid,
                "hkey":          hkey,
                "value_name":    val_name,
                "matched_path":  matched_path,
                "value_type":    details.get("type", "UNKNOWN"),
                "description": (
                    f"Write to persistence registry key detected: {matched_path}. "
                    "This is a common malware technique for surviving reboots "
                    "(MITRE ATT&CK T1547.001)."
                ),
            },
        )
        return [alert]
