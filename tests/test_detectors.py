import os
import sys
import time
import pytest

# Add the parent directory (bx2trace root) to Python's path so it finds the library
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bx2trace import TraceSession, EngineConfig, TraceMode

DUMMY_REGISTRY = os.path.join(os.path.dirname(__file__), "dummy_persistence.py")
DUMMY_C2 = os.path.join(os.path.dirname(__file__), "dummy_c2_beacon.py")
DUMMY_HOLLOW = os.path.join(os.path.dirname(__file__), "dummy_process_hollow.py")
DUMMY_MEMORY = os.path.join(os.path.dirname(__file__), "dummy_memory_scanner.py")

def test_registry_persistence_detector():
    """
    Test that our library correctly catches a process trying to write to the Windows
    Startup registry key (Run).
    """
    # 1. Setup the TraceSession to monitor the python executable running our dummy script
    config = EngineConfig(
        target_path=sys.executable,
        cmd_args=f'"{DUMMY_REGISTRY}"',
        mode=TraceMode.FULL_TRACE,
        enable_stealth=False,  # Not needed for tests
    )

    session = TraceSession(config)
    session.engine.load_defaults()

    alerts_triggered = []

    # 2. Start Monitoring
    session.start()

    try:
        # 3. Wait and collect events while the dummy script runs
        while session.is_alive:
            event = session.get_event()
            if event is None:
                time.sleep(0.05)
                continue

            # Send every event through the detector engine
            alerts = session.engine.process(event)

            # Check if any alert was triggered
            for alert in alerts:
                if alert.action == "REGISTRY_PERSISTENCE_DETECTED":
                    alerts_triggered.append(alert)

    finally:
        # Stop debugging cleanly
        session.join()

    # 4. ASSERTIONS (The actual test)
    # Did the camera catch the thief?
    assert len(alerts_triggered) > 0, "The detector failed to catch the registry write!"

    # Is the evidence accurate?
    first_alert = alerts_triggered[0]

    # Assert it was marked as a CRITICAL severity
    assert first_alert.severity.name == "CRITICAL", "Alert severity should be CRITICAL"

    # Assert it caught the correct path
    assert (
        "run" in first_alert.payload["matched_path"].lower()
    ), "Did not match the 'Run' key"

    # Assert it caught the correct value name that our dummy script used
    assert (
        first_alert.payload["value_name"].lower() == "bx2testmalware"
    ), "Did not catch the correct value name"

def test_c2_beacon_detector():
    """Test that our library catches repeated connections to the same IP:Port."""
    config = EngineConfig(
        target_path=sys.executable,
        cmd_args=f'"{DUMMY_C2}"',
        mode=TraceMode.FULL_TRACE,
        enable_stealth=False,
    )
    session = TraceSession(config)
    session.engine.load_defaults()
    
    alerts_triggered = []
    session.start()
    
    try:
        while session.is_alive:
            event = session.get_event()
            if event is None:
                time.sleep(0.05)
                continue
            alerts = session.engine.process(event)
            for alert in alerts:
                if alert.action == "C2_BEACON_DETECTED":
                    alerts_triggered.append(alert)
    finally:
        session.join()
        
    assert len(alerts_triggered) > 0, "The C2 beacon detector failed to fire!"
    first_alert = alerts_triggered[0]
    assert first_alert.severity.name == "CRITICAL"
    assert first_alert.payload["target_ip"] == "8.8.8.8"
    assert first_alert.payload["connection_count"] >= 3

def test_process_hollow_detector():
    """Test that our library catches VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThreadEx on the same PID."""
    config = EngineConfig(
        target_path=sys.executable,
        cmd_args=f'"{DUMMY_HOLLOW}"',
        mode=TraceMode.FULL_TRACE,
        enable_stealth=False,
    )
    session = TraceSession(config)
    session.engine.load_defaults()
    
    alerts_triggered = []
    session.start()
    
    try:
        while session.is_alive:
            event = session.get_event()
            if event is None:
                time.sleep(0.05)
                continue
            alerts = session.engine.process(event)
            for alert in alerts:
                if alert.action == "PROCESS_HOLLOWING_DETECTED":
                    alerts_triggered.append(alert)
    finally:
        session.join()
        
    assert len(alerts_triggered) > 0, "The Process Hollowing detector failed to fire!"
    first_alert = alerts_triggered[0]
    assert first_alert.severity.name == "CRITICAL"

def test_memory_scanner():
    """Test that our library catches strings written to RWX memory regions."""
    config = EngineConfig(
        target_path=sys.executable,
        cmd_args=f'"{DUMMY_MEMORY}"',
        mode=TraceMode.FULL_TRACE,
        enable_stealth=False,
        memory_scan_interval=2.0, # Scan frequently for the test
    )
    session = TraceSession(config)
    session.engine.load_defaults()
    
    alerts_triggered = []
    session.start()
    
    try:
        while session.is_alive:
            event = session.get_event()
            if event is None:
                time.sleep(0.05)
                continue
            alerts = session.engine.process(event)
            for alert in alerts:
                # We expect the memory scanner to find the RWX strings
                if alert.action == "RWX_STRINGS_DETECTED":
                    alerts_triggered.append(alert)
    finally:
        session.join()
        
    assert len(alerts_triggered) > 0, "The Memory Scanner failed to detect RWX strings!"
    first_alert = alerts_triggered[0]
    assert first_alert.severity.name == "HIGH"
    assert first_alert.payload["new_strings_count"] >= 20 # Threshold

