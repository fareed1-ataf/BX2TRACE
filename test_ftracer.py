import os
import sys
import threading
import queue

# Ensure we can import ftracer from the current directory if pip install fails
sys.path.insert(0, os.path.abspath("."))

from ftracer.core.debug_thread import DebugThread
from ftracer.core.memory_scanner import MemoryScannerThread
from ftracer.core.models import TraceMode

def test_full():
    print("--- Starting ftracer Integration Test ---")
    event_queue = queue.Queue()
    
    # Launch cmd without arguments because create_process_debug doesn't support them yet
    cmd = r"c:\windows\system32\cmd.exe"
    
    debug_thread = DebugThread(
        exe_path=cmd,
        mode=TraceMode.FULL_TRACE,
        raw_event_queue=event_queue
    )
    
    debug_thread.start()
    debug_thread.started_ok.wait(timeout=5.0)
    
    if debug_thread.startup_error:
        print(f"Startup error: {debug_thread.startup_error}")
        return
        
    print(f"Process started successfully. Root PID: {debug_thread.root_pid}")
    
    scanner = MemoryScannerThread(
        get_tracked_handles=lambda: {p.pid: p.handle for p in debug_thread.tracked.values()},
        event_queue=event_queue,
        interval=0.5
    )
    scanner.start()
    
    event_count = 0
    try:
        while debug_thread.is_alive():
            try:
                event = event_queue.get(timeout=1.0)
                event_count += 1
                payload_str = str(event.payload)
                if len(payload_str) > 100:
                    payload_str = payload_str[:100] + "..."
                print(f"[{event.category}/{event.action}] PID: {event.pid} | Payload: {payload_str}")
                
                if event.action == "EXITED" and event.payload.get("is_root"):
                    print("Root process EXITED detected.")
                    break
                
                if event_count >= 15:
                    print("Reached 15 events. Stopping test to prevent hanging.")
                    break
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        print(f"Cleaning up... Total events captured: {event_count}")
        debug_thread.request_stop()
        scanner.request_stop()
        debug_thread.join(timeout=2.0)
        scanner.join(timeout=2.0)
        print("Test script finished.")

if __name__ == '__main__':
    test_full()
