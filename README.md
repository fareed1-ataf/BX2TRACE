# ftracer (TraceBox)

**Developed by FBX2**

GitHub Repository: [https://github.com/fareed1-ataf/Ftracer](https://github.com/fareed1-ataf/Ftracer)

`ftracer` is an advanced, high-performance behavioral analysis framework for Windows, specifically designed for
cybersecurity analysts and malware researchers. It provides deep visibility into process behavior, live memory changes,
and stealth debugging capabilities.

## Overview

Unlike standard debuggers, `ftracer` is built for **automated analysis** and **stealth**. It monitors process creation,
DLL loading, and thread activity while simultaneously scanning live memory for indicators of compromise (IoCs),
self-unpacking behavior, and encrypted payloads using YARA and entropy analysis.

## Key Features

* **Stealth Engine:** Automatically patches the PEB (Process Environment Block) to clear `BeingDebugged` and
  `NtGlobalFlag`, effectively evading many anti-debugging tricks used by modern malware.
* **Hardware Breakpoints (DR0-DR3):** Monitor execution without modifying the target's code, making detection much
  harder for packers.
* **Dynamic Memory Scanner:** Periodically scans committed memory regions to detect newly appeared strings and code
  decryption in real-time.
* **YARA Integration:** Scan live memory against custom YARA rules to identify specific malware families or behaviors
  instantly.
* **Entropy Analysis:** Detect packed or encrypted memory regions by calculating Shannon entropy at the page level.
* **Child Process Tracking:** Automatically follows process trees to catch "Process Hollowing" and multi-stage
  execution.
* **SQLite Storage:** All events are recorded in a structured database for post-mortem analysis and correlation.

## Installation

```bash
pip install ftracer
```

> **Important:** `ftracer` requires **Administrator privileges** to function correctly as it needs `SeDebugPrivilege` to
> monitor other processes.

## Requirements

* Windows 10/11 (x64)
* Python 3.11+
* Administrator rights

---

## Usage Guide

The `ftracer` package is a library. While it includes internal components to build complex analysis engines, most users
will interact with the high-level components or build their own tools using the provided modules.

### Python API Usage

Analysts can build their own custom analysis tools by leveraging the core components of `ftracer`.

#### 1. Basic Process Monitoring

```python
from queue import Queue
from ftracer.core.debug_thread import DebugThread
from ftracer.core.models import TraceMode

# Event queue for collecting data
event_queue = Queue()

# Initialize and start the debugger thread
debug_thread = DebugThread(
    exe_path="malware.exe",
    mode=TraceMode.FULL_TRACE,
    raw_event_queue=event_queue
)
debug_thread.start()

try:
    while debug_thread.is_alive():
        event = event_queue.get()
        print(f"[{event.severity.value}] {event.category}/{event.action}: {event.payload}")
except KeyboardInterrupt:
    debug_thread.request_stop()
```

#### 2. Advanced Memory Scanning with YARA

```python
from queue import Queue
from ftracer.core.debug_thread import DebugThread
from ftracer.core.memory_scanner import MemoryScannerThread
from ftracer.core.models import TraceMode

event_queue = Queue()

debug_thread = DebugThread("malware.exe", TraceMode.FULL_TRACE, event_queue)
debug_thread.start()
debug_thread.started_ok.wait()  # Wait for the process to launch

# Setup scanner to read tracked handles from DebugThread
scanner = MemoryScannerThread(
    get_tracked_handles=lambda: {p.pid: p.handle for p in debug_thread.tracked.values()},
    event_queue=event_queue,
    interval=2.0,
    yara_rules_path="rules.yar"
)
scanner.start()
```

### Building Custom Detectors

You can extend the framework by creating custom detection logic that consumes events from the `event_queue`. This allows
you to implement specialized behavioral rules (e.g., detecting specific API call sequences or network patterns).

---

## Technical Assessment

### Strengths

1. **Architecture:** Decoupled design using a thread-safe event queue allows adding new detection modules (Detectors)
   without touching the core engine.
2. **Performance:** Memory scanning is optimized with shared buffers and batch SQLite writes to ensure minimal impact on
   the host system.
3. **Accuracy:** Correlating high-entropy memory regions with the appearance of new strings provides a high-confidence
   signal for self-unpacking.

### Potential Weaknesses

1. **Polling Latency:** Very fast fileless malware might execute between scan intervals. (Planned: Event-driven scanning
   via API hooks).
2. **Architecture Mismatch:** Currently focused on x64 targets; 32-bit (WOW64) support is limited.

## Disclaimer

This tool is intended for educational and research purposes only. The authors are not responsible for any misuse or
damage caused by this software. Use it only on systems you own or have explicit permission to analyze.

---
**Developed for Security Engineers who need precision and stealth.**
