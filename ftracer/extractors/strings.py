"""
extractors/strings.py
=======================
Pure functions: bytes → list[str]. Stateless, no knowledge of Windows.
This file is the "heart" of the project's utility (detecting decryption) — it must be accurate
and well-tested in isolation from any other complexity.
"""

import re

# --- Raw extraction patterns are compiled per-call inside each function
# (using % min_length) to support a configurable min_length argument.
# No module-level pattern constants here — they caused re.error on Python 3.12+.

# --- "Interesting" patterns to increase confidence (used later in the classification phase) ---
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]{4,256}")
IPV4_PATTERN = re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}")


def extract_ascii_strings(data: bytes, min_length: int = 5) -> list[str]:
    """Extracts consecutive ASCII strings with length >= min_length."""
    pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def extract_utf16le_strings(data: bytes, min_length: int = 5) -> list[str]:
    """
    Extracts UTF-16LE strings (the default text encoding inside Windows memory,
    especially since most Win32 APIs use the "W" version of them). Without this, you miss
    all text stored in this encoding — which is actually the most common inside live memory
    on Windows, more than pure ASCII.
    """
    pattern = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_length)
    results = []
    for m in pattern.finditer(data):
        try:
            results.append(m.group().decode("utf-16-le", errors="ignore"))
        except UnicodeDecodeError:
            continue
    return results


def extract_strings(data: bytes, min_length: int = 5) -> list[str]:
    """
    Main function: combines both types, removes duplicates, and returns a clean list.
    Order of results is not guaranteed (we use set for deduplication) — if order is important
    for future use, use extract_ascii_strings/utf16 separately.
    """
    combined = extract_ascii_strings(data, min_length) + extract_utf16le_strings(data, min_length)
    return list(dict.fromkeys(combined))  # Preserves order and removes duplicates


def diff_new_strings(previous: list[str], current: list[str]) -> list[str]:
    """
    Returns text present in current but NOT present in previous only —
    this is the "Golden Signal": new text appearing means a change happened in memory.
    """
    previous_set = set(previous)
    return [s for s in current if s not in previous_set]
