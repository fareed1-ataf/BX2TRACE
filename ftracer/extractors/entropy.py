"""
extractors/entropy.py
=======================
Pure function entirely: bytes → float. Stateless, no knowledge of anything
outside its scope. Can be tested in complete isolation, even without Windows or any running process.
"""

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy for a sequence of bytes. Value is between 0.0 and 8.0:
    - Close to 0: highly repetitive data (like a page of zeros, or a repeating plain text pattern)
    - Close to 8: completely random data (typical for compressed/encrypted data)

    ⚠️ Important note to remember during interpretation: high entropy alone is not definitive
    proof of "decryption" — regular compressed text (e.g., JPEG images) also has
    high entropy. We use it as an initial indicator paired with other indicators (sudden appearance
    of clear strings, page protection changing to RWX) not as sole evidence.
    """
    if not data:
        return 0.0

    length = len(data)
    frequency = Counter(data)

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def entropy_by_page(data: bytes, page_size: int = 4096) -> list[tuple[int, float]]:
    """
    Splits large data into pages (default 4KB, the same as a Windows memory page size)
    and calculates entropy for each page separately, instead of a single number for the whole block.

    Why is this better than one overall entropy? Because a large memory region might contain
    a "normal" part (regular code) and an "encrypted" part at the same time — a single number
    mixes the two and hides the signal. We return a list of (offset, entropy) for each page
    so higher layers (correlation) can pinpoint exactly "where" the change occurred.
    """
    results = []
    for offset in range(0, len(data), page_size):
        chunk = data[offset : offset + page_size]
        results.append((offset, shannon_entropy(chunk)))
    return results
