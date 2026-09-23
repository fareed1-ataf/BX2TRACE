import ctypes
import time
import os

kernel32 = ctypes.windll.kernel32

def main():
    print("[Dummy Memory Scanner] Starting memory allocation simulation...")
    
    # Step 1: Allocate a page with PAGE_EXECUTE_READWRITE (0x40)
    # This is suspicious by itself and will attract the memory scanner
    alloc_addr = kernel32.VirtualAlloc(0, 4096, 0x3000, 0x40)
    
    # Step 2: Create a buffer containing a lot of strings and a fake malicious indicator
    payload = (
        b"http://malicious-c2-domain.com/drop.exe\x00"
        b"cmd.exe /c powershell -enc ZWNobyBoYWNrZWQ=\x00"
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"CreateRemoteThread\x00"
        b"VirtualAllocEx\x00"
        b"LoadLibraryA\x00"
        b"GetProcAddress\x00"
        # We add a fake YARA match string: "MALWARE_SIGNATURE_123"
        b"MALWARE_SIGNATURE_123\x00"
    )
    
    # Pad it so it crosses the string threshold
    for i in range(50):
        payload += f"FAKE_API_FUNCTION_NAME_{i}\x00".encode('ascii')
        
    print(f"[Dummy Memory Scanner] Writing {len(payload)} bytes to RWX memory at {hex(alloc_addr)}...")
    
    # Write to the allocated memory
    ctypes.memmove(alloc_addr, payload, len(payload))
    
    # Step 3: Sleep to ensure the background memory scanner has time to scan our process.
    # The default scan interval is 5 seconds, so we sleep for 8 seconds.
    print("[Dummy Memory Scanner] Sleeping for 8 seconds to allow memory scanner to run...")
    time.sleep(8.0)
    
    print("[Dummy Memory Scanner] Simulation complete.")

if __name__ == "__main__":
    main()
