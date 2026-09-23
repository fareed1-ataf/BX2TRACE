import ctypes
from ctypes import wintypes
import time

kernel32 = ctypes.windll.kernel32

def main():
    print("[Dummy Hollowing] Starting Process Hollowing simulation...")
    
    # Step 1: Open a handle to our OWN process. 
    # It's completely safe and works just as well to trigger the API hooks.
    pid = kernel32.GetCurrentProcessId()
    print(f"[Dummy Hollowing] Target PID: {pid}")
    
    # PROCESS_ALL_ACCESS
    h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)
    
    if not h_process:
        print("[Dummy Hollowing] Failed to open process.")
        return

    # Step 2: VirtualAllocEx
    # MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_EXECUTE_READWRITE = 0x40
    print("[Dummy Hollowing] Calling VirtualAllocEx...")
    alloc_addr = kernel32.VirtualAllocEx(h_process, 0, 4096, 0x3000, 0x40)
    
    # Step 3: WriteProcessMemory
    # We just write some harmless text
    print("[Dummy Hollowing] Calling WriteProcessMemory...")
    harmless_payload = b"This is just a test payload for bx2trace\x00"
    bytes_written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(h_process, alloc_addr, harmless_payload, len(harmless_payload), ctypes.byref(bytes_written))
    
    # Step 4: CreateRemoteThreadEx
    # We attempt to start a thread on the harmless string. It will immediately crash the new thread, 
    # but the API call itself is what the detector cares about.
    print("[Dummy Hollowing] Calling CreateRemoteThreadEx...")
    h_thread = ctypes.c_void_p(0)
    kernel32.CreateRemoteThreadEx(
        h_process, None, 0, ctypes.c_void_p(alloc_addr), None, 0, None, ctypes.byref(h_thread)
    )
    
    # Let the thread fail and close handles
    time.sleep(1)
    kernel32.CloseHandle(h_process)
    print("[Dummy Hollowing] Simulation complete.")

if __name__ == "__main__":
    main()
