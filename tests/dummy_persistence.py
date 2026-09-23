import winreg
import sys
import time

def main():
    print("[Dummy] Starting malicious simulation...")
    # Sleep slightly to let the debugger attach fully
    time.sleep(1.0)
    
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    try:
        print(f"[Dummy] Attempting to open registry key: {key_path}")
        # HKEY_CURRENT_USER does not require Admin privileges, perfect for testing
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        
        print("[Dummy] Writing payload to Run key (Persistence)...")
        # Write a fake malware path
        winreg.SetValueEx(key, "Bx2TestMalware", 0, winreg.REG_SZ, "C:\\FakeMalware.exe")
        winreg.CloseKey(key)
        
        print("[Dummy] Cleaning up... deleting the fake key so the system stays clean.")
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "Bx2TestMalware")
        winreg.CloseKey(key)
        print("[Dummy] Simulation complete.")
        
    except Exception as e:
        print(f"[Dummy] Error during simulation: {e}")

if __name__ == "__main__":
    main()
