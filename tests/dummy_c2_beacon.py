import socket
import time

def main():
    print("[Dummy C2] Starting C2 beaconing simulation...")
    
    # We will connect to a public IP (Google DNS) on port 80 
    # to simulate a C2 check-in. The beacon detector triggers on 3 connections.
    target_ip = "8.8.8.8"
    target_port = 80
    
    for i in range(4): # Loop 4 times to exceed the default threshold of 3
        try:
            print(f"[Dummy C2] Connection attempt {i+1} to {target_ip}:{target_port}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, target_port))
            # Just connect and close, like a simple ping
            s.close()
            print(f"[Dummy C2] Connection {i+1} successful.")
        except Exception as e:
            print(f"[Dummy C2] Connection {i+1} failed: {e}")
            
        time.sleep(1.0) # Wait before the next beacon
        
    print("[Dummy C2] Beaconing simulation complete.")

if __name__ == "__main__":
    main()
