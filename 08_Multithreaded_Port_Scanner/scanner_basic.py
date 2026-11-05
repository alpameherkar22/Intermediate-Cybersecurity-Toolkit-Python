import socket
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(target_ip, port):
    """
    Attempts to connect to a specific port on the target IP.
    """
    try:
        # creating a standard IPv4 TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # 1 second timeout to avoid hang

        # try connecting to the target port
        result = s.connect_ex((target_ip, port))

        if result == 0:
            print(f"[+] Port {port} is OPEN")

        s.close()
    except Exception as e:
        pass

def main():
    target = input("Enter target IP to scan: ").strip()

    # test scanning ports 1 to 1024
    start_port = 1
    end_port = 1024

    print(f"\n[-] Scanning {target} across ports {start_port}-{end_port} using multithreading...")
    start_time = time.time()

    # ThreadPoolExecutor manages a pool of worker threads automatically
    # max_workers=100 allows 100 simultaneous connection attempts
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target, port)

    end_time = time.time()
    print(f"n[+] Scan completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main() 