import socket
import time
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# thread lock to keep console output clean and syncronized
print_lock = threading.Lock()

def scan_port(target_ip, port):
    """
    Attempts to connect to a specific port on the target IP.
    Returns the port if open.
    Else None.
    """
    try:
        # creating a standard IPv4 TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # 1 second timeout to avoid hang

        # try connecting to the target port
        result = s.connect_ex((target_ip, port))
        s.close()

        if result == 0:
            with print_lock:
                print(f"[+] Port {port} is OPEN")
                return port
            
    except Exception:
        pass
    return None

def main():
    # setting up command-line argument parsing
    parser = argparse.ArgumentParser(description="A fast multithreaded TCP port scanner built from scratch.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname to scan")
    parser.add_argument("-s", "--start-port", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("-e", "--end-port", type=int, default=1024, help="Ending port (default: 1024)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-o", "--output", help="Save open ports to a specified text file report")

    args = parser.parse_args()

    print(f"\n[-] Scanning {args.target} across ports {args.start_port}-{args.end_port} using {args.workers} threads...")
    start_time = time.time()

    open_ports = []

    try:
        # ThreadPoolExecutor manages a pool of worker threads automatically
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            # submitting all port scanning tasks
            futures = {executor.submit(scan_port, args.target, port): port for port in range(args.start_port, args.end_port + 1)}

            # collecting results as threads finish
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

    except KeyboardInterrupt:
        print("\n\n[-] Scan aborted by user (Ctrl+C). Exiting gracefully...")
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(0)

    end_time = time.time()

    print(f"\n[+] Scan completed in {end_time - start_time:.2f} seconds.")
    print(f"[+] Total open ports found: {len(open_ports)}")

    # saving results to file if -o argument was provided 
    if args.output and open_ports:
        try:
            with open(args.output, "w") as f:
                f.write(f"Scan Report for target: {args.target}\n")
                f.write(f"Scanned range: {args.start_port}-{args.end_port}\n")
                f.write("-" * 35 +"\n")
                for port in sorted(open_ports):
                    f.write(f"Port {port} OPEN\n")
            print(f"[+] Results successfully saved to {args.output}")

        except Exception as e:
            print(f"[-] Error saving to file: {e}")

if __name__ == "__main__":
    main() 