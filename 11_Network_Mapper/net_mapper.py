import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import sys

def check_host(ip, port=445, timeout=0.5):
    """
    Checks if host is active by attempting a quick TCP connection 
    on common responsive port (default port 445/SMB)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                return str(ip)
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Basic Multi-Threaded Network Mapper")
    parser.add_argument("-t", "--target", required=True, help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--port", type=int, default=445, help="Target TCP port to probe (default: 445)")
    parser.add_argument("--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("-o", "--output", help="Save discovered active hosts to a text file report.")

    args = parser.parse_args()


    # parsing network range
    try:
        network = ipaddress.ip_network(args.target, strict=False)
    except ValueError as e:
        print(f"[-] Invalid network format -> {e}")
        return

    hosts = list(network.hosts())

    print("\n" + "="*50)
    print("           POLISHED NETWORK MAPPER (NET_MAPPER)")
    print("="*50)
    print(f"[*] Target Subnet : {args.target}")
    print(f"[*] Probe Port    : {args.port}")
    print(f"[*] Total Hosts   : {len(hosts)}")
    print(f"[*] Threads       : {args.threads}")
    print(f"[*] Started       : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50 + "\n")

    active_hosts = []
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_host, ip, args.port): ip for ip in hosts}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(f"[+] Active Host: {result}")
                    active_hosts.append(result)

    except KeyboardInterrupt:
        print("\n\n[-] Scan aborted by user. Exiting...")
        sys.exit(0)

    elasped_time = time.time() - start_time

    print("\n" + "="*50)
    print(f"[+] Scan completed in {elasped_time:.2f} seconds.")
    print(f"[+] Total active hosts discovered: {len(active_hosts)}")
    print("="*50)

    # saving results to file if -o flag is specified
    if args.output and active_hosts:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(f"# Network scan results for {args.target} (Port: {args.port})\n")
                out_f.write(f"# Scan completed at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for host in active_hosts:
                    out_f.write(f"{host}\n")
            print(f"[+] Results successfully saved to: {args.output}")

        except Exception as e:
            print(f"[-] Error saving file: {e}")

if __name__ == "__main__":
    main()