import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
import sys

def grab_banner(ip, port, timeout=2):
    """Connects to an open port, listens for a welcome banner, or sends a light probe."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # trying to recieve a banner immediately (common for SSH, FTP, SMTP, etc.)
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                # if no immediate banner and it's a web port, send a basic HTTP probe
                if not banner and port in [80, 443, 8080, 8443]:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                banner = "No banner recieved (timeout)"

            return port, True, banner

    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""

def scan_ports(target, ports, threads):
    print("\n" + "="*50)
    print("   ADVANCED PORT SCANNER & SERVICE BANNER GRABBER   ")
    print("="*50)
    print(f"[*] Target      : {target}")
    print(f"[*] Port Range  : {ports[0]} to {ports[-1] if len(ports) > 1 else ports[0]}")
    print(f"[*] Threads     : {threads}")
    print("="*50 + "\n")

    open_ports = []

    # using ThreadPoolExecutor for high-speed concurrent scanning
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(grab_banner, target, port): port for port in ports}
        for future in futures:
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                print(f"[+] Port {port:5d} OPEN | Banner: {banner if banner else '[Open, No Banner]'}")

    print("\n" + "="*50)
    print(f"[-] Scan complete. Found {len(open_ports)} open port(s).")
    print("="*50)

def main():
    parser = argparse.ArgumentParser(description="Advanced Multi-Threaded Port Scanner & Banner Grabber")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024 or explicit list)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")

    args = parser.parse_args()

    # resolving target domain to IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve target '{args.target}")
        sys.exit(1)

    # parsing port range format
    port_list = []
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        port_list = range(start, end + 1)
    elif "," in args.ports:
        port_list = [int(p.strip()) for p in args.ports.split(",")]
    else:
        port_list = [int(args.ports)]

    scan_ports(target_ip, port_list, args.threads)

if __name__ == "__main__":
    main()