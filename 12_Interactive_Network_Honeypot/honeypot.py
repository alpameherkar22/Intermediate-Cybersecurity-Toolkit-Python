import argparse
import socket
import datetime
import sys

def run_honeypot(host, port, log_file_path):
    # creating a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)

        print("\n" + "-"*50)
        print("      POLSIHED NETWORK HONEYPOT (HONEYPOT)       ")
        print("="*50)
        print(f"[*] Honeypot active on {host}:{port}")
        print(f"[*] Logging alerts to : {log_file_path}")
        print(f"[*] Waiting for incoming connections... (Press Crtl+C to stop)")
        print("="*50 + "\n")

        while True:
            # accepting and incoming connection
            client_socket, client_address = server_socket.accept()
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            alert_msg = f"[!] ALERT: Connection attempt from {client_address[0]}:{client_address[1]} at {timestamp}"
            print(alert_msg)

            # log connection to file
            with open(log_file_path, "a", encoding="utf-8") as log_f:
                log_f.write(f"[{timestamp}] Connection from {client_address[0]}:{client_address[1]}:{port}\n")

            try:
                # sending a deceptive banner to mimic a service (e.g., fake SSH banner)
                client_socket.sendall(b"SSH-2.0-OpenSSH_8.2p1\r\n")

                # attempt to recieve any incoming payload/data from the scanner
                client_socket.settimeout(2.0)
                data = client_socket.recv(1024)
                if data:
                    payload_msg = f"    [*] Captured Payload: {data}"
                    print(payload_msg)
                    with open(log_f.name if hasattr(log_f, 'name') else log_file_path, "a", encoding="utf-8") as log_f_inner:
                        log_f_inner.write(f"       Payload: {data}\n")

            except socket.timeout:
                pass # normal if client just probes without sending data
            except Exception as e:
                print(f"[-] Error handling client: {e}")
            finally:
                client_socket.close()

    except KeyboardInterrupt:
        print("\n\n[-] Honeypot stopped by user. Exiting...")
    except Exception as e:
        print(f"[-] Error starting honeypot: {e}")
    finally:
        server_socket.close()

def main():
    parser = argparse.ArgumentParser(description="Polished Interactive Network Honeypot")
    parser.add_argument("--host", default="127.0.0.1", help="Bind IP address (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=2222, help="Port to listen on (default: 2222)")
    parser.add_argument("-o", "--output", default="honeypot_report.txt", help="Log output filename")

    args = parser.parse_args()
    run_honeypot(args.host, args.port, args.output)

if __name__ == "__main__":
    main()