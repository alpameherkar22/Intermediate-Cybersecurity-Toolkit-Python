import socket
import datetime
import sys

def run_honeypot(host= '127.0.0.1', port= 2222):
    # creating a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)

        print("\n" + "-"*50)
        print("      BASIC NETWORK HONEYPOT (HONEYPOT_BASIC)       ")
        print("="*50)
        print(f"[*] Honeypot active on {host}:{port}")
        print(f"[*] Waiting for incoming connections... (Press Crtl+C to stop)")
        print("="*50 + "\n")

        while True:
            # accepting and incoming connection
            client_socket, client_address = server_socket.accept()
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print(f"[!] ALERT: Connection attempt form {client_address[0]}:{client_address[1]}\n")

            try:
                # sending a deceptive banner to mimic a service (e.g., fake SSH banner)
                client_socket.sendall(b"SSH-2.0-OpenSSH_8.2p1\r\n")

                # attempt to recieve any incoming payload/data from the scanner
                client_socket.settimeout(2.0)
                data = client_socket.recv(1024)
                if data:
                    print(f"[*] Captured Payload: {data}")
                    with open("honeypot_log.txt", "a", encoding="utf-8") as log_file:
                        log_file.write(f"       Payload: {data}\n")

            except socket.timeout:
                print("[-] Client connection timed out waiting for payload.")
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

if __name__ == "__main__":
    run_honeypot()