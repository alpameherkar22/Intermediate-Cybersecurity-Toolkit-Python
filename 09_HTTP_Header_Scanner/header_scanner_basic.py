import argparse
import sys
import requests

# dictionary of critical security header and why they matter
SECURITY_HEADERS = {
    "Strict-Transport_Security": "Enforces secure (HTTPS) connections to the server.",
    "Content-Security_Policy": "Mitigates XSS and data injection attacks by restricting resource loading",
    "X-Frame_Options": "Protects against Clickjacking by controlling if the site can be framed.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing browsers away from declared content types.",
    "X-XSS-Protection": "Enables cross-site scripting filtering (legacy, but still checked).",
    "Referrer-Policy": "Controls how much referrer information is included with requests."
}

def scan_headers(target_url):
    """
    Sends an HTTP GET request to the target URL and audits response header.
    """
    # ensuring url has a scheme
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    print(f"\n[-] Inspecting HTTP Security headers for: {target_url}\n")

    try:
        # sending a GET request with timeout (so it doesn't hang)
        # allow_redirects=True follows standard redirects (examples: HTTP to HTTPS)
        response = requests.get(target_url, timeout=5, allow_redirects=True)

        print(f"[+] Final URL: {response.url}")
        print(f"[+] HTTP Status Code: {response.status_code}\n")

        headers = response.headers
        present_count = 0

        print("--- Header Audit Results ---")
        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                print(f"[FOUND] {header}")
                print(f"        Value: {headers[header]}")
                present_count += 1
            else:
                print(f"[MISSING] {header}")
                print(f"          Purpose: {description}")

            print("-" * 50)

        print(f"\n[+] Audit Summary: {present_count}/{len(SECURITY_HEADERS)} recommended security headers present.")

    
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.TooManyRedirects) as e:
        print(f"[-] Connection error or invalid URL: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="An HTTP Security Scanner to audit web application posture.")
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain to scan (e.g. example.com)")

    args = parser.parse_args()
    scan_headers(args.url)

if __name__ =="__main__":
    main()