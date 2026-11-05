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

def scan_headers(target_url, output_file = None):
    """
    Sends an HTTP GET request to the target URL and audits response header.
    """
    # ensuring url has a scheme
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    print(f"\n[-] Inspecting HTTP Security headers for: {target_url}\n")

    # custom User-Agent to mimic a standard security auditing tool/browser
    headers_sent = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityHeaderAuditor/1.0"
    }

    try:
        # sending a GET request with timeout (so it doesn't hang)
        # allow_redirects=True follows standard redirects (examples: HTTP to HTTPS)
        response = requests.get(target_url, timeout=5, allow_redirects=True)

        final_url = response.url
        status_code = response.status_code

        print(f"[+] Final URL: {response.url}")
        print(f"[+] HTTP Status Code: {response.status_code}\n")

        resp_headers = response.headers
        present_count = 0
        report_lines = []

        # building report header info
        report_lines.append("HTTP Security Header Audit Report")
        report_lines.append(f"Target URL: {final_url}")
        report_lines.append(f"Status Code: {status_code}")
        report_lines.append("-" * 50)

        print("--- Header Audit Results ---")
        for header, description in SECURITY_HEADERS.items():
            if header in resp_headers:
                msg = f"[FOUND] {header}\n        Value: {resp_headers[header]}"
                print(msg)
                report_lines.append(f"FOUND: {header} -> {resp_headers[header]}")
                present_count += 1
            else:
                msg = f"[MISSING] {header}          Purpose: {description}"
                print(msg)
                report_lines.append(f"[MISSING] {header}(Purpose: {description})")
            print("-" * 50)

        summary_msg = f"\n[+] Audit Summary: {present_count}/{len(SECURITY_HEADERS)} recommended security headers present."
        print(summary_msg)
        report_lines.append("-" * 50)
        report_lines.append(f"Summary: {present_count}/{len(SECURITY_HEADERS)} recommended security headers present.")

        # save to file if output argument is provided
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines) + "\n")
            print(f"[+] Report successfully saved to {output_file}")
    
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.TooManyRedirects) as e:
        print(f"[-] Connection error or invalid URL: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="An HTTP Security Scanner to audit web application posture.")
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain to scan (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Save the header audit report to a specified text file.")

    args = parser.parse_args()
    scan_headers(args.url, args.output)

if __name__ =="__main__":
    main()