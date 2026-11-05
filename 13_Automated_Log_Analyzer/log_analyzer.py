import argparse
import re
from collections import Counter

# regex for a standard Apache/Nginx combined log format
# e.g.- 12*.*.*.* (IP address) - - [10/Nov/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 2326

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+' # IP address
    r'(?P<indentity>\S+)\s+' # Remote logname
    r'(?P<user>\S+)\s+' # Remote user
    r'\[(?P<time>[^\]]+)\]\s+' # Time
    r'"(?P<request>[^"]+)"\s+' # Request line
    r'(?P<status>\d{3})\s+' # Status code
    r'(?P<size>\S+)' # Response size
)

def analyze_logs(file_path, threshold):
    print("\n" + "="*50)
    print("      AUTOMATED LOG ANALYZER (LOG_ANALYZER)       ")
    print("="*50)
    print(f"[*] Analyzing file : {file_path}")
    print(f"[*] Alert threshold: {threshold} requests/errors")
    print("="*50 + "\n")

    ip_counter = Counter()
    status_counter = Counter()
    failed_logins = Counter()
    total_lines = 0
    parsed_lines = 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                match = LOG_PATTERN.match(line.strip())
                if match:
                    parsed_lines += 1
                    data = match.groupdict()
                    ip = data['ip']
                    status = data['status']
                    request = data['request']

                    ip_counter[ip] += 1
                    status_counter[status] += 1

                    # checking for suspicious patterns (e.g., login pages returning 401/403 or heavy error status codes)
                    if status in ['401', '403', '500']:
                        failed_logins[ip] += 1

        # generating report
        print(f"[+] Total lines processed : {total_lines}")
        print(f"[+] Successfully parsed   : {parsed_lines}\n")

        print("--- Top IP Addresses by Traffic ---")
        for ip, count in ip_counter.most_common(5):
            print("     {ip} : {count} requests")

        print("\n--- HTTP Status Code Distribution ---")
        for status, count in status_counter.items():
            print("     Status {status} : {count} occurrences")

        print("\n--- Potential Brute-Force / Suspicious IPs (Threshold >= {threshold}) --- ")
        flagged = False
        for ip, count in failed_logins.items():
            if count >= threshold:
                print(f"    [!] ALERT: IP {ip} triggered {count} error/unauthorized responses.")
                flagged = True

        if not flagged:
            print("    [-] No IPs exceeded the suspicion thresold.")

    except FileNotFoundError:
        print(f"[-] Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Automated Log Analyzer for Security Audits")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file to analyze")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Threshold for flagging suspicious IP activity")

    args = parser.parse_args()
    analyze_logs(args.file, args.threshold)

if __name__ == "__main__":
    main()