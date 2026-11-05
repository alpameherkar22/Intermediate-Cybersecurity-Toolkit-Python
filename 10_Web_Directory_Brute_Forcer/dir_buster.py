import argparse
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_path(base_url, path):
    """
    Appends a path to the base URL and checks HTTP response status
    """
    # ensuring clean formatting for slashes
    full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
            headers = {"User Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Security Auditor/1.0"}
            # allowredirects=False prevents following redirection loops to soft 404 pages
            response = requests.get(full_url, headers=headers, timeout=3, allow_redirects=False)
    
            # looking for successful loads (200), redirects (301/302), and forbidden gates (403)
            if response.status_code in [200, 301, 302, 403]:
                return(full_url, response.status_code)
    
    except Exception:
            pass
    
    return None

def main():
    parser = argparse.ArgumentParser(description= "A multi-threaded web directory brute forcer for security auditing.")
    parser.add_argument("-u","--url", required=True, help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-w","--wordlist", required=True, help="Path to text file containing directories/files to teast")
    parser.add_argument("-t","--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("-o", "--output", help="Save discovered paths to a text file report")

    args = parser.parse_args()

    # loading and cleaning wordlist file
    try:
        with open(args.wordlist, "r", encoding="utf-8") as f:
            # reading lines, stripping whitespaces, ignoring empty lines or comments
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)

    print("\n" + "="*50)
    print("       WEB DIRECTORY BRUTE_FORCER (DIR_BUSTER)       ")
    print("="*50)
    print(f"[*] Target URL : {args.url}")
    print(f"[*] Wordlist   : {args.wordlist} ({len(paths)} paths loaded)")
    print(f"[*] Threads    : {args.threads}")
    print(f"[*] Started    : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50 + "\n")

    found_paths = []
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_path, args.url, path): path for path in paths}
    
            for future in as_completed(futures):
                result = future.result()
                if result:
                    url, status = result
                    print(f"[FOUND] Status: {status} -> {url}")
                    found_paths.append(result)
    
    except KeyboardInterrupt:
        print("n\n[-] Scan aborted by user (Ctrl+C). Exiting...")
        sys.exit(0)

    elasped_time = time.time() - start_time

    print("\n" + "="*50)
    print(f"[+] Scan completed in {elasped_time:.2f} seconds")
    print(f"[+] Total valid paths discovered: {len(found_paths)}")
    print("="*50)

    # saving results to file if -o flag is specified
    if args.output and found_paths:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(f"# Directory scan results for {args.url}\n")
                out_f.write(f"# Scan completed at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for url, status in found_paths:
                    out_f.write(f"[{status}] {url}\n")
            print(f"[+] Results successfully saved to: {args.output}") 
        except Exception as e:
            print(f"[-] Error saving file: {e}")

if __name__ == "__main__":
    main()