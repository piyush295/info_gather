import argparse
import whois
import dns.resolver
import shodan
import requests
from datetime import datetime

# SHODAN API Key (Replace with your actual key)
SHODAN_API_KEY = "your_shodan_api_key"

def banner():
    print("""
    =======================================
          All-in-One Info Gathering Tool
    =======================================
    """)

def whois_lookup(domain):
    """Perform a WHOIS lookup for the given domain."""
    try:
        print(f"\n[+] Performing WHOIS lookup for: {domain}")
        domain_info = whois.whois(domain)
        for key, value in domain_info.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")

def dns_lookup(domain):
    """Fetch DNS records for the given domain."""
    try:
        print(f"\n[+] Retrieving DNS records for: {domain}")
        records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in records:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answers:
                print(f"\n[+] {record_type} Records:")
                for rdata in answers:
                    print(rdata)
    except Exception as e:
        print(f"[-] DNS lookup failed: {e}")

def shodan_lookup(ip):
    """Perform a Shodan search for the given IP."""
    try:
        print(f"\n[+] Searching Shodan for IP: {ip}")
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        print(f"[+] Shodan Results for {ip}:")
        print(f"Organization: {result.get('org', 'N/A')}")
        print(f"Operating System: {result.get('os', 'N/A')}")
        print(f"Last Update: {result.get('last_update', 'N/A')}")
        print(f"Open Ports: {result.get('ports', [])}")
        for item in result['data']:
            print(f"\nBanner:\n{item.get('data', '')}")
    except Exception as e:
        print(f"[-] Shodan lookup failed: {e}")

def fetch_http_headers(url):
    """Fetch HTTP headers for the given URL."""
    try:
        print(f"\n[+] Fetching HTTP headers for: {url}")
        response = requests.head(url, timeout=10)
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"[-] HTTP headers lookup failed: {e}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="All-in-One Information Gathering Tool")
    parser.add_argument("-d", "--domain", help="Domain name for footprinting")
    parser.add_argument("-i", "--ip", help="IP address for Shodan lookup")
    parser.add_argument("-u", "--url", help="URL for HTTP headers lookup")
    args = parser.parse_args()

    if not args.domain and not args.ip and not args.url:
        parser.error("[-] At least one of --domain, --ip, or --url is required.")

    if args.domain:
        whois_lookup(args.domain)
        dns_lookup(args.domain)

    if args.ip:
        shodan_lookup(args.ip)

    if args.url:
        fetch_http_headers(args.url)

if __name__ == "__main__":
    main()
