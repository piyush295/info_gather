import argparse
import whois
import dns.resolver
import requests
import shodan
import socket
from ipwhois import IPWhois

def whois_lookup(domain):
    """Perform a WHOIS lookup."""
    try:
        print("\n[+] WHOIS Lookup for domain:", domain)
        whois_data = whois.whois(domain)
        print(whois_data)
    except Exception as e:
        print("[-] WHOIS lookup failed:", e)

def dns_lookup(domain):
    """Retrieve DNS records for a domain."""
    try:
        print("\n[+] DNS Records for domain:", domain)
        for record in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record)
                print(f"[{record}] Records:")
                for rdata in answers:
                    print(f"  - {rdata}")
            except Exception as e:
                print(f"  [-] No {record} record found.")
    except Exception as e:
        print("[-] DNS lookup failed:", e)

def http_headers(domain):
    """Fetch HTTP headers for a domain."""
    try:
        print("\n[+] HTTP Headers for domain:", domain)
        response = requests.get(f"http://{domain}", timeout=5)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        print("[-] Failed to fetch HTTP headers:", e)

def shodan_lookup(api_key, ip):
    """Perform a Shodan IP lookup."""
    try:
        print("\n[+] Shodan Lookup for IP:", ip)
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        for item in host['data']:
            print(f"Port: {item['port']}, Service: {item['product']}")
    except Exception as e:
        print("[-] Shodan lookup failed:", e)

def ip_geolocation(ip):
    """Retrieve geolocation for an IP."""
    try:
        print("\n[+] Geolocation for IP:", ip)
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        print(f"Country: {results['nets'][0]['country']}")
        print(f"City: {results['nets'][0]['city']}")
    except Exception as e:
        print("[-] Geolocation lookup failed:", e)

def port_scan(ip):
    """Perform a basic port scan."""
    print("\n[+] Port Scan for IP:", ip)
    try:
        for port in range(20, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  - Port {port} is open")
            sock.close()
    except Exception as e:
        print("[-] Port scanning failed:", e)

def main():
    parser = argparse.ArgumentParser(description="All-in-One Information Gathering Tool")
    parser.add_argument("-d", "--domain", help="Domain to gather information about", required=False)
    parser.add_argument("-i", "--ip", help="IP address for information gathering", required=False)
    parser.add_argument("-s", "--shodan", help="Shodan API key for IP lookup", required=False)
    
    args = parser.parse_args()
    
    if args.domain:
        whois_lookup(args.domain)
        dns_lookup(args.domain)
        http_headers(args.domain)
    
    if args.ip:
        ip_geolocation(args.ip)
        port_scan(args.ip)
        if args.shodan:
            shodan_lookup(args.shodan, args.ip)
    
    if not args.domain and not args.ip:
        print("[-] Please provide a domain (-d) or IP (-i) for information gathering.")

if __name__ == "__main__":
    main()
