import argparse
import dns.resolver
import requests
import shodan
import socket
from ipwhois import IPWhois
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def whois_lookup(domain):
    """Perform a WHOIS lookup."""
    try:
        logging.info(f"Performing WHOIS lookup for domain: {domain}")
        whois_data = whois.whois(domain)
        print(whois_data)
    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}")

def dns_lookup(domain):
    """Retrieve DNS records for a domain."""
    logging.info(f"Retrieving DNS records for domain: {domain}")
    for record in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"[{record}] Records:")
            for rdata in answers:
                print(f"  - {rdata}")
        except dns.resolver.NoAnswer:
            logging.warning(f"No {record} record found.")
        except Exception as e:
            logging.error(f"Failed to retrieve {record} records: {e}")

def http_headers(domain, use_https=False):
    """Fetch HTTP headers for a domain."""
    protocol = "https" if use_https else "http"
    try:
        logging.info(f"Fetching HTTP headers for domain: {domain} using {protocol}")
        response = requests.get(f"{protocol}://{domain}", timeout=5)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except Exception as e:
        logging.error(f"Failed to fetch HTTP headers: {e}")

def shodan_lookup(api_key, ip):
    """Perform a Shodan IP lookup."""
    try:
        logging.info(f"Performing Shodan lookup for IP: {ip}")
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        for item in host['data']:
            print(f"Port: {item['port']}, Service: {item['product']}")
    except Exception as e:
        logging.error(f"Shodan lookup failed: {e}")

def ip_geolocation(ip):
    """Retrieve geolocation for an IP."""
    try:
        logging.info(f"Retrieving geolocation for IP: {ip}")
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        print(f"Country: {results['nets'][0]['country']}")
        print(f"City: {results['nets'][0]['city']}")
    except Exception as e:
        logging.error(f"Geolocation lookup failed: {e}")

def port_scan(ip):
    """Perform a basic port scan."""
    logging.info(f"Starting port scan for IP: {ip}")
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    logging.info(f"Port {port} is open")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, range(20, 1025))

def main():
    parser = argparse.ArgumentParser(description="All-in-One Information Gathering Tool")
    parser.add_argument("-d", "--domain", help="Domain to gather information about", required=False)
    parser.add_argument("-i", "--ip", help="IP address for information gathering", required=False)
    parser.add_argument("-s", "--shodan", help="Shodan API key for IP lookup", required=False)
    parser.add_argument("--https", help="Use HTTPS for HTTP header retrieval", action="store_true")
    
    args = parser.parse_args()
    
    if args.domain:
        whois_lookup(args.domain)
        dns_lookup(args.domain)
        http_headers(args.domain, use_https=args.https)
    
    if args.ip:
        ip_geolocation(args.ip)
        port_scan(args.ip)
        if args.shodan:
            shodan_lookup(args.shodan, args.ip)
    
    if not args.domain and not args.ip:
        logging.error("Please provide a domain (-d) or IP (-i) for information gathering.")

if __name__ == "__main__":
    main()
