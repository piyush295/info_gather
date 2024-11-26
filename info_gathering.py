import argparse
import whois
import dns.resolver
import requests
import shodan
import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from ipwhois import IPWhois

# Set up logging
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
    try:
        logging.info(f"Retrieving DNS records for domain: {domain}")
        for record in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record)
                print(f"[{record}] Records:")
                for rdata in answers:
                    print(f"  - {rdata}")
            except dns.resolver.NoAnswer:
                logging.warning(f"No {record} record found for domain: {domain}")
            except Exception as e:
                logging.error(f"Failed to retrieve {record} records: {e}")
    except Exception as e:
        logging.error(f"DNS lookup failed: {e}")

def http_headers(domain):
    """Fetch HTTP headers for a domain."""
    try:
        logging.info(f"Fetching HTTP headers for domain: {domain}")
        for protocol in ['http', 'https']:
            try:
                response = requests.get(f"{protocol}://{domain}", timeout=5)
                print(f"\n{protocol.upper()} Headers:")
                for header, value in response.headers.items():
                    print(f"{header}: {value}")
            except requests.RequestException as e:
                logging.warning(f"Failed to fetch {protocol.upper()} headers: {e}")
    except Exception as e:
        logging.error(f"HTTP headers fetch failed: {e}")

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
            print(f"Port: {item['port']}, Service: {item.get('product', 'N/A')}")
    except shodan.APIError as e:
        logging.error(f"Shodan lookup failed: {e}")
    except Exception as e:
        logging.error(f"Shodan lookup error: {e}")

def ip_geolocation(ip):
    """Retrieve geolocation for an IP."""
    try:
        logging.info(f"Performing geolocation lookup for IP: {ip}")
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        print(f"Country: {results['nets'][0]['country']}")
        print(f"City: {results['nets'][0].get('city', 'N/A')}")
    except Exception as e:
        logging.error(f"Geolocation lookup failed: {e}")

def port_scan(ip):
    """Perform a basic port scan using threading."""
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                logging.info(f"Port {port} is open on IP: {ip}")
            sock.close()
        except Exception as e:
            logging.warning(f"Error scanning port {port}: {e}")

    logging.info(f"Starting port scan for IP: {ip}")
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, range(20, 1025))

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
        logging.error("Please provide a domain (-d) or IP (-i) for information gathering.")

if __name__ == "__main__":
    main()
