Documentation
Usage
Install Dependencies:

Install the required Python libraries:
bash
Copy code
pip install python-whois dnspython shodan requests
Run the Script:

bash
Copy code
python3 info_gathering.py -d example.com -i 192.168.1.1 -u https://example.com
Arguments:

-d, --domain: Domain name for WHOIS and DNS lookups.
-i, --ip: IP address for Shodan searches.
-u, --url: URL for HTTP header analysis.
Code Breakdown
whois_lookup(domain):

Uses the whois library to fetch domain ownership and registration details.
Handles exceptions gracefully.
dns_lookup(domain):

Retrieves DNS records (e.g., A, AAAA, MX, TXT).
Leverages the dns.resolver module from dnspython.
shodan_lookup(ip):

Interacts with the Shodan API to gather IP-related data.
Requires a valid Shodan API key.
fetch_http_headers(url):

Sends an HTTP HEAD request using the requests library.
Prints out all the HTTP headers returned by the server.
main():

Parses user arguments and calls the appropriate functions based on input.
Sample Output
Command:

bash
Copy code
python3 info_gathering.py -d example.com -i 8.8.8.8 -u https://google.com
Output:

yaml
Copy code
=======================================
      All-in-One Info Gathering Tool
=======================================

[+] Performing WHOIS lookup for: example.com
domain_name: example.com
creation_date: 1995-08-14
expiration_date: 2025-08-14
registrant_name: Example Inc.
...

[+] Retrieving DNS records for: example.com
[+] A Records:
93.184.216.34

[+] Searching Shodan for IP: 8.8.8.8
Organization: Google LLC
Operating System: N/A
Last Update: 2023-10-20
Open Ports: [53]

[+] Fetching HTTP headers for: https://google.com
Date: Tue, 26 Nov 2024 14:32:01 GMT
Content-Type: text/html; charset=ISO-8859-1
...

Next Steps
Replace the placeholder Shodan API key with your own.
Extend the script by integrating additional APIs (e.g., VirusTotal, GeoIP).
Enhance output formatting using libraries like tabulate or rich.
