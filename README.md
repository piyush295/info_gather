# All-in-One Information Gathering Tool

## Overview
This Python script combines multiple information-gathering features into one tool. It can retrieve WHOIS data, DNS records, HTTP headers, IP geolocation, perform basic port scanning, and integrate with Shodan for IP lookups.

## Features
- WHOIS Lookup
- DNS Records Lookup
- HTTP Headers Inspection
- Shodan IP Information Retrieval
- IP Geolocation Lookup
- Port Scanning (Basic)

## Requirements
- Python 3.7+
- Libraries:
  - `whois`
  - `dns.resolver`
  - `requests`
  - `shodan`
  - `socket`
  - `ipwhois`

## Installation and uses
1. Clone the repository:
   ```bash
   git clone https://github.com/piyush295/info_gathering.git
   cd info-gathering-tool
   python3 info_gathering.py -d example.com
   python3 info_gathering.py -i 8.8.8.8 --shodan YOUR_SHODAN_API_KEY
   
## Install dependencies:
   ```bash
      pip install -r requirements.txt





