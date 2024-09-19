import whois
import nmap
import subprocess
import requests

def get_whois_info(url):
    try:
        domain_info = whois.whois(url)
        print(domain_info)
    except Exception as e:
        print(f"Error retrieving WHOIS information: {e}")

def scan_ports(url):
    scanner = nmap.PortScanner()
    try:
        print(f"Scanning ports on {url}...")
        scanner.scan(url)
        print(scanner.all_hosts())
    except Exception as e:
        print(f"Error scanning ports: {e}")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    get_whois_info(target_url)
    scan_ports(target_url)
