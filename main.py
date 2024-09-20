import subprocess
import socket
import logging
import whois
import ssl
import OpenSSL
import requests
import argparse
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(filename="scan_results.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# WHOIS Lookup
def whois_lookup(domain):
    """Performs a WHOIS lookup for the given domain."""
    try:
        w = whois.whois(domain)
        result = f"WHOIS Lookup for {domain}:\n{w}"
        print(result)
        logging.info(result)
    except Exception as e:
        error_msg = f"WHOIS Lookup failed for {domain}: {e}"
        print(error_msg)
        logging.error(error_msg)

# DNS Lookup
def dns_lookup(domain):
    """Performs a DNS lookup to get the IP address of the domain."""
    try:
        ip = socket.gethostbyname(domain)
        result = f"DNS Lookup for {domain}: {ip}"
        print(result)
        logging.info(result)
        return ip
    except socket.error as e:
        error_msg = f"DNS Lookup failed for {domain}: {e}"
        print(error_msg)
        logging.error(error_msg)
        return None

# SSL/TLS Information
def ssl_info(ip):
    """Fetches SSL/TLS certificate information from the IP address."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                issuer = x509.get_issuer()
                subject = x509.get_subject()
                result = f"SSL/TLS Info for {ip}:\nSubject: {subject}\nIssuer: {issuer}"
                print(result)
                logging.info(result)
    except Exception as e:
        error_msg = f"SSL/TLS fetch failed for {ip}: {e}"
        print(error_msg)
        logging.error(error_msg)

# Open Port Scanning
def scan_ports(ip):
    """Scans common ports on the IP address to check if they are open."""
    open_ports = []
    ports = [80, 443, 21, 22, 23, 25, 53, 110, 143]
    print(f"\nScanning ports on {ip}...")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            error_msg = f"Port scanning error on port {port}: {e}"
            print(error_msg)
            logging.error(error_msg)
    if open_ports:
        result = f"Open ports on {ip}: {open_ports}"
    else:
        result = f"No open ports found on {ip}."
    print(result)
    logging.info(result)

# Vulnerability Scan with OWASP ZAP
def run_zap_scan(target_url):
    """Runs a vulnerability scan using OWASP ZAP."""
    try:
        print(f"\nRunning OWASP ZAP scan on {target_url}...")
        # Replace with the actual ZAP API call or subprocess command
        # Example placeholder:
        zap_command = ["zap-cli", "quick-scan", target_url]
        subprocess.run(zap_command, timeout=300)
        result = f"OWASP ZAP scan completed for {target_url}."
        print(result)
        logging.info(result)
    except Exception as e:
        error_msg = f"OWASP ZAP scan failed for {target_url}: {e}"
        print(error_msg)
        logging.error(error_msg)

# Non-Aggressive SQL Injection Test
def sql_injection_test(target_url):
    """Performs a basic SQL Injection test on the target URL."""
    print(f"\nPerforming non-aggressive SQL Injection test on {target_url}...")
    payloads = ["'", "' OR '1'='1", "' OR '1'='1'--", "';"]
    vulnerable = False
    for payload in payloads:
        test_url = f"{target_url}{payload}"
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            errors = ["sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark"]
            if any(error.lower() in response.text.lower() for error in errors):
                result = f"Possible SQL Injection vulnerability detected at {test_url}"
                print(result)
                logging.warning(result)
                logging.info(f"Response: {response.text[:200]}...")  # Log first 200 characters
                vulnerable = True
                break
        except requests.RequestException as e:
            error_msg = f"Error testing SQL injection for {test_url}: {e}"
            print(error_msg)
            logging.error(error_msg)
    if not vulnerable:
        result = f"No SQL Injection vulnerability detected for {target_url}"
        print(result)
        logging.info(result)

def main():
    parser = argparse.ArgumentParser(description="Penetration Testing Script")
    parser.add_argument('--url', required=True, help='Target URL to scan')
    args = parser.parse_args()

    target_url = args.url
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path

    print(f"Starting scan for {target_url}\n")

    # WHOIS Lookup
    whois_lookup(domain)

    # DNS Lookup
    ip = dns_lookup(domain)
    if not ip:
        print("Terminating scan due to DNS lookup failure.")
        return

    # SSL/TLS Information
    ssl_info(ip)

    # Open Port Scanning
    scan_ports(ip)

    # Vulnerability Scan with OWASP ZAP
    run_zap_scan(target_url)

    # Non-Aggressive SQL Injection Test
    sql_injection_test(target_url)

    print("\nScan completed.")

if __name__ == "__main__":
    main()
