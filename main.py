import sys
from recon import get_whois_info, get_dns_info, get_ssl_info
from port_scan import scan_ports
from vuln_scan import zap_scan
from exploit import sql_injection_test
from report import generate_report
from urllib.parse import urlparse



#test
def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # Handles cases where netloc might be empty
    return domain

def main():
    if len(sys.argv) != 3 or sys.argv[1] != '--url':
        print("Usage: python3 main.py --url <target_url>")
        sys.exit(1)

    target_url = sys.argv[2]
    domain = extract_domain(target_url)  # Use the domain extraction

    print(f"Starting scan for {target_url}")

    # Step 1: Reconnaissance
    print("\n[+] Performing WHOIS Lookup...")
    whois_data = get_whois_info(domain)

    print("\n[+] Performing DNS Lookup...")
    dns_data = get_dns_info(domain)

    print("\n[+] Fetching SSL/TLS Information...")
    ssl_data = get_ssl_info(domain)

    # Step 2: Port Scanning
    print("\n[+] Scanning for Open Ports...")
    scan_ports(domain)

    # Step 3: Vulnerability Scanning (OWASP ZAP)
    print("\n[+] Running Vulnerability Scan with OWASP ZAP...")
    zap_report = zap_scan(target_url)

    # Step 4: SQL Injection Testing (Sqlmap)
    print("\n[+] Testing for SQL Injection...")
    sql_injection_result = sql_injection_test(target_url)

    # Step 5: Generating Report
    vulnerabilities = [
        {"WHOIS Info": whois_data},
        {"DNS Info": dns_data},
        {"SSL Info": ssl_data},
        {"ZAP Scan": zap_report},
        {"SQL Injection Test": sql_injection_result}
    ]
    
    print("\n[+] Generating Vulnerability Report...")
    generate_report(vulnerabilities, "vulnerability_report.pdf")
    print("\nReport generated: vulnerability_report.pdf")

if __name__ == "__main__":
    main()
