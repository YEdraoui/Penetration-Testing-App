import nmap
def scan_ports(domain):
    scanner = nmap.PortScanner()
    try:
        print(f"Scanning ports on {domain}...")
        scanner.scan(domain, '1-1024')
        for host in scanner.all_hosts():
            print(f"Host: {host}")
            print("Open ports:")
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    print(f"Port {port}: {scanner[host][proto][port]['state']}")
    except Exception as e:
        print(f"Error scanning ports: {e}")
