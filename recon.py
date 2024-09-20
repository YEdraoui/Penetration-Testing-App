import whois
import socket
import subprocess


def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")
        return None


def get_dns_info(domain):
    try:
        
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.split("//")[1]
        result = socket.gethostbyname(domain)
        return result
    except Exception as e:
        print(f"Error fetching DNS data: {e}")
        return None
    

def get_ssl_info(domain):
    try:
        # Remove protocol from the domain
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.split("//")[1]
        result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443'], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        print(f"Error fetching SSL/TLS info: {e}")
        return None
