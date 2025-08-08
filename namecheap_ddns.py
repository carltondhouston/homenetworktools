import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration from .env
DOMAIN = os.getenv("DOMAIN")
HOSTS = os.getenv("HOSTS").split(",") if os.getenv("HOSTS") else []
PASSWORD = os.getenv("DDNS_PASSWORD")
IP_SERVICE = "https://ipinfo.io/ip"  # Service to get public IP
NAMECHEAP_DDNS_URL = "https://dynamicdns.park-your-domain.com/update"

def get_public_ip():
    """Retrieve the current public IP address."""
    try:
        response = requests.get(IP_SERVICE, timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None

def get_current_dns_ip(host, domain):
    """Retrieve the current IP address from DNS for the given host and domain."""
    try:
        import socket
        # Use bare domain for '@' host, otherwise construct host.domain
        hostname = domain if host == "@" else f"{host}.{domain}"
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Error resolving DNS for {hostname}: {e}")
        return None

def update_namecheap_ddns(host, domain, password, ip):
    """Update Namecheap Dynamic DNS with the provided IP."""
    params = {
        "host": host,
        "domain": domain,
        "password": password,
        "ip": ip
    }
    try:
        response = requests.get(NAMECHEAP_DDNS_URL, params=params, timeout=10)
        response.raise_for_status()
        print(f"Successfully updated {host}.{domain} to IP {ip}")
        return True
    except requests.RequestException as e:
        print(f"Error updating {host}.{domain}: {e}")
        return False

def main():
    # Validate environment variables
    if not all([DOMAIN, HOSTS, PASSWORD]):
        print("Missing required environment variables (DOMAIN, HOSTS, DDNS_PASSWORD).")
        return

    # Get current public IP
    current_ip = get_public_ip()
    if not current_ip:
        print("Failed to retrieve public IP. Exiting.")
        return

    # Update each host
    for host in HOSTS:
        host = host.strip()  # Clean any whitespace from host names
        # Get current DNS IP
        dns_ip = get_current_dns_ip(host, DOMAIN)
        if dns_ip == current_ip:
            hostname = DOMAIN if host == "@" else f"{host}.{DOMAIN}"
            print(f"No update needed for {hostname}. IP: {dns_ip}")
            continue

        # Update DNS if IPs differ
        if update_namecheap_ddns(host, DOMAIN, PASSWORD, current_ip):
            hostname = DOMAIN if host == "@" else f"{host}.{DOMAIN}"
            print(f"Updated {hostname} to {current_ip}")
        else:
            print(f"Failed to update {host}.{DOMAIN}")

if __name__ == "__main__":
    main()
