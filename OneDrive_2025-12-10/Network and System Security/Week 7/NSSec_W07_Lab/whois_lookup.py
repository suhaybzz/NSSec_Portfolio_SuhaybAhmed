# whois_lookup.py
import socket
import requests

def get_domain_info(domain: str) -> None:
    """
    Simple, safe 'whois-style' lookup using a public IP info API.
    Only for learning – do not use against domains without permission.
    """
    try:
        # 1) Resolve domain to IP address (DNS lookup)
        ip = socket.gethostbyname(domain)
        print(f"[+] Domain: {domain}")
        print(f"[+] IP Address: {ip}")

        # 2) Call a public API to get basic info about that IP
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            print(f"[+] Organisation: {data.get('org', 'Unknown')}")
            print(f"[+] City:         {data.get('city', 'Unknown')}")
            print(f"[+] Country:      {data.get('country_name', 'Unknown')}")
        else:
            print("[-] Could not fetch extra info (non-200 status).")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    # Use a well-known public domain – educational use only.
    get_domain_info("python.org")
