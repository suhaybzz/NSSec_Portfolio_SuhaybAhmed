# black_box_recon.py
import requests

def black_box_recon(url: str) -> None:
    """
    Very simple black-box recon:
    - Send an HTTP HEAD request
    - Print a couple of interesting headers
    """
    try:
        print(f"[+] Probing {url}")
        response = requests.head(url, timeout=5)

        print("\n[Black Box Findings]")
        server = response.headers.get("Server", "Unknown")
        ctype = response.headers.get("Content-Type", "Unknown")

        print(f"  Server:       {server}")
        print(f"  Content-Type: {ctype}")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    target_url = "https://python.org"   # keep to safe public website
    black_box_recon(target_url)
