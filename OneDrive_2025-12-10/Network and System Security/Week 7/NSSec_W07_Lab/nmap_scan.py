# nmap_scan.py
import nmap

def nmap_scan(host: str, port_range: str = "1-1024") -> None:
    """
    Wrapper around nmap.PortScanner.
    Runs a service/version scan (-sV) on the given host and port range.
    """
    nm = nmap.PortScanner()

    try:
        print(f"[+] Starting Nmap scan on {host} ports {port_range} ...")
        nm.scan(host, port_range, arguments="-sV")  # -sV = service/version

        for h in nm.all_hosts():
            print(f"\nHost:  {h} ({nm[h].hostname()})")
            print(f"State: {nm[h].state()}")

            for proto in nm[h].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[h][proto].keys()
                for port in sorted(ports):
                    service = nm[h][proto][port]
                    name = service.get("name", "unknown")
                    version = service.get("version", "")
                    state = service["state"]
                    print(f"  Port {port:5}  State: {state:7}  Service: {name} {version}")

    except Exception as e:
        print(f"[!] Error running nmap scan: {e}")
        print("    Make sure Nmap is installed on your system.")

if __name__ == "__main__":
    # Only scan localhost or explicitly authorised lab machines
    nmap_scan("127.0.0.1", "1-100")
