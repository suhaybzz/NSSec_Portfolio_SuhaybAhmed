# basic_port_scanner.py
import socket

def scan_ports(host: str, ports: list[int]) -> list[int]:
    """
    Very simple TCP connect scanner.
    ONLY use against localhost or systems you own/have explicit permission for.
    """
    open_ports: list[int] = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))  # 0 = success
        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports

if __name__ == "__main__":
    target_host = "127.0.0.1"              # localhost only
    target_ports = [22, 80, 443, 8080]     # demo set

    print(f"[+] Scanning {target_host} on ports {target_ports}")
    open_ports = scan_ports(target_host, target_ports)
    print(f"[+] Open ports on {target_host}: {open_ports}")
