#!/usr/bin/env python3
"""
Simple Port Scanner
Waypoint Compliance Advisory - waypointca.com

A basic port scanner in under 50 lines of core logic.
The goal isn't to replace nmap—it's to understand what's happening.

Prerequisites:
    None - uses Python standard library only

Usage:
    python port_scanner.py <host> [start_port] [end_port]
    
    Examples:
    python port_scanner.py scanme.nmap.org
    python port_scanner.py 192.168.1.1 1 1024
    python port_scanner.py localhost 80 443

Educational Purpose:
    When you understand how a scan works, you understand:
    - Why certain scans are noisy (full TCP handshake)
    - Why others are stealthy (SYN scan, requires raw sockets)
    - What your firewall logs actually mean

GitHub: https://github.com/WaypointCA/friday-projects
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

# Common ports to scan if no range specified
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]


def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """
    Scan a single port on a host.
    
    Args:
        host: Target hostname or IP
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Tuple of (port, is_open, service_hint)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try to get service name
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                return (port, True, service)
            return (port, False, "")
    except socket.gaierror:
        return (port, False, "dns_error")
    except socket.timeout:
        return (port, False, "timeout")
    except Exception as e:
        return (port, False, str(e))


def scan_ports(host: str, ports: List[int], threads: int = 50, timeout: float = 1.0) -> List[Tuple[int, str]]:
    """
    Scan multiple ports using threading.
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        threads: Number of concurrent threads
        timeout: Connection timeout per port
        
    Returns:
        List of (port, service) tuples for open ports
    """
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
    
    return sorted(open_ports, key=lambda x: x[0])


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def main():
    """Main entry point."""
    print("\n" + "=" * 50)
    print("SIMPLE PORT SCANNER")
    print("Educational use only - scan responsibly")
    print("=" * 50)
    
    # Parse arguments
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <host> [start_port] [end_port]")
        print(f"       {sys.argv[0]} <host> --common")
        print("\nExamples:")
        print("  python port_scanner.py scanme.nmap.org")
        print("  python port_scanner.py 192.168.1.1 1 1024")
        print("  python port_scanner.py localhost --common")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Determine port range
    if len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2] == '--common'):
        ports = COMMON_PORTS
        port_desc = f"{len(COMMON_PORTS)} common ports"
    elif len(sys.argv) >= 4:
        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
            ports = list(range(start_port, end_port + 1))
            port_desc = f"ports {start_port}-{end_port}"
        except ValueError:
            print("Error: Ports must be integers")
            sys.exit(1)
    else:
        try:
            single_port = int(sys.argv[2])
            ports = [single_port]
            port_desc = f"port {single_port}"
        except ValueError:
            ports = COMMON_PORTS
            port_desc = f"{len(COMMON_PORTS)} common ports"
    
    # Resolve host
    ip = resolve_host(host)
    if not ip:
        print(f"\nError: Could not resolve host '{host}'")
        sys.exit(1)
    
    print(f"\nTarget: {host} ({ip})")
    print(f"Scanning: {port_desc}")
    print(f"Threads: 50")
    print("-" * 50)
    
    # Scan
    import time
    start_time = time.time()
    
    open_ports = scan_ports(host, ports)
    
    elapsed = time.time() - start_time
    
    # Results
    if open_ports:
        print(f"\n{'PORT':<10} {'STATE':<10} {'SERVICE'}")
        print("-" * 35)
        for port, service in open_ports:
            print(f"{port:<10} {'open':<10} {service}")
    else:
        print("\nNo open ports found.")
    
    print("-" * 50)
    print(f"Scanned {len(ports)} ports in {elapsed:.2f} seconds")
    print(f"Open ports: {len(open_ports)}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
