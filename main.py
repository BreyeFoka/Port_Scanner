import socket
import sys
import threading
from queue import Queue
import argparse
import time
from datetime import datetime
import ipaddress

def get_service_name(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except (socket.error, OSError):
        return "unknown"

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def scan_port(target, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                open_ports.append((port, service))
    except socket.error:
        pass

def port_scanner(target, start_port, end_port, num_threads=100):
    if not validate_ip(target):
        print(f"Error: Invalid IP address: {target}")
        sys.exit(1)

    open_ports = []
    queue = Queue()
    threads = []

    # Put all ports into the queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(target, port, open_ports)
            queue.task_done()
            # Update progress
            remaining = queue.qsize()
            total = end_port - start_port + 1
            progress = ((total - remaining) / total) * 100
            print(f"\rProgress: {progress:.1f}% - Ports remaining: {remaining}", end="")

    print(f"\nStarting scan on {target}")
    print(f"Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Start threads
    for _ in range(min(num_threads, end_port - start_port + 1)):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all ports to be scanned
    queue.join()

    print("\n\nScan completed!")
    print("\nOpen ports:")
    if open_ports:
        # Sort ports for consistent output
        open_ports.sort()
        for port, service in open_ports:
            print(f"[OPEN] Port {port:<6} - Service: {service}")
    else:
        print("No open ports found.")

def main():
    parser = argparse.ArgumentParser(description='Simple Port Scanner')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-s', '--start', type=int, default=1, help='Start port (default: 1)')
    parser.add_argument('-e', '--end', type=int, default=1024, help='End port (default: 1024)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')

    args = parser.parse_args()

    try:
        port_scanner(args.target, args.start, args.end, args.threads)
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
