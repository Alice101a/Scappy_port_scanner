from scapy.all import sr1, IP, TCP
import argparse
import threading

# Function to perform the port scan for a range of ports
def scan_ports(target_ip, start_port, end_port, open_ports):
    for port in range(start_port, end_port + 1):
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            open_ports.append(port)

# Function to perform the threaded port scan
def threaded_scan(target_ip, num_threads, target_ports):
    open_ports = []
    threads = []

    # Calculate the number of ports to scan per thread
    ports_per_thread = len(target_ports) // num_threads
    remaining_ports = len(target_ports) % num_threads

    # Create and start the threads
    for i in range(num_threads):
        start_port = i * ports_per_thread
        end_port = start_port + ports_per_thread - 1
        if i == num_threads - 1:
            end_port += remaining_ports

        thread = threading.Thread(target=scan_ports, args=(target_ip, target_ports[start_port], target_ports[end_port], open_ports))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    return sorted(open_ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded port scanner")
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("-p", "--ports", type=str, default="1-1024", help="Ports to scan (e.g., 1-1024 or 80,443,8080)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use for scanning")

    args = parser.parse_args()

    # Parse the ports argument to get the range of ports to scan
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
        target_ports = list(range(start_port, end_port + 1))
    else:
        target_ports = list(map(int, args.ports.split(",")))

    # Perform the threaded port scan
    open_ports = threaded_scan(args.target_ip, args.threads, target_ports)

    print(f"Open ports on {args.target_ip}: {open_ports}")
 
