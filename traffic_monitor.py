import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP
import threading

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Initialize variables to track packet count and blocked IPs
packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()

# Callback function to handle incoming packets
def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        # Check the packet rate for each IP address
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        # Reset packet count and time after each interval
        packet_count.clear()
        start_time[0] = current_time

# Function to run packet sniffing in a separate thread
def start_traffic_monitoring():
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)

# Create a background thread for traffic monitoring
def run_traffic_monitor():
    monitor_thread = threading.Thread(target=start_traffic_monitoring)
    monitor_thread.daemon = True  # This ensures the thread will close when the program exits
    monitor_thread.start()

if __name__ == "__main__":
    run_traffic_monitor()
    # Main program logic can be added here
    # You can add any additional tasks or a way to keep the script running
    while True:
        time.sleep(1)  # Keeps the main thread alive
