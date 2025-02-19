import socket
import subprocess
import scapy
import re
import uuid
import requests
import json
import time
import threading

from scapy.layers.l2 import ARP, Ether
from scapy.all import srp


def get_local_ip():
    "Retrieve the local IP address of your machine."
    local_ip = socket.gethostbyname(socket.gethostname())
    return local_ip


def get_network_range(local_ip):
    "Convert the local IP into a subnet range to scan."
    ip_parts = local_ip.split(".")
    network_range = ".".join(ip_parts[:3])
    return f"{network_range}.0/24"


def scan_network(network):
    # Create an Ethernet frame and an ARP request
    arp_request = ARP(pdst=network)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame/arp_request

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=False)[0]

    # List to store connected devices
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices




def resolve_mac_address(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    else:
        return None


def get_vendor_info(mac_address):
    "Get vendor information for a MAC address."
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Manufacturer"
    except requests.RequestException:
        return "Error retrieving vendor information"


def display_results(devices):
    if not devices:
        print("No active devices found on the network.")
        return
    print("IP Address\t\tMAC Address\t\tManufacturer")
    print("-" * 60)
    for device in devices:
        ip = device["ip"]
        mac = device["mac"]
        manufacturer = device.get("vendor", "Unknown Manufacturer")
        print(f"{ip}\t\t{mac}\t\t{manufacturer}")


def scan_and_display():
    local_ip = get_local_ip()
    network_range = get_network_range(local_ip)
    print(f"Scanning network range: {network_range}")

    devices = scan_network(network_range)

    # Get the vendor info in parallel for all devices
    for device in devices:
        mac = device["mac"]
        vendor = get_vendor_info(mac)
        device["vendor"] = vendor

    display_results(devices)


# Run network scanning in a separate thread
def run_network_scan():
    scan_thread = threading.Thread(target=scan_and_display)
    scan_thread.daemon = True
    scan_thread.start()


if __name__ == "__main__":
    run_network_scan()
    # Keeping the script alive
    while True:
        time.sleep(10)
