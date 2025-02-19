from flask import Flask, render_template
from traffic_monitor import run_traffic_monitor, blocked_ips
from network_scanner import scan_network, get_local_ip, get_network_range
import subprocess
import platform
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp

app = Flask(__name__)

# Start the traffic monitoring in the background when the Flask app starts
run_traffic_monitor()

# Scan for connected devices
def get_connected_devices(network):
    # Create an ARP request to discover devices on the network
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the request and capture the response
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # List to store connected devices
    devices = []
    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device)

    return devices

# Blocked IPs (this could come from your traffic monitor or elsewhere)
blocked_ips = ["192.168.1.10", "192.168.1.20"]  # Example blocked IPs


def get_wifi_name():
    try:
        system_platform = platform.system()

        # For macOS
        if system_platform == "Darwin":
            # Get the current Wi-Fi interface
            interfaces = subprocess.check_output(['networksetup', '-listallhardwareports'], universal_newlines=True)
            wifi_interface = None
            for line in interfaces.splitlines():
                if "Wi-Fi" in line:
                    wifi_interface = line.split(":")[1].strip()
                    break

            if wifi_interface:
                result = subprocess.check_output(['networksetup', '-getairportnetwork', wifi_interface],
                                                 universal_newlines=True)
                if "Current Wi-Fi Network:" in result:
                    wifi_name = result.split(":")[1].strip()
                    return wifi_name
                else:
                    return "Not connected to Wi-Fi"

        # For Linux
        elif system_platform == "Linux":
            result = subprocess.check_output(['iwgetid'], universal_newlines=True)
            if result:
                return result.strip()  # The output should be the SSID of the connected Wi-Fi
            else:
                return "Not connected to Wi-Fi"

        else:
            return "Unsupported Operating System"

    except subprocess.CalledProcessError:
        return "Error retrieving Wi-Fi network"

@app.route('/')
def home():
    # Get local IP and determine the network range
    local_ip = get_local_ip()
    network = get_network_range(local_ip)

    # Get connected devices
    connected_devices = get_connected_devices(network)

    # Get the Wi-Fi name
    wifi_name = get_wifi_name()

    return render_template('index.html', wifi_name=wifi_name, connected_devices=connected_devices,
                           blocked_ips=blocked_ips)

if __name__ == "__main__":
    app.run(debug=True)
