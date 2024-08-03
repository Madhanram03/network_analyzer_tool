import requests
from scapy.all import sniff, IP, wrpcap
import psutil
from colorama import init, Fore
from sklearn.ensemble import IsolationForest
import numpy as np
import matplotlib.pyplot as plt
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from collections import Counter

# Initialize colorama
init(autoreset=True)

# IPStack API Key (replace with your own key)
IPSTACK_API_KEY = 'your_ipstack_api_key_here'

# Global variables
packets = []
anomalies = []
frame_number = 0
src_ip_counts = Counter()
dst_ip_counts = Counter()
protocol_counts = Counter()
packet_lengths = []

console = Console()

# Function to get geolocation data
def get_geolocation(ip):
    try:
        response = requests.get(f"http://api.ipstack.com/{ip}?access_key={IPSTACK_API_KEY}")
        data = response.json()
        return data.get("latitude"), data.get("longitude")
    except Exception as e:
        console.print(f"Error getting geolocation data: {e}", style="bold red")
        return None, None

# Function to analyze packets
def analyze_packet(packet):
    global frame_number, src_ip_counts, dst_ip_counts, protocol_counts, packet_lengths
    if IP in packet:
        frame_number += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = packet[IP].len

        src_ip_counts[src_ip] += 1
        dst_ip_counts[dst_ip] += 1
        protocol_counts[proto] += 1
        packet_lengths.append(size)

        packets.append(packet)
        
        console.print(f"{Fore.CYAN}Source IP: {src_ip} --> Destination IP: {dst_ip}")
        console.print(f"{Fore.YELLOW}Protocol: {proto}   Size: {size} bytes")
        console.print(f"{Fore.GREEN}Frame Number: {frame_number}   Frame Length: {size} bytes")
        console.print("-" * 50)

# Function to perform anomaly detection
def detect_anomalies():
    global packet_lengths, anomalies
    if len(packet_lengths) < 2:
        return
    
    clf = IsolationForest(contamination=0.05)
    clf.fit(np.array(packet_lengths).reshape(-1, 1))
    predictions = clf.predict(np.array(packet_lengths).reshape(-1, 1))
    
    for i, pred in enumerate(predictions):
        if pred == -1:
            anomalies.append(packets[i])

# Function to select network interface
def select_network_interface():
    interfaces = psutil.net_if_addrs()
    console.print(f"{Fore.MAGENTA}Available network interfaces:")
    for interface_name, _ in interfaces.items():
        console.print(interface_name)
    while True:
        selected_interface = input(f"{Fore.YELLOW}Enter the name of the network interface you want to capture traffic on: ")
        if selected_interface in interfaces:
            return selected_interface
        console.print(f"{Fore.RED}Invalid interface name. Please try again.\n")

# Function to load packets from a file
def load_packets(file_name):
    global packets, src_ip_counts, dst_ip_counts, protocol_counts, packet_lengths, anomalies, frame_number
    packets = rdpcap(file_name)
    src_ip_counts = Counter()
    dst_ip_counts = Counter()
    protocol_counts = Counter()
    packet_lengths = []
    anomalies = []
    frame_number = 0
    for packet in packets:
        analyze_packet(packet)
    detect_anomalies()

# Function to visualize IP distribution
def visualize_ip_distribution():
    src_ips = list(src_ip_counts.keys())
    src_counts = list(src_ip_counts.values())
    dst_ips = list(dst_ip_counts.keys())
    dst_counts = list(dst_ip_counts.values())

    fig, ax = plt.subplots(2, 1, figsize=(10, 8))

    ax[0].bar(src_ips, src_counts, color='blue')
    ax[0].set_title('Source IP Distribution')
    ax[0].set_xlabel('IP Addresses')
    ax[0].set_ylabel('Count')
    ax[0].tick_params(axis='x', rotation=90)

    ax[1].bar(dst_ips, dst_counts, color='green')
    ax[1].set_title('Destination IP Distribution')
    ax[1].set_xlabel('IP Addresses')
    ax[1].set_ylabel('Count')
    ax[1].tick_params(axis='x', rotation=90)

    plt.tight_layout()
    plt.show()

# Function to visualize protocol distribution
def visualize_protocol_distribution():
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140)
    plt.title('Protocol Distribution')
    plt.show()

# Function to visualize anomalies
def visualize_anomalies():
    if not anomalies:
        console.print("No anomalies detected.", style="bold green")
        return

    anomaly_table = Table(title="Anomalies Detected")

    anomaly_table.add_column("Source IP", justify="center", style="cyan")
    anomaly_table.add_column("Destination IP", justify="center", style="cyan")
    anomaly_table.add_column("Protocol", justify="center", style="cyan")
    anomaly_table.add_column("Size (bytes)", justify="center", style="cyan")

    for packet in anomalies:
        if IP in packet:
            anomaly_table.add_row(
                packet[IP].src,
                packet[IP].dst,
                str(packet[IP].proto),
                str(packet[IP].len)
            )

    console.print(anomaly_table)

# Function to visualize packet lengths
def visualize_packet_lengths():
    plt.figure(figsize=(10, 6))
    plt.hist(packet_lengths, bins=50, color='purple', alpha=0.75)
    plt.title('Packet Length Distribution')
    plt.xlabel('Packet Length (bytes)')
    plt.ylabel('Frequency')
    plt.show()

# Main function
if __name__ == "__main__":
    selected_interface = select_network_interface()

    while True:
        try:
            packet_count = int(input(f"{Fore.YELLOW}Enter the number of packets to capture: "))
            break
        except ValueError:
            console.print(f"{Fore.RED}Invalid input. Please enter a valid number.\n")

    console.print(f"{Fore.BLUE}Analyzing traffic on {selected_interface}...")
    sniff(iface=selected_interface, prn=analyze_packet, count=packet_count)
    detect_anomalies()

    # Save captured packets
    save_packets = input(f"\n{Fore.YELLOW}Do you want to save the captured packets? (yes/no): ").lower()
    if save_packets == 'yes':
        output_file = input(f"{Fore.YELLOW}Enter the output file name for the captured packets (without extension): ")
        output_file += ".pcap"
        wrpcap(output_file, packets)
        console.print(f"\n{Fore.CYAN}Captured packets saved to {output_file}")

    # Visualization options
    while True:
        console.print("\nVisualization Options:", style="bold blue")
        console.print("1. IP Distribution")
        console.print("2. Protocol Distribution")
        console.print("3. Packet Length Distribution")
        console.print("4. Anomalies")
        console.print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            visualize_ip_distribution()
        elif choice == '2':
            visualize_protocol_distribution()
        elif choice == '3':
            visualize_packet_lengths()
        elif choice == '4':
            visualize_anomalies()
        elif choice == '5':
            break
        else:
            console.print("Invalid choice. Please try again.", style="bold red")
