
# Traffic Analysis Tool

## Overview

This Traffic Analysis Tool is designed to enhance network security and efficiency by providing real-time monitoring, data visualization, anomaly detection, packet capture and storage, and an interactive dashboard for comprehensive analysis.

## Features

- **Real-Time Network Traffic Monitoring**: Visualize packet data dynamically to monitor network activity and quickly identify potential issues.
- **Comprehensive Data Visualization**:
  - **IP Distribution Graph**: Understand the distribution of source and destination IP addresses.
  - **Protocol Distribution Graph**: Analyze the breakdown of network protocols in use.
  - **Network Pathway Graph**: Map communication routes between network nodes for better network management.
- **Anomaly Detection**: Utilize Isolation Forest algorithms to spot and highlight irregular network activities, ensuring proactive threat management.
- **Packet Capture and Storage**: Efficiently capture and store packet data for detailed analysis and future reference.
- **Interactive Dashboard**: Navigate through a user-friendly interface with multiple analytical tabs for a comprehensive overview of network performance.
- **Graceful Shutdown and Resource Management**: Ensure smooth operation and optimal resource usage with built-in management features.

## Prerequisites

- Python 3.x
- Required Python packages:
  - scapy
  - psutil
  - colorama
  - requests
  - scikit-learn
  - matplotlib
  - rich

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/traffic-analysis-tool.git
   cd traffic-analysis-tool
   ```

2. **Install the required packages**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your IPStack API key**:
   - Sign up on [IPStack](https://ipstack.com/) and obtain your API key.
   - Replace `'your_ipstack_api_key_here'` with your actual API key in the script.

## Usage

1. **Run the script**:
   ```bash
   sudo python traffic_analysis_tool.py
   ```

2. **Select the network interface**:
   - The script will display available network interfaces. Enter the name of the interface you wish to monitor.

3. **Capture packets**:
   - Enter the number of packets you want to capture.

4. **Save captured packets**:
   - You will be prompted to save the captured packets to a file.

5. **Visualize data**:
   - After capturing packets, you can choose from various visualization options provided in the menu.

## Example

Here is a brief example of running the tool:

```bash
$ sudo python traffic_analysis_tool.py
Available network interfaces:
eth0
wlan0
Enter the name of the network interface you want to capture traffic on: wlan0
Enter the number of packets to capture: 100
Analyzing traffic on wlan0...
...
Do you want to save the captured packets? (yes/no): yes
Enter the output file name for the captured packets (without extension): capture
Captured packets saved to capture.pcap

Visualization Options:
1. IP Distribution
2. Protocol Distribution
3. Packet Length Distribution
4. Anomalies
5. Exit
Enter your choice: 1
```

## Contact

For questions or suggestions, please reach out to us at [itsmemadhan22@gmail.com] or create an issue in this repository.
