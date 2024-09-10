[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/custom-components/hacs) 
![GitHub release](https://img.shields.io/github/release/jjmonteiro/ha-net-monitor.svg)
# Network Monitor Sensor

The **Network Monitor** integration for Home Assistant allows you to monitor the number of devices connected to your local network. This custom sensor leverages the power of network scanning tools to provide real-time data on the number of active devices within a specified IP range.

<p align="center">
<img src="https://github.com/user-attachments/assets/6333d361-97f3-4d7b-b032-985a9ac3d645" width=80%>
</p>

## Features
- **Custom IP Range**: Specify the IP range to scan, allowing for tailored monitoring of different network segments.
- **Real-Time Monitoring**: Regularly updates the count of devices on your network, helping you keep track of connected devices.
- **Multiple Protocol**: ICMP and ARP scanner for maximum detection accuracy.

## Configuration
To configure the `Network Monitor` sensor, add the following to your `configuration.yaml`:

```yaml
sensor:
  - platform: net_monitor
    name: My Network Monitor  # Customize the sensor name
    ip_range: 192.168.1.1/24  # Replace with your network's IP range
    scan_interval:            # Optional: Set the interval between scans
      minutes: 5  
      seconds: 0
```

## Use Cases
- **Network Security**: Keep an eye on how many devices are connected to your network and detect unauthorized access.
- **Home Automation**: Trigger automations based on the number of devices connected to your network.
- **Network Management**: Monitor network congestion and usage patterns by tracking device counts over time.

## Installation
This integration can be easily installed via [HACS](https://hacs.xyz/) by adding the repository to your custom repositories list.
