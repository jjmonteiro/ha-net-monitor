# Network Monitor Integration

The **Network Monitor** integration for Home Assistant allows you to monitor the number of devices connected to your local network. This custom sensor leverages the power of network scanning tools to provide real-time data on the number of active devices within a specified IP range.

## Features
- **Custom IP Range**: Specify the IP range to scan, allowing for tailored monitoring of different network segments.
- **Configurable Sensor Name**: Easily name your sensor to fit within your Home Assistant environment.
- **Real-Time Monitoring**: Regularly updates the count of devices on your network, helping you keep track of connected devices.

## Configuration
To configure the `Network Monitor` sensor, add the following to your `configuration.yaml`:

```yaml
sensor:
  - platform: net_monitor
    name: My Network Monitor  # Customize the sensor name
    ip_range: 192.168.1.1/24  # Replace with your network's IP range

## Use Cases
- **Network Security**: Keep an eye on how many devices are connected to your network to detect any unauthorized access.
- **Home Automation**: Trigger automations based on the number of devices connected to your network.
- **Network Management**: Monitor network congestion and usage patterns by tracking device counts over time.

## Installation
This integration can be easily installed via [HACS](https://hacs.xyz/) by adding the repository to your custom repositories list.
