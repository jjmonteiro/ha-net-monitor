import logging
import asyncio
import threading
from typing import Optional, Dict
from datetime import timedelta, datetime
from homeassistant.components.sensor import SensorEntity
from homeassistant.const import CONF_SCAN_INTERVAL
from scapy.all import ARP, Ether, srp
import subprocess

_LOGGER = logging.getLogger(__name__)

DEVICE_OFFLINE_THRESHOLD = 3  # Number of missed replies before considering a device offline

def scan_network(ip_range: str) -> Dict[str, str]:
    """Scan the local network for devices and return a dictionary of IP and MAC addresses."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = {received.psrc: received.hwsrc for sent, received in result}

    return devices

def ping_device(ip: str) -> bool:
    """Ping a device to check if it is online."""
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return "1 packets transmitted, 1 received" in output
    except subprocess.CalledProcessError:
        return False

def run_scan_network(ip_range: str, result: Dict[str, str]):
    """Run network scan in a separate thread."""
    devices = scan_network(ip_range)
    result.update(devices)

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the sensor platform."""
    name = config.get("name")
    ip_range = config.get("ip_range")

    # Read scan_interval from config
    scan_interval_config = config.get("scan_interval", {})
    
    # Ensure scan_interval_config is a dictionary
    if not isinstance(scan_interval_config, dict):
        scan_interval_config = {}

    minutes = scan_interval_config.get("minutes", 10)
    seconds = scan_interval_config.get("seconds", 0)
    scan_interval = timedelta(minutes=minutes, seconds=seconds)

    async_add_entities([NetworkMonitorSensor(name, ip_range, scan_interval)], True)

class NetworkMonitorSensor(SensorEntity):
    """Representation of a Network Monitor Sensor."""

    _attr_state_class = "measurement"
    _attr_native_step = 1
    _attr_suggested_display_precision = 0
    _attr_native_value = 0
    _attr_unit_of_measurement = "online"

    def __init__(self, name: str, ip_range: str, scan_interval: timedelta) -> None:
        """Initialize the sensor."""
        self._name = name
        self._ip_range = ip_range
        self._scan_interval = scan_interval
        self._state: Optional[int] = None
        self._last_scanned: Optional[datetime] = None
        self._detected_devices: Dict[str, str] = {}
        self._device_status: Dict[str, int] = {}  # Track missed replies
        self._attr_native_value = 0  # Initial value

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return self._name

    @property
    def state(self) -> Optional[int]:
        """Return the state of the sensor as an integer."""
        return self._state

    @property
    def state_class(self) -> str:
        """Return the state class of the sensor."""
        return self._attr_state_class

    @property
    def unit_of_measurement(self) -> str:
        """Return the unit of measurement of the sensor."""
        return self._attr_unit_of_measurement

    @property
    def icon(self) -> str:
        """Return the icon of the sensor."""
        return "mdi:network"

    @property
    def unique_id(self) -> str:
        """Return a unique ID for the sensor."""
        return f"net_monitor_{self._name}_{self._ip_range.replace('/', '_')}"

    @property
    def available(self) -> bool:
        """Return True if the sensor is available."""
        return self._state is not None

    @property
    def extra_state_attributes(self) -> dict:
        """Return the state attributes."""
        return {
            "last_scanned": self._last_scanned,
            "detected_devices": self._detected_devices,
            "device_status": self._device_status,
        }

    async def async_update(self) -> None:
        """Fetch new state data for the sensor."""
        if self._last_scanned and datetime.now() - self._last_scanned < self._scan_interval:
            return  # Skip update if the interval hasn't passed yet

        loop = asyncio.get_event_loop()
        result = {}

        # Run network scan in a separate thread
        await loop.run_in_executor(None, run_scan_network, self._ip_range, result)

        current_devices = result

        # Track devices that are currently detected
        self._detected_devices = current_devices

        # Update device status
        for ip, mac in current_devices.items():
            if ip in self._device_status:
                self._device_status[ip] = 0  # Reset missed replies count if the device is detected
            else:
                self._device_status[ip] = 0  # Device detected for the first time

        # Check for devices that have gone offline
        devices_to_remove = []
        for ip, missed_replies in self._device_status.items():
            if missed_replies >= DEVICE_OFFLINE_THRESHOLD:
                devices_to_remove.append(ip)
            else:
                # Check if device is still online by pinging
                if not ping_device(ip):
                    self._device_status[ip] += 1  # Increment missed replies if the device is not reachable

        # Remove devices that are considered offline
        for ip in devices_to_remove:
            self._device_status.pop(ip)

        self._state = len(self._device_status)
        self._last_scanned = datetime.now()
        self._attr_native_value = self._state
        _LOGGER.debug("Network Monitor Sensor '%s' updated to %d devices", self._name, self._state)
