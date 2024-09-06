import logging
import asyncio
import ipaddress
from pythonping import ping
from typing import Optional, Dict
from datetime import timedelta, datetime
from homeassistant.components.sensor import SensorEntity

from scapy.all import IP, ICMP, sr1
from scapy.layers.l2 import ARP, Ether, srp

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

def ping_device(ip: str, timeout: int = 2) -> bool:
    """Helper function to ping a single IP."""
    response = ping(str(ip), count=1, timeout)
    return response.success()

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the sensor platform."""
    name = config.get("name")
    ip_range = config.get("ip_range")

    # Read scan_interval from config
    scan_interval_config = config.get("scan_interval", {})
    
    # Ensure scan_interval_config is a dictionary
    if not isinstance(scan_interval_config, dict):
        scan_interval_config = {}

    minutes = scan_interval_config.get("minutes", 5)
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
        self._no_reply: Dict[str, int] = {}
        self._attr_native_value = 0

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
            "unresponsive": self._no_reply,
        }

    async def async_update(self) -> None:
        """Fetch new state data for the sensor."""
        if self._last_scanned and datetime.now() - self._last_scanned < self._scan_interval:
            _LOGGER.debug("async_update return")
            await self.ping_no_reply_devices()  # Try to ping no_reply devices before returning
            return  # Skip update if the interval hasn't passed yet

        loop = asyncio.get_event_loop()

        # Run network scan
        current_devices = await loop.run_in_executor(None, scan_network, self._ip_range)

        # Add new devices to detected devices
        self.add_new_devices(current_devices)

        # Handle devices that failed to respond in this scan
        self.handle_missing_devices(current_devices)

        # Attempt to ping devices in the no_reply list
        await self.ping_no_reply_devices()

        # Remove offline devices that exceeded the no reply threshold
        self.remove_offline_devices()

        # Update the last scanned time and the state count
        self._last_scanned = datetime.now()
        self._state = len(self._detected_devices)  # Count the devices still considered online
        self._attr_native_value = self._state

        _LOGGER.debug("Final detected devices list: %s", self._detected_devices)
        _LOGGER.debug("Final online devices count: %d", self._state)
        _LOGGER.debug("Unresponsive devices: %s", self._no_reply)

    def add_new_devices(self, current_devices: Dict[str, str]) -> None:
        """Add new devices to the detected devices list."""
        for ip, mac in current_devices.items():
            if ip not in self._detected_devices:
                _LOGGER.debug("New device found: %s", ip)
                self._detected_devices[ip] = mac  # Add to detected devices list

    def handle_missing_devices(self, current_devices: Dict[str, str]) -> None:
        """Handle devices that are missing from the current scan."""
        updated_no_reply = self._no_reply.copy()  # Work on a copy of the current no-reply list

        for ip in self._detected_devices.keys():
            if ip not in current_devices:
                _LOGGER.debug("Device %s failed to reply.", ip)
                updated_no_reply[ip] = updated_no_reply.get(ip, 0) + 1  # Increment no-reply counter
            else:
                # If the device responded, remove it from the no-reply list if it was there
                if ip in updated_no_reply and updated_no_reply[ip] == 0:
                    del updated_no_reply[ip]

        # Update no_reply with only devices with missed replies > 0
        self._no_reply = {ip: count for ip, count in updated_no_reply.items() if count > 0}

    async def ping_no_reply_devices(self) -> None:
        """Ping devices in the no_reply list to see if they respond."""
        for ip in list(self._no_reply.keys()):
            ping_reply = ping_device(ip)
            if ping_reply:
                _LOGGER.debug("Device %s responded to ping.", ip)
                del self._no_reply[ip]  # Remove from no_reply list if the device responded
            else:
                _LOGGER.debug("Device %s still unreachable after ping.", ip)

    def remove_offline_devices(self) -> None:
        """Remove devices from both lists that exceeded the offline threshold."""
        offline_devices = [ip for ip, count in self._no_reply.items() if count >= DEVICE_OFFLINE_THRESHOLD]

        for ip in offline_devices:
            _LOGGER.debug("Device %s removed after exceeding the offline threshold.", ip)
            if ip in self._detected_devices:
                del self._detected_devices[ip]  # Remove from detected devices
            del self._no_reply[ip]  # Remove from no_reply list
        