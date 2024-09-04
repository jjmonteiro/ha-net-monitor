import logging
from homeassistant.components.sensor import SensorEntity
from scapy.all import ARP, Ether, srp

_LOGGER = logging.getLogger(__name__)

def scan_network(ip_range):
    """Scan the local network for devices."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append(received.psrc)

    return len(devices)  # Ensure this is a numeric value

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the sensor platform."""
    name = config.get("name")
    ip_range = config.get("ip_range")
    async_add_entities([NetworkMonitorSensor(name, ip_range)], True)

class NetworkMonitorSensor(SensorEntity):
    """Representation of a Network Monitor Sensor."""

    def __init__(self, name, ip_range):
        """Initialize the sensor."""
        self._name = name
        self._ip_range = ip_range
        self._state = None

    @property
    def name(self):
        """Return the name of the sensor."""
        return self._name

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._state

    def update(self):
        """Fetch new state data for the sensor."""
        self._state = scan_network(self._ip_range)  # Ensure this is numeric
