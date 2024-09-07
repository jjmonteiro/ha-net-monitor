import logging
import ipaddress
from typing import Optional
from datetime import timedelta, datetime
from pythonping import ping
from scapy.layers.l2 import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
from homeassistant.components.sensor import SensorEntity
from functools import lru_cache

_LOGGER = logging.getLogger(__name__)


@lru_cache(maxsize=256)
def ping_host(ip):
    """Helper function to ping a single IP with caching."""
    response = ping(str(ip), count=1, timeout=1)
    return response.success()


def icmp_scan_network(ip_range: str) -> set:
    """Scan the network using ICMP requests in parallel."""
    network = ipaddress.ip_network(ip_range, strict=False)
    responsive_ips = set()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in network.hosts()}
        for future in as_completed(futures):
            if future.result():
                responsive_ips.add(str(futures[future]))

    _LOGGER.debug("ICMP scan result: %s", len(responsive_ips))
    return responsive_ips


def arp_scan_network(ip_range: str) -> set:
    """Scan the network using ARP requests."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    responsive_ips = {received.psrc for sent, received in result}

    _LOGGER.debug("ARP scan result: %s", len(responsive_ips))
    return responsive_ips


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the sensor platform."""
    name = config.get("name")
    ip_range = config.get("ip_range")
    scan_interval_config = config.get("scan_interval", {})

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
    _attr_unit_of_measurement = "online"

    def __init__(self, name: str, ip_range: str, scan_interval: timedelta) -> None:
        """Initialize the sensor."""
        self._name = name
        self._ip_range = ip_range
        self._scan_interval = scan_interval
        self._state: Optional[int] = None
        self._arp_replies: Optional[int] = None
        self._icmp_replies: Optional[int] = None
        self._last_scanned: Optional[datetime] = None

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return self._name

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
            "arp_replies": self._arp_replies,
            "icmp_replies": self._icmp_replies,
        }

    def update(self) -> None:
        """Fetch new state data for the sensor."""
        if self._last_scanned and datetime.now() - self._last_scanned < self._scan_interval:
            return

        _LOGGER.debug("Starting network scan at %s", datetime.now())

        arp_responsive_ips = arp_scan_network(self._ip_range)
        icmp_responsive_ips = icmp_scan_network(self._ip_range)

        total_responsive_devices = arp_responsive_ips.union(icmp_responsive_ips)

        self._last_scanned = datetime.now()
        self._arp_replies = len(arp_responsive_ips)
        self._icmp_replies = len(icmp_responsive_ips)
        self._state = len(total_responsive_devices)
        self._attr_native_value = self._state

        _LOGGER.debug("Total detected devices: %s", len(total_responsive_devices))
