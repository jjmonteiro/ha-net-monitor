import logging
import asyncio
from ipaddress import ip_network
from datetime import timedelta, datetime
from scapy.layers.l2 import ARP, Ether, srp
from aioping import ping
from typing import Optional
from homeassistant.components.sensor import SensorEntity

_LOGGER = logging.getLogger(__name__)

num_concurrent_tasks = 130
ping_timeout = 1
arp_timeout = 2
semaphore = asyncio.Semaphore(num_concurrent_tasks)


# Helper Functions
def parse_ip_range(ip_range_str):
    """Get a list of IP addresses from an IP range."""
    if '-' in ip_range_str:
        ip_start, ip_end = ip_range_str.split('-')
        ip_start_parts = ip_start.split('.')
        ip_base = '.'.join(ip_start_parts[:-1])  # Get the first 3 octets
        ip_start_last_octet = int(ip_start_parts[-1])
        ip_end_last_octet = int(ip_end)

        ip_list = [
            f"{ip_base}.{i}"
            for i in range(ip_start_last_octet, ip_end_last_octet + 1)
        ]
        return ip_list
    else:
        network = ip_network(ip_range_str, strict=False)
        return [str(ip) for ip in network.hosts()]


# ICMP Ping Functions
async def async_ping_host(ip_str):
    """Ping a single IP using ICMP."""
    async with semaphore:
        try:
            ping_obj = ping(ip_str, timeout=ping_timeout)
            if await ping_obj is not None:
                return ip_str
            else:
                return None
        except Exception:
            return None


async def async_icmp_scan_subnet(subnet: str) -> list:
    """Perform an ICMP scan over a subnet or IP range."""
    ip_list = parse_ip_range(subnet)
    tasks = [async_ping_host(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip]


async def async_icmp_scan_all_subnets(ip_ranges_str) -> list:
    """Perform an ICMP scan on all provided subnets or ranges."""
    all_responsive_ips = []
    ip_ranges_list = [ip_range.strip() for ip_range in ip_ranges_str.split(',')]

    for ip_range in ip_ranges_list:
        _LOGGER.debug(f"Starting ICMP scan on {ip_range}")
        responsive_ips = await async_icmp_scan_subnet(ip_range)
        all_responsive_ips.extend(responsive_ips)

    _LOGGER.debug(f"ICMP responsive hosts: {all_responsive_ips}")
    return all_responsive_ips


# ARP Functions
async def async_arp_scan_subnet(subnet: str) -> set:
    """Perform an ARP scan over a single subnet or IP range asynchronously."""
    ip_list = parse_ip_range(subnet)

    def run_srp():
        arp = ARP(pdst=ip_list)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=ping_timeout, verbose=0)[0]
        return {received.psrc for sent, received in result}

    return await asyncio.to_thread(run_srp)


async def async_arp_scan_all_subnets(ip_ranges_str) -> list:
    """Perform an ARP scan on all provided subnets or ranges asynchronously."""
    all_responsive_ips = []
    ip_ranges_list = [ip_range.strip() for ip_range in ip_ranges_str.split(',')]

    for ip_range in ip_ranges_list:
        _LOGGER.debug(f"Starting ARP scan on {ip_range}")
        responsive_ips = await async_arp_scan_subnet(ip_range)
        all_responsive_ips.extend(responsive_ips)

    _LOGGER.debug(f"ARP responsive hosts: {all_responsive_ips}")
    return all_responsive_ips


# HA Functions
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
        self._background_task = None
        self._setup_background_scan()

    def _setup_background_scan(self):
        """Set up the periodic background scan."""

        async def periodic_scan():
            while True:
                await asyncio.sleep(self._scan_interval.total_seconds())
                await self._perform_scan()

        self._background_task = asyncio.create_task(periodic_scan())

    async def _perform_scan(self):
        """Perform the network scan and update the state."""
        start_time = datetime.now()
        _LOGGER.debug(f"Starting network scan at {datetime.now()}")

        # Perform ICMP Scan
        icmp_responsive_ips = await async_icmp_scan_all_subnets(self._ip_range)
        _LOGGER.info(f"Total ICMP responsive hosts: {len(icmp_responsive_ips)}")
        self._icmp_replies = len(icmp_responsive_ips)

        # Perform ARP Scan
        arp_responsive_ips = await async_arp_scan_all_subnets(self._ip_range)
        _LOGGER.info(f"Total ARP responsive hosts: {len(arp_responsive_ips)}")
        self._arp_replies = len(arp_responsive_ips)

        # Combine both results
        all_responsive_ips = list(set(icmp_responsive_ips + arp_responsive_ips))
        self._state = len(all_responsive_ips)

        _LOGGER.debug(f"Total responsive hosts: {all_responsive_ips}")
        _LOGGER.info(f"Total detected devices: {len(all_responsive_ips)}")
        elapsed_time = datetime.now() - start_time
        _LOGGER.info(f"Time elapsed for full scan: {elapsed_time.total_seconds():.2f} seconds")

        # Update remaining results
        self._attr_native_value = self._state
        self._last_scanned = datetime.now()

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
        return f"net_monitor_{self._ip_range.replace('/', '_')}"

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

    async def async_update(self) -> None:
        """Fetch new state data for the sensor."""
        # Return the latest state without waiting for a scan to complete
        self._attr_native_value = self._state
        self._attr_extra_state_attributes = {
            "last_scanned": self._last_scanned,
            "arp_replies": self._arp_replies,
            "icmp_replies": self._icmp_replies,
        }
