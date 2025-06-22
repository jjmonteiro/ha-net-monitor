"""DataUpdateCoordinator for the Network Monitor integration."""
import logging
import asyncio
from datetime import timedelta
from ipaddress import ip_network, ip_address
import time
from typing import Dict, Any, Optional, Set, Callable
from scapy.layers.l2 import ARP, Ether, srp
from aioping import ping
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.core import Event, HomeAssistant
from .const import (
    DEFAULT_SCAN_INTERVAL, DEFAULT_NUM_CONCURRENT_TASKS, DEFAULT_PING_TIMEOUT,
    DEFAULT_ARP_TIMEOUT, DEFAULT_BATCH_SIZE, CONSIDER_ONLINE
)

_LOGGER = logging.getLogger(__name__)

def _parse_ip_range(ip_range_str: str) -> list[ip_address]:
    """Parse the IP range string into a list of IP addresses."""
    try:
        # Handle CIDR notation
        if "/" in ip_range_str:
            return list(ip_network(ip_range_str, strict=False).hosts())
        
        # Handle range notation (e.g., 192.168.1.1-254 or 192.168.1.1-192.168.1.254)
        if "-" in ip_range_str:
            parts = ip_range_str.split('-')
            start_ip_str = parts[0]
            end_ip_str = parts[1]

            # If end_ip is just a number, assume it's the last octet of the start_ip
            if '.' not in end_ip_str:
                end_ip_str = '.'.join(start_ip_str.split('.')[:-1] + [end_ip_str])

            start_ip = ip_address(start_ip_str)
            end_ip = ip_address(end_ip_str)

            if start_ip.version != end_ip.version:
                raise ValueError("Start and end IP addresses must be of the same version.")

            hosts = []
            current_ip = start_ip
            while current_ip <= end_ip:
                hosts.append(current_ip)
                current_ip += 1
            return hosts

        # Handle single IP address
        return [ip_address(ip_range_str)]
        
    except ValueError as e:
        _LOGGER.error("Invalid IP range format: %s. Error: %s", ip_range_str, e)
        return []

async def async_ping_host(ip_str: str, semaphore: asyncio.Semaphore, ping_timeout: float) -> Optional[str]:
    """Ping a single IP using ICMP.
    
    Args:
        ip_str: The IP address to ping
        semaphore: Semaphore to limit concurrent pings
        ping_timeout: Timeout in seconds for the ping operation
    
    Returns:
        The IP address if ping was successful, None otherwise
    """
    async with semaphore:
        try:
            ping_obj = ping(ip_str, timeout=ping_timeout)
            if await ping_obj is not None:
                return ip_str
            else:
                return None
        except Exception:
            return None

async def async_icmp_scan_subnet(subnet: str, semaphore: asyncio.Semaphore, ping_timeout: float) -> list[str]:
    """Perform an ICMP scan over a subnet or IP range.
    
    Args:
        subnet: The subnet or IP range to scan
        semaphore: Semaphore to limit concurrent pings
        ping_timeout: Timeout in seconds for each ping
    
    Returns:
        List of IP addresses that responded to ping
    """
    ip_list = _parse_ip_range(subnet)
    tasks = [async_ping_host(str(ip), semaphore, ping_timeout) for ip in ip_list]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip]

async def async_arp_scan_subnet(ip_list: list[str], arp_timeout: float) -> dict:
    """Perform an ARP scan over a list of IP addresses asynchronously.
    
    Args:
        ip_list: List of IP addresses to scan
        arp_timeout: Timeout in seconds for the ARP scan
    
    Returns:
        Dict mapping MAC addresses to the last IP address that responded
    """
    def run_srp() -> dict:
        arp = ARP(pdst=ip_list)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=arp_timeout, verbose=0)[0]
        return {received.hwsrc: received.psrc for sent, received in result}

    return await asyncio.to_thread(run_srp)

def format_scan_time(seconds: float) -> str:
    """Format scan time in MM:SS format.
    
    Args:
        seconds: Time in seconds
    
    Returns:
        Formatted time string in MM:SS format
    """
    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)
    return f"{minutes:02d}:{remaining_seconds:02d}"

class NetworkMonitorCoordinator(DataUpdateCoordinator):
    """Data update coordinator for the Network Monitor integration."""

    def __init__(self, hass: HomeAssistant, config: Dict[str, Any]):
        """Initialize the coordinator.
        
        Args:
            hass: Home Assistant instance
            config: Configuration dictionary containing ip_range and scan_interval
        """
        self.ip_range = config["ip_range"]
        self.wait_time = timedelta(seconds=config.get("scan_interval", DEFAULT_SCAN_INTERVAL))
        self._scan_task: Optional[asyncio.Task] = None
        self._semaphore = asyncio.Semaphore(DEFAULT_NUM_CONCURRENT_TASKS)
        self._startup_listener: Optional[Callable[[Event], None]] = None
        self._startup_listener_remover: Optional[Callable[[], None]] = None
        self._startup_listener_executed = False
        self._device_failures: Dict[str, int] = {}  # Track consecutive failures for each device
        
        _LOGGER.debug("Initializing coordinator with IP range: %s, scan interval: %s",
                     self.ip_range, self.wait_time)
        
        super().__init__(
            hass,
            _LOGGER,
            name="Network Monitor",
        )

    def _update_device_status(self, responding_devices: Set[str]) -> None:
        """Update device status based on responses and CONSIDER_ONLINE threshold.
        
        Args:
            responding_devices: Set of devices that responded in the current scan
        """
        # Update failures for all known devices
        for device in self._device_failures:
            if device not in responding_devices:
                self._device_failures[device] += 1
            else:
                self._device_failures[device] = 0
        
        # Add new devices that responded
        for device in responding_devices:
            if device not in self._device_failures:
                self._device_failures[device] = 0
        
        # Remove devices that have exceeded the failure threshold
        offline_devices = {
            device for device, failures in self._device_failures.items()
            if failures > CONSIDER_ONLINE
        }
        for device in offline_devices:
            del self._device_failures[device]
        
        _LOGGER.debug("Device status update - Online: %d, Offline: %d",
                     len(self._device_failures), len(offline_devices))

    async def _scan_loop(self) -> None:
        """Main background loop for network scanning.
        
        Continuously scans the network at the configured interval until cancelled.
        """
        _LOGGER.debug("Starting permanent scan loop for IP range: %s, scan interval: %s",
                     self.ip_range, self.wait_time)
        
        try:
            while True:
                await self.async_refresh()
                _LOGGER.debug("Scan finished, waiting %s before next scan", self.wait_time)
                await asyncio.sleep(self.wait_time.total_seconds())
        except asyncio.CancelledError:
            _LOGGER.debug("Scan loop cancelled.")
        finally:
            _LOGGER.debug("Scan loop finished.")

    async def async_start(self, event: Optional[Event] = None) -> None:
        """Start the background scanning loop.
        
        Args:
            event: Optional event that triggered the start
        """
        if event is not None:
            self._startup_listener_executed = True
            _LOGGER.debug("Startup listener executed")
            
        _LOGGER.debug("Starting coordinator with IP range: %s, scan interval: %s",
                     self.ip_range, self.wait_time)
        if self._scan_task is None:
            self._scan_task = self.hass.async_create_task(self._scan_loop())
        else:
            _LOGGER.warning("Scan task already exists, not starting a new one")

    async def async_shutdown(self) -> None:
        """Stop the background scanning loop and cleanup resources."""
        _LOGGER.debug("Shutting down coordinator")
        
        # Remove startup listener if it exists and hasn't been executed
        if self._startup_listener_remover is not None and not self._startup_listener_executed:
            try:
                self._startup_listener_remover()
                _LOGGER.debug("Removed startup listener")
            except Exception as e:
                _LOGGER.debug("Error removing startup listener: %s", e)
        elif self._startup_listener_executed:
            _LOGGER.debug("Startup listener already executed, no need to remove")
            
        self._startup_listener_remover = None
        self._startup_listener = None
        self._startup_listener_executed = False

        # Cancel scan task if it exists
        if self._scan_task is not None:
            _LOGGER.debug("Cancelling background scan task")
            self._scan_task.cancel()
            try:
                await self._scan_task
                _LOGGER.debug("Scan task cancelled successfully")
            except asyncio.CancelledError:
                _LOGGER.debug("Scan task was cancelled")
            self._scan_task = None
        else:
            _LOGGER.debug("No scan task to cancel")

    def set_startup_listener(self: 'NetworkMonitorCoordinator', listener: Callable[[Event], None], remover: Callable[[], None]) -> None:
        """Set the startup listener for cleanup.
        
        Args:
            listener: The listener function to store for cleanup
            remover: The function to call to remove the listener
        """
        self._startup_listener = listener
        self._startup_listener_remover = remover
        self._startup_listener_executed = False
        _LOGGER.debug("Startup listener set with remover")

    async def _async_update_data(self) -> Dict[str, Any]:
        """Fetch data from the network."""
        _LOGGER.debug("Starting network scan for IP range: %s", self.ip_range)
        start_time = time.time()
        try:
            hosts = await self.hass.async_add_executor_job(
                _parse_ip_range, self.ip_range
            )
            if not hosts:
                _LOGGER.warning("No hosts to scan. Please check your IP range configuration.")
                return {"icmp_replies": 0, "arp_replies": 0, "last_scan": "", "time_scan": ""}

            icmp_replies = set()
            total_batches = (len(hosts) + DEFAULT_BATCH_SIZE - 1) // DEFAULT_BATCH_SIZE
            for i in range(0, len(hosts), DEFAULT_BATCH_SIZE):
                batch = hosts[i:i+DEFAULT_BATCH_SIZE]
                icmp_batch_num = (i // DEFAULT_BATCH_SIZE) + 1
                _LOGGER.debug("ICMP scanning batch %d/%d: hosts %d-%d", icmp_batch_num, total_batches, i+1, min(i+DEFAULT_BATCH_SIZE, len(hosts)))
                ping_tasks = []
                for host in batch:
                    ping_tasks.append(async_ping_host(str(host), self._semaphore, DEFAULT_PING_TIMEOUT))
                results = await asyncio.gather(*ping_tasks, return_exceptions=True)
                for host, result in zip(batch, results):
                    if isinstance(result, Exception):
                        _LOGGER.debug("Ping failed for %s: %s", host, result)
                    elif result:
                        icmp_replies.add(str(host))
                # Yield control to the event loop
                await asyncio.sleep(0)
            _LOGGER.debug("ICMP scan complete: %d replies", len(icmp_replies))

            # Perform ARP scan in batches for large networks
            arp_replies = {}
            total_arp_batches = (len(hosts) + DEFAULT_BATCH_SIZE - 1) // DEFAULT_BATCH_SIZE
            for j in range(0, len(hosts), DEFAULT_BATCH_SIZE):
                arp_batch = hosts[j:j+DEFAULT_BATCH_SIZE]
                arp_batch_str = [str(ip) for ip in arp_batch]
                arp_batch_num = (j // DEFAULT_BATCH_SIZE) + 1
                _LOGGER.debug("ARP scanning batch %d/%d: hosts %d-%d", arp_batch_num, total_arp_batches, j+1, min(j+DEFAULT_BATCH_SIZE, len(hosts)))
                batch_replies = await async_arp_scan_subnet(arp_batch_str, DEFAULT_ARP_TIMEOUT)
                arp_replies.update(batch_replies)
                await asyncio.sleep(0)
            _LOGGER.debug("ARP scan complete: %d replies", len(arp_replies))

            # Combine ICMP and ARP replies
            responding_devices = icmp_replies | set(arp_replies.values())
            
            # Update device status based on responses
            self._update_device_status(responding_devices)

            end_time = time.time()
            scan_duration = round(end_time - start_time, 2)
            self._last_icmp_set = icmp_replies
            self._last_arp_set = set(arp_replies.values())
            total_online = set(self._device_failures.keys())  # Only count devices that haven't exceeded failure threshold
            _LOGGER.info("Scan complete for %s in %s seconds. Found %d online devices.",
                         self.ip_range, scan_duration, len(total_online))
            return {
                "icmp_replies": len(icmp_replies),
                "arp_replies": len(arp_replies),
                "last_scan": time.ctime(),
                "time_scan": format_scan_time(scan_duration),
            }
        except Exception as e:
            _LOGGER.error("Scan failed: %s", e, exc_info=True)
            return {"icmp_replies": 0, "arp_replies": 0, "last_scan": "", "time_scan": ""}
        finally:
            end_time = time.time()
            duration = round(end_time - start_time, 3)
            _LOGGER.debug("Exiting _async_update_data for %s after %s seconds", self.ip_range, duration)