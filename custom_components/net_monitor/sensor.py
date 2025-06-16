"""Sensor platform for the Network Monitor integration."""
from typing import Any, Dict, Optional
import asyncio
from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN

async def async_setup_entry(hass: Any, entry: Any, async_add_entities: Any) -> None:
    """Set up the sensor platform.
    
    Args:
        hass: Home Assistant instance
        entry: Config entry for this integration
        async_add_entities: Callback to add entities
    """
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NetworkMonitorSensor(coordinator, entry)])

class NetworkMonitorSensor(CoordinatorEntity, SensorEntity):
    """Representation of a Network Monitor Sensor."""

    def __init__(self, coordinator: Any, entry: Any) -> None:
        """Initialize the sensor.
        
        Args:
            coordinator: The coordinator instance
            entry: Config entry for this integration
        """
        super().__init__(coordinator)
        self._attr_name = entry.data["name"]
        self._attr_unique_id = f"{entry.entry_id}_online_devices"
        self._attr_native_unit_of_measurement = "devices"
        self._attr_icon = "mdi:network"
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_should_poll = False  # Disable automatic polling
        self._refresh_task: Optional[asyncio.Task] = None

        # Start with default values
        self._attr_native_value = 0
        self._attr_available = True  # Mark as available immediately
        self._attr_extra_state_attributes = {
            "icmp_replies": 0,
            "arp_replies": 0,
            "last_scan": "Initializing",
            "time_scan": 0
        }
        
    async def async_added_to_hass(self) -> None:
        """When entity is added to HA.
        
        Triggers proper cleanup, but does not force an immediate refresh to avoid blocking startup.
        """
        await super().async_added_to_hass()
        # Do not trigger immediate update after startup; let the coordinator handle it
        self.async_on_remove(lambda: self.hass.async_create_task(self._cleanup_refresh_task()))
        
    async def _cleanup_refresh_task(self) -> None:
        """Clean up the refresh task when entity is removed."""
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            self._refresh_task = None
        
    @property
    def native_value(self) -> Optional[int]:
        """Return the state of the sensor as the number of unique devices that replied to ARP or ICMP."""
        icmp_set = getattr(self.coordinator, "_last_icmp_set", set())
        arp_set = getattr(self.coordinator, "_last_arp_set", set())
        return len(set(icmp_set) | set(arp_set))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Return the state attributes: icmp_replies, arp_replies, last_scan, time_scan."""
        if self.coordinator.data is None:
            return {}
        return {
            "icmp_replies": self.coordinator.data.get("icmp_replies"),
            "arp_replies": self.coordinator.data.get("arp_replies"),
            "last_scan": self.coordinator.data.get("last_scan"),
            "time_scan": self.coordinator.data.get("time_scan"),
        }

    @property
    def available(self) -> bool:
        """Return if entity is available.
        
        Returns:
            True if coordinator has data, False otherwise
        """
        return self.coordinator.data is not None