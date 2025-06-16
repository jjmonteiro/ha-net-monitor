"""The Network Monitor integration."""
import logging
from typing import Any, Dict
from datetime import timedelta
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, CoreState
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL
from .coordinator import NetworkMonitorCoordinator

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up with proper cleanup and robust startup.
    
    Args:
        hass: Home Assistant instance
        entry: Config entry for this integration
    
    Returns:
        True if setup was successful, False otherwise
    """
    # Use a lock to prevent race conditions during setup
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    
    # Clean up old coordinator if it exists
    if entry.entry_id in hass.data[DOMAIN]:
        old_coordinator = hass.data[DOMAIN][entry.entry_id]
        await old_coordinator.async_shutdown()

    # Create and store new coordinator
    coordinator = NetworkMonitorCoordinator(hass, entry.data)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    
    # Set up the sensor platform
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    
    # Start the coordinator based on Home Assistant state
    if hass.state == CoreState.running:
        hass.async_create_task(coordinator.async_start())
    else:
        # Store the listener reference for proper cleanup
        listener = coordinator.async_start
        remover = hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, listener)
        coordinator.set_startup_listener(listener, remover)
        
    # Listen for config entry updates
    entry.async_on_unload(
        entry.add_update_listener(async_update_listener)
    )
        
    return True

async def async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update.
    
    Args:
        hass: Home Assistant instance
        entry: Config entry that was updated
    """
    _LOGGER.debug("Config entry updated: %s", entry.data)
    
    # Get the coordinator
    coordinator: NetworkMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    
    # Update coordinator settings
    coordinator.ip_range = entry.data["ip_range"]
    coordinator.wait_time = timedelta(seconds=entry.data.get("scan_interval", DEFAULT_SCAN_INTERVAL))
    
    # Restart the coordinator
    _LOGGER.debug("Restarting coordinator with new settings: IP Range=%s, Scan Interval=%s",
                 coordinator.ip_range, coordinator.wait_time)
    await coordinator.async_shutdown()
    await coordinator.async_start()

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.
    
    Args:
        hass: Home Assistant instance
        entry: Config entry to unload
    
    Returns:
        True if unload was successful, False otherwise
    """
    # The coordinator's shutdown method will cancel the long-running scan task.
    coordinator: NetworkMonitorCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
    await coordinator.async_shutdown()

    # Unload the sensor platform.
    return await hass.config_entries.async_unload_platforms(entry, ["sensor"])