"""Config flow for Network Monitor."""
import logging
import re
from typing import Any, Dict, Optional
import voluptuous as vol
from ipaddress import ip_network, ip_address
from homeassistant import config_entries
from homeassistant.core import callback
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL, DEFAULT_IP_RANGE, DEFAULT_NAME

_LOGGER = logging.getLogger(__name__)

def validate_ip_range(ip_range: str) -> bool:
    """Validate the IP range format.
    
    Args:
        ip_range: The IP range to validate (CIDR or range format)
    
    Returns:
        True if valid, False otherwise
    """
    # Check for CIDR notation
    if '/' in ip_range:
        try:
            ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    # Check for range notation (e.g., 192.168.1.100-150)
    if '-' in ip_range:
        try:
            start, end = ip_range.split('-')
            # Validate start IP
            ip_address(start)
            # Validate end number
            end_num = int(end)
            if not (0 <= end_num <= 255):
                return False
            # Validate start IP's last octet
            start_parts = start.split('.')
            if len(start_parts) != 4:
                return False
            start_last_octet = int(start_parts[-1])
            if not (0 <= start_last_octet <= end_num):
                return False
            return True
        except (ValueError, IndexError):
            return False
    
    return False

def _validate_ip_range(ip_range: str) -> Optional[str]:
    """Validate the IP range format."""
    try:
        ip_network(ip_range, strict=False)
        return None
    except ValueError:
        return "invalid_ip_range"

class NetworkMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Monitor."""

    VERSION = 1

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle the initial step.
        
        Args:
            user_input: User input from the form
        
        Returns:
            Flow result dictionary
        """
        errors: Dict[str, str] = {}
        
        if user_input is not None:
            # Validate IP range
            validation_result = await self.hass.async_add_executor_job(
                _validate_ip_range, user_input["ip_range"]
            )
            if validation_result:
                errors["ip_range"] = validation_result
            else:
                # Check if an entry with the same IP range already exists
                existing_entries = self.hass.config_entries.async_entries(DOMAIN)
                if any(
                    entry.data["ip_range"] == user_input["ip_range"]
                    for entry in existing_entries
                ):
                    return self.async_abort(reason="already_configured")

                _LOGGER.info("Creating new Network Monitor entry for IP range: %s", user_input["ip_range"])
                return self.async_create_entry(title=user_input["name"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("name", default=DEFAULT_NAME): str,
                    vol.Required("ip_range", default=DEFAULT_IP_RANGE): str,
                    vol.Required(
                        "scan_interval", default=DEFAULT_SCAN_INTERVAL
                    ): int,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        """Get the options flow for this handler.
        
        Args:
            config_entry: The config entry that is being configured
        
        Returns:
            Options flow handler
        """
        return NetworkMonitorOptionsFlow(config_entry)

class NetworkMonitorOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for Network Monitor."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow.
        
        Args:
            entry: The config entry that is being configured
        """
        self.entry = entry

    async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle the initial step of the options flow.
        
        Args:
            user_input: User input from the form
        
        Returns:
            Flow result dictionary
        """
        errors: Dict[str, str] = {}
        
        if user_input is not None:
            # Validate IP range
            validation_result = await self.hass.async_add_executor_job(
                _validate_ip_range, user_input["ip_range"]
            )
            if validation_result:
                errors["ip_range"] = validation_result
            else:
                # Check if another entry with the same IP range exists
                existing_entries = self.hass.config_entries.async_entries(DOMAIN)
                if any(
                    entry.data["ip_range"] == user_input["ip_range"]
                    and entry.entry_id != self.entry.entry_id
                    for entry in existing_entries
                ):
                    errors["ip_range"] = "already_configured"
                else:
                    # Update the config entry
                    self.hass.config_entries.async_update_entry(
                        self.entry,
                        data=user_input,
                        title=user_input["name"]
                    )
                    return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "name",
                        default=self.entry.data.get("name", DEFAULT_NAME)
                    ): str,
                    vol.Required(
                        "ip_range",
                        default=self.entry.data.get("ip_range", DEFAULT_IP_RANGE)
                    ): str,
                    vol.Required(
                        "scan_interval",
                        default=self.entry.data.get("scan_interval", DEFAULT_SCAN_INTERVAL)
                    ): int,
                }
            ),
            errors=errors,
        )