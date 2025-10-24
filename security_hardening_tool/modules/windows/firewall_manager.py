"""Windows Defender Firewall Manager for network security hardening."""

import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ...core.models import (
    HardeningError, HardeningResult, Parameter, ParameterBackup, SystemError
)

# Windows-specific imports
if sys.platform == "win32":
    try:
        import winreg
        import subprocess
    except ImportError:
        winreg = None
        subprocess = None
else:
    winreg = None
    subprocess = None


class WindowsFirewallManager:
    """Manages Windows Defender Firewall for security hardening."""
    
    # Firewall profile types
    PROFILE_DOMAIN = "domain"
    PROFILE_PRIVATE = "private"
    PROFILE_PUBLIC = "public"
    
    def __init__(self):
        """Initialize Windows Firewall Manager."""
        if not self._is_windows():
            raise SystemError("Windows Firewall Manager can only be used on Windows systems")
        
        if not all([winreg, subprocess]):
            raise SystemError("Required Windows modules not available")
        
        # Firewall settings according to Annexure-A
        self.firewall_settings = {
            # Private Profile Settings
            "private_firewall_state": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "state",
                "target_value": "on",
                "description": "Enable Private profile firewall",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                "registry_value": "EnableFirewall",
                "netsh_command": "netsh advfirewall set privateprofile state on"
            },
            "private_inbound_connections": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "inbound",
                "target_value": "block",
                "description": "Block inbound connections on Private profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                "registry_value": "DefaultInboundAction",
                "netsh_command": "netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound"
            },
            "private_outbound_connections": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "outbound",
                "target_value": "allow",
                "description": "Allow outbound connections on Private profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                "registry_value": "DefaultOutboundAction",
                "netsh_command": "netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound"
            },
            "private_display_notification": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "notifications",
                "target_value": "no",
                "description": "Disable notifications for Private profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                "registry_value": "DisableNotifications",
                "netsh_command": "netsh advfirewall set privateprofile settings inboundusernotification disable"
            },
            "private_log_file_path": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "logging",
                "target_value": "%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log",
                "description": "Set Private profile log file path",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging",
                "registry_value": "LogFilePath",
                "netsh_command": "netsh advfirewall set privateprofile logging filename %SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log"
            },
            "private_log_size_limit": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "logging",
                "target_value": 16384,
                "description": "Set Private profile log size limit to 16384 KB",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging",
                "registry_value": "LogFileSize",
                "netsh_command": "netsh advfirewall set privateprofile logging maxfilesize 16384"
            },
            "private_log_dropped_packets": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of dropped packets for Private profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging",
                "registry_value": "LogDroppedPackets",
                "netsh_command": "netsh advfirewall set privateprofile logging droppedconnections enable"
            },
            "private_log_successful_connections": {
                "profile": self.PROFILE_PRIVATE,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of successful connections for Private profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging",
                "registry_value": "LogSuccessfulConnections",
                "netsh_command": "netsh advfirewall set privateprofile logging allowedconnections enable"
            },
            
            # Public Profile Settings
            "public_firewall_state": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "state",
                "target_value": "on",
                "description": "Enable Public profile firewall",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "EnableFirewall",
                "netsh_command": "netsh advfirewall set publicprofile state on"
            },
            "public_inbound_connections": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "inbound",
                "target_value": "block",
                "description": "Block inbound connections on Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "DefaultInboundAction",
                "netsh_command": "netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound"
            },
            "public_outbound_connections": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "outbound",
                "target_value": "allow",
                "description": "Allow outbound connections on Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "DefaultOutboundAction",
                "netsh_command": "netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound"
            },
            "public_display_notification": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "notifications",
                "target_value": "no",
                "description": "Disable notifications for Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "DisableNotifications",
                "netsh_command": "netsh advfirewall set publicprofile settings inboundusernotification disable"
            },
            "public_local_firewall_rules": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "local_rules",
                "target_value": "no",
                "description": "Disable local firewall rules for Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "AllowLocalPolicyMerge",
                "netsh_command": "netsh advfirewall set publicprofile settings localfirewallrules disable"
            },
            "public_local_connection_rules": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "local_rules",
                "target_value": "no",
                "description": "Disable local connection security rules for Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
                "registry_value": "AllowLocalIPsecPolicyMerge",
                "netsh_command": "netsh advfirewall set publicprofile settings localconsecrules disable"
            },
            "public_log_file_path": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "logging",
                "target_value": "%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log",
                "description": "Set Public profile log file path",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging",
                "registry_value": "LogFilePath",
                "netsh_command": "netsh advfirewall set publicprofile logging filename %SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log"
            },
            "public_log_size_limit": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "logging",
                "target_value": 16384,
                "description": "Set Public profile log size limit to 16384 KB",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging",
                "registry_value": "LogFileSize",
                "netsh_command": "netsh advfirewall set publicprofile logging maxfilesize 16384"
            },
            "public_log_dropped_packets": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of dropped packets for Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging",
                "registry_value": "LogDroppedPackets",
                "netsh_command": "netsh advfirewall set publicprofile logging droppedconnections enable"
            },
            "public_log_successful_connections": {
                "profile": self.PROFILE_PUBLIC,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of successful connections for Public profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging",
                "registry_value": "LogSuccessfulConnections",
                "netsh_command": "netsh advfirewall set publicprofile logging allowedconnections enable"
            },
            
            # Domain Profile Settings (additional settings to reach 22 total)
            "domain_firewall_state": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "state",
                "target_value": "on",
                "description": "Enable Domain profile firewall",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "registry_value": "EnableFirewall",
                "netsh_command": "netsh advfirewall set domainprofile state on"
            },
            "domain_inbound_connections": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "inbound",
                "target_value": "block",
                "description": "Block inbound connections on Domain profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "registry_value": "DefaultInboundAction",
                "netsh_command": "netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound"
            },
            "domain_outbound_connections": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "outbound",
                "target_value": "allow",
                "description": "Allow outbound connections on Domain profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "registry_value": "DefaultOutboundAction",
                "netsh_command": "netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound"
            },
            "domain_display_notification": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "notifications",
                "target_value": "no",
                "description": "Disable notifications for Domain profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "registry_value": "DisableNotifications",
                "netsh_command": "netsh advfirewall set domainprofile settings inboundusernotification disable"
            },
            "domain_log_file_path": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "logging",
                "target_value": "%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log",
                "description": "Set Domain profile log file path",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                "registry_value": "LogFilePath",
                "netsh_command": "netsh advfirewall set domainprofile logging filename %SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log"
            },
            "domain_log_size_limit": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "logging",
                "target_value": 16384,
                "description": "Set Domain profile log size limit to 16384 KB",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                "registry_value": "LogFileSize",
                "netsh_command": "netsh advfirewall set domainprofile logging maxfilesize 16384"
            },
            "domain_log_dropped_packets": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of dropped packets for Domain profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                "registry_value": "LogDroppedPackets",
                "netsh_command": "netsh advfirewall set domainprofile logging droppedconnections enable"
            },
            "domain_log_successful_connections": {
                "profile": self.PROFILE_DOMAIN,
                "setting": "logging",
                "target_value": "yes",
                "description": "Enable logging of successful connections for Domain profile",
                "registry_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                "registry_value": "LogSuccessfulConnections",
                "netsh_command": "netsh advfirewall set domainprofile logging allowedconnections enable"
            }
        }
    
    def get_firewall_setting(self, setting_id: str) -> Tuple[bool, Any]:
        """Get current firewall setting value."""
        if setting_id not in self.firewall_settings:
            return False, None
        
        setting_info = self.firewall_settings[setting_id]
        
        try:
            # Try to read from registry first
            registry_path = setting_info.get("registry_path")
            registry_value = setting_info.get("registry_value")
            
            if registry_path and registry_value:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_READ) as key:
                    value, reg_type = winreg.QueryValueEx(key, registry_value)
                    return True, value
            
        except (OSError, FileNotFoundError):
            pass
        
        # Fallback to netsh command
        try:
            return self._get_setting_via_netsh(setting_info)
        except Exception:
            return False, None
    
    def set_firewall_setting(self, setting_id: str, value: Any) -> bool:
        """Set firewall setting value."""
        if setting_id not in self.firewall_settings:
            return False
        
        setting_info = self.firewall_settings[setting_id]
        
        try:
            # Try to set via registry first
            if self._set_setting_via_registry(setting_info, value):
                return True
        except Exception:
            pass
        
        # Fallback to netsh command
        try:
            return self._set_setting_via_netsh(setting_info, value)
        except Exception:
            return False
    
    def backup_firewall_setting(self, setting_id: str) -> Optional[ParameterBackup]:
        """Create backup of firewall setting."""
        success, current_value = self.get_firewall_setting(setting_id)
        
        if not success:
            current_value = None
        
        setting_info = self.firewall_settings.get(setting_id, {})
        
        backup = ParameterBackup(
            parameter_id=setting_id,
            original_value=current_value,
            restore_method="firewall",
            restore_data={
                "setting_info": setting_info,
                "registry_path": setting_info.get("registry_path"),
                "registry_value": setting_info.get("registry_value"),
                "netsh_command": setting_info.get("netsh_command")
            }
        )
        
        return backup
    
    def restore_firewall_setting(self, backup: ParameterBackup) -> bool:
        """Restore firewall setting from backup."""
        if backup.restore_method != "firewall":
            return False
        
        try:
            if backup.original_value is None:
                # Setting didn't exist originally, try to delete it
                return self._delete_firewall_setting(backup)
            else:
                # Restore original value
                return self.set_firewall_setting(backup.parameter_id, backup.original_value)
                
        except Exception:
            return False
    
    def apply_firewall_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply firewall hardening configurations."""
        results = []
        
        # Filter firewall-related parameters
        firewall_params = [p for p in parameters if p.category == "network" and "firewall" in p.id]
        
        for param in firewall_params:
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.get_firewall_setting(param.id)
                result.previous_value = current_value if success else None
                
                # Apply new value
                if self.set_firewall_setting(param.id, param.target_value):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to set firewall setting {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_firewall_status(self) -> Dict[str, Dict[str, Any]]:
        """Get comprehensive firewall status."""
        status = {}
        
        for setting_id, setting_info in self.firewall_settings.items():
            success, current_value = self.get_firewall_setting(setting_id)
            
            status[setting_id] = {
                "info": setting_info,
                "current_value": current_value if success else None,
                "target_value": setting_info["target_value"],
                "compliant": self._is_setting_compliant(current_value, setting_info["target_value"]) if success else False
            }
        
        return status
    
    def enable_firewall_all_profiles(self) -> List[HardeningResult]:
        """Enable firewall for all profiles."""
        results = []
        
        profile_settings = [
            "domain_firewall_state",
            "private_firewall_state",
            "public_firewall_state"
        ]
        
        for setting_id in profile_settings:
            result = HardeningResult(
                parameter_id=setting_id,
                previous_value=None,
                applied_value="on",
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.get_firewall_setting(setting_id)
                result.previous_value = current_value if success else None
                
                # Enable firewall
                if self.set_firewall_setting(setting_id, "on"):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to enable firewall for {setting_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def configure_firewall_logging(self) -> List[HardeningResult]:
        """Configure firewall logging for all profiles."""
        results = []
        
        logging_settings = [
            "domain_log_file_path",
            "domain_log_size_limit", 
            "domain_log_dropped_packets",
            "domain_log_successful_connections",
            "private_log_file_path",
            "private_log_size_limit",
            "private_log_dropped_packets",
            "private_log_successful_connections",
            "public_log_file_path",
            "public_log_size_limit",
            "public_log_dropped_packets",
            "public_log_successful_connections"
        ]
        
        for setting_id in logging_settings:
            result = HardeningResult(
                parameter_id=setting_id,
                previous_value=None,
                applied_value=self.firewall_settings[setting_id]["target_value"],
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.get_firewall_setting(setting_id)
                result.previous_value = current_value if success else None
                
                # Apply logging setting
                target_value = self.firewall_settings[setting_id]["target_value"]
                if self.set_firewall_setting(setting_id, target_value):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to configure logging for {setting_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def _get_setting_via_netsh(self, setting_info: Dict[str, Any]) -> Tuple[bool, Any]:
        """Get firewall setting using netsh command."""
        profile = setting_info["profile"]
        setting_type = setting_info["setting"]
        
        try:
            if setting_type == "state":
                cmd = f"netsh advfirewall show {profile}profile state"
            elif setting_type in ["inbound", "outbound"]:
                cmd = f"netsh advfirewall show {profile}profile firewallpolicy"
            elif setting_type == "notifications":
                cmd = f"netsh advfirewall show {profile}profile settings"
            elif setting_type == "logging":
                cmd = f"netsh advfirewall show {profile}profile logging"
            else:
                return False, None
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the output to extract the specific setting value
                return self._parse_netsh_output(result.stdout, setting_info)
            
        except subprocess.TimeoutExpired:
            pass
        
        return False, None
    
    def _set_setting_via_registry(self, setting_info: Dict[str, Any], value: Any) -> bool:
        """Set firewall setting via registry."""
        registry_path = setting_info.get("registry_path")
        registry_value = setting_info.get("registry_value")
        
        if not registry_path or not registry_value:
            return False
        
        try:
            # Convert value to appropriate registry format
            reg_value = self._convert_value_for_registry(value, setting_info)
            
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                winreg.SetValueEx(key, registry_value, 0, winreg.REG_DWORD, reg_value)
                return True
                
        except (OSError, PermissionError):
            return False
    
    def _set_setting_via_netsh(self, setting_info: Dict[str, Any], value: Any) -> bool:
        """Set firewall setting using netsh command."""
        netsh_command = setting_info.get("netsh_command")
        
        if not netsh_command:
            return False
        
        try:
            # Customize command based on value
            cmd = self._customize_netsh_command(netsh_command, value, setting_info)
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
    
    def _parse_netsh_output(self, output: str, setting_info: Dict[str, Any]) -> Tuple[bool, Any]:
        """Parse netsh command output to extract setting value."""
        lines = output.lower().split('\n')
        setting_type = setting_info["setting"]
        profile = setting_info["profile"]
        
        # Parse different setting types
        if setting_type == "state":
            for line in lines:
                if "state" in line and profile in line:
                    if "on" in line or "enable" in line:
                        return True, "on"
                    elif "off" in line or "disable" in line:
                        return True, "off"
        
        elif setting_type in ["inbound", "outbound"]:
            for line in lines:
                if setting_type in line and profile in line:
                    if "block" in line:
                        return True, "block"
                    elif "allow" in line:
                        return True, "allow"
        
        elif setting_type == "notifications":
            for line in lines:
                if "notification" in line and profile in line:
                    if "disable" in line or "no" in line:
                        return True, "no"
                    elif "enable" in line or "yes" in line:
                        return True, "yes"
        
        elif setting_type == "local_rules":
            for line in lines:
                if ("local" in line and "rule" in line) or ("policy" in line and "merge" in line):
                    if "disable" in line or "no" in line:
                        return True, "no"
                    elif "enable" in line or "yes" in line:
                        return True, "yes"
        
        elif setting_type == "logging":
            setting_name = setting_info.get("registry_value", "").lower()
            
            if "logfilepath" in setting_name or "filename" in setting_info.get("netsh_command", "").lower():
                for line in lines:
                    if "filename" in line or "file" in line:
                        # Extract file path from line
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if "system32" in part.lower() or ".log" in part.lower():
                                return True, part
            
            elif "logfilesize" in setting_name or "maxfilesize" in setting_info.get("netsh_command", "").lower():
                for line in lines:
                    if "size" in line or "max" in line:
                        # Extract size value
                        import re
                        numbers = re.findall(r'\d+', line)
                        if numbers:
                            return True, int(numbers[0])
            
            elif "logdroppedpackets" in setting_name or "droppedconnections" in setting_info.get("netsh_command", "").lower():
                for line in lines:
                    if "dropped" in line or "drop" in line:
                        if "enable" in line or "yes" in line:
                            return True, "yes"
                        elif "disable" in line or "no" in line:
                            return True, "no"
            
            elif "logsuccessfulconnections" in setting_name or "allowedconnections" in setting_info.get("netsh_command", "").lower():
                for line in lines:
                    if "allowed" in line or "success" in line:
                        if "enable" in line or "yes" in line:
                            return True, "yes"
                        elif "disable" in line or "no" in line:
                            return True, "no"
        
        return False, None
    
    def _convert_value_for_registry(self, value: Any, setting_info: Dict[str, Any]) -> int:
        """Convert setting value to registry format."""
        if isinstance(value, bool):
            return 1 if value else 0
        elif isinstance(value, str):
            if value.lower() in ["on", "yes", "enable", "true"]:
                return 1
            elif value.lower() in ["off", "no", "disable", "false"]:
                return 0
            elif value.lower() == "block":
                return 1
            elif value.lower() == "allow":
                return 0
        elif isinstance(value, int):
            return value
        
        return 0
    
    def _customize_netsh_command(self, command: str, value: Any, setting_info: Dict[str, Any]) -> str:
        """Customize netsh command based on the value being set."""
        setting_type = setting_info["setting"]
        
        # Handle different setting types
        if setting_type == "state":
            if isinstance(value, str):
                if value.lower() in ["on", "enable", "true", "yes"]:
                    return command.replace("state on", "state on").replace("state off", "state on")
                else:
                    return command.replace("state on", "state off").replace("state off", "state off")
        
        elif setting_type in ["inbound", "outbound"]:
            if isinstance(value, str):
                if value.lower() == "block":
                    return command.replace("allowoutbound", "allowoutbound").replace("blockinbound", "blockinbound")
                elif value.lower() == "allow":
                    return command.replace("blockinbound", "allowinbound").replace("allowoutbound", "allowoutbound")
        
        elif setting_type == "notifications":
            if isinstance(value, str):
                if value.lower() in ["no", "disable", "false"]:
                    return command.replace("enable", "disable").replace("disable", "disable")
                else:
                    return command.replace("disable", "enable").replace("enable", "enable")
        
        elif setting_type == "local_rules":
            if isinstance(value, str):
                if value.lower() in ["no", "disable", "false"]:
                    return command.replace("enable", "disable").replace("disable", "disable")
                else:
                    return command.replace("disable", "enable").replace("enable", "enable")
        
        elif setting_type == "logging":
            setting_name = setting_info.get("registry_value", "").lower()
            
            if "logfilepath" in setting_name:
                # Replace filename in command
                if isinstance(value, str):
                    return command.replace("%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log", value).replace("%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log", value)
            
            elif "logfilesize" in setting_name:
                # Replace size in command
                if isinstance(value, (int, str)):
                    return command.replace("16384", str(value))
            
            elif "logdroppedpackets" in setting_name:
                if isinstance(value, str):
                    if value.lower() in ["yes", "enable", "true"]:
                        return command.replace("disable", "enable").replace("enable", "enable")
                    else:
                        return command.replace("enable", "disable").replace("disable", "disable")
            
            elif "logsuccessfulconnections" in setting_name:
                if isinstance(value, str):
                    if value.lower() in ["yes", "enable", "true"]:
                        return command.replace("disable", "enable").replace("enable", "enable")
                    else:
                        return command.replace("enable", "disable").replace("disable", "disable")
        
        return command
    
    def _delete_firewall_setting(self, backup: ParameterBackup) -> bool:
        """Delete firewall setting (used during restore if original didn't exist)."""
        try:
            restore_data = backup.restore_data
            registry_path = restore_data.get("registry_path")
            registry_value = restore_data.get("registry_value")
            
            if registry_path and registry_value:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_WRITE) as key:
                    winreg.DeleteValue(key, registry_value)
                    return True
                    
        except (OSError, FileNotFoundError):
            # Value already doesn't exist, which is what we want
            return True
        except Exception:
            pass
        
        return False
    
    def _is_setting_compliant(self, current_value: Any, target_value: Any) -> bool:
        """Check if current setting value is compliant with target."""
        if current_value is None:
            return False
        
        # Normalize values for comparison
        current_normalized = self._normalize_value(current_value)
        target_normalized = self._normalize_value(target_value)
        
        return current_normalized == target_normalized
    
    def _normalize_value(self, value: Any) -> Any:
        """Normalize value for comparison."""
        if isinstance(value, str):
            value = value.lower()
            if value in ["on", "yes", "enable", "true"]:
                return True
            elif value in ["off", "no", "disable", "false"]:
                return False
        elif isinstance(value, int):
            return bool(value) if value in [0, 1] else value
        
        return value
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"
    
    def get_supported_settings(self) -> List[str]:
        """Get list of supported firewall setting IDs."""
        return list(self.firewall_settings.keys())
    
    def is_setting_supported(self, setting_id: str) -> bool:
        """Check if firewall setting is supported by this manager."""
        return setting_id in self.firewall_settings
    
    def configure_default_deny_policies(self) -> List[HardeningResult]:
        """Configure default deny policies for all profiles."""
        results = []
        
        deny_settings = [
            "domain_inbound_connections",
            "private_inbound_connections",
            "public_inbound_connections"
        ]
        
        for setting_id in deny_settings:
            result = HardeningResult(
                parameter_id=setting_id,
                previous_value=None,
                applied_value="block",
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.get_firewall_setting(setting_id)
                result.previous_value = current_value if success else None
                
                # Apply deny policy
                if self.set_firewall_setting(setting_id, "block"):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to set deny policy for {setting_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def disable_local_policy_merge(self) -> List[HardeningResult]:
        """Disable local policy merge for public profile."""
        results = []
        
        local_policy_settings = [
            "public_local_firewall_rules",
            "public_local_connection_rules"
        ]
        
        for setting_id in local_policy_settings:
            result = HardeningResult(
                parameter_id=setting_id,
                previous_value=None,
                applied_value="no",
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.get_firewall_setting(setting_id)
                result.previous_value = current_value if success else None
                
                # Disable local policy merge
                if self.set_firewall_setting(setting_id, "no"):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to disable local policy merge for {setting_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def create_firewall_rules(self, rules: List[Dict[str, Any]]) -> List[HardeningResult]:
        """Create custom firewall rules."""
        results = []
        
        for rule in rules:
            result = HardeningResult(
                parameter_id=f"firewall_rule_{rule.get('name', 'custom')}",
                previous_value=None,
                applied_value=rule,
                success=False
            )
            
            try:
                # Build netsh command for rule creation
                cmd_parts = ["netsh", "advfirewall", "firewall", "add", "rule"]
                
                # Add rule parameters
                if "name" in rule:
                    cmd_parts.extend(["name=", f'"{rule["name"]}"'])
                
                if "dir" in rule:
                    cmd_parts.extend(["dir=", rule["dir"]])
                
                if "action" in rule:
                    cmd_parts.extend(["action=", rule["action"]])
                
                if "protocol" in rule:
                    cmd_parts.extend(["protocol=", rule["protocol"]])
                
                if "localport" in rule:
                    cmd_parts.extend(["localport=", str(rule["localport"])])
                
                if "remoteip" in rule:
                    cmd_parts.extend(["remoteip=", rule["remoteip"]])
                
                cmd = " ".join(cmd_parts)
                
                # Execute command
                result_proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                if result_proc.returncode == 0:
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to create firewall rule: {result_proc.stderr}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def validate_firewall_configuration(self) -> Dict[str, Any]:
        """Validate current firewall configuration against security best practices."""
        validation_results = {
            "overall_status": "unknown",
            "issues": [],
            "recommendations": [],
            "compliant_settings": 0,
            "total_settings": len(self.firewall_settings)
        }
        
        compliant_count = 0
        
        for setting_id, setting_info in self.firewall_settings.items():
            success, current_value = self.get_firewall_setting(setting_id)
            
            if success:
                target_value = setting_info["target_value"]
                is_compliant = self._is_setting_compliant(current_value, target_value)
                
                if is_compliant:
                    compliant_count += 1
                else:
                    validation_results["issues"].append({
                        "setting": setting_id,
                        "current": current_value,
                        "expected": target_value,
                        "description": setting_info["description"]
                    })
                    
                    validation_results["recommendations"].append(
                        f"Set {setting_id} to {target_value}: {setting_info['description']}"
                    )
            else:
                validation_results["issues"].append({
                    "setting": setting_id,
                    "current": "Unable to read",
                    "expected": setting_info["target_value"],
                    "description": f"Failed to read {setting_info['description']}"
                })
        
        validation_results["compliant_settings"] = compliant_count
        
        # Determine overall status
        compliance_percentage = (compliant_count / len(self.firewall_settings)) * 100
        
        if compliance_percentage >= 90:
            validation_results["overall_status"] = "compliant"
        elif compliance_percentage >= 70:
            validation_results["overall_status"] = "mostly_compliant"
        elif compliance_percentage >= 50:
            validation_results["overall_status"] = "partially_compliant"
        else:
            validation_results["overall_status"] = "non_compliant"
        
        return validation_results
    
    def export_firewall_configuration(self) -> Dict[str, Any]:
        """Export current firewall configuration for backup or analysis."""
        config = {
            "timestamp": str(datetime.now()),
            "settings": {},
            "profiles": {}
        }
        
        # Export all settings
        for setting_id, setting_info in self.firewall_settings.items():
            success, current_value = self.get_firewall_setting(setting_id)
            
            config["settings"][setting_id] = {
                "current_value": current_value if success else None,
                "target_value": setting_info["target_value"],
                "description": setting_info["description"],
                "profile": setting_info["profile"],
                "setting_type": setting_info["setting"]
            }
        
        # Group by profiles for easier analysis
        for profile in [self.PROFILE_DOMAIN, self.PROFILE_PRIVATE, self.PROFILE_PUBLIC]:
            config["profiles"][profile] = {
                setting_id: config["settings"][setting_id]
                for setting_id, setting_info in self.firewall_settings.items()
                if setting_info["profile"] == profile
            }
        
        return config
    
    def apply_comprehensive_hardening(self) -> List[HardeningResult]:
        """Apply comprehensive firewall hardening across all profiles and settings."""
        results = []
        
        # Enable firewall for all profiles
        results.extend(self.enable_firewall_all_profiles())
        
        # Configure default deny policies
        results.extend(self.configure_default_deny_policies())
        
        # Disable local policy merge for public profile
        results.extend(self.disable_local_policy_merge())
        
        # Configure comprehensive logging
        results.extend(self.configure_firewall_logging())
        
        # Disable notifications for all profiles
        notification_settings = [
            "domain_display_notification",
            "private_display_notification", 
            "public_display_notification"
        ]
        
        for setting_id in notification_settings:
            result = HardeningResult(
                parameter_id=setting_id,
                previous_value=None,
                applied_value="no",
                success=False
            )
            
            try:
                success, current_value = self.get_firewall_setting(setting_id)
                result.previous_value = current_value if success else None
                
                if self.set_firewall_setting(setting_id, "no"):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to disable notifications for {setting_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Get current firewall rules."""
        rules = []
        
        try:
            # Get firewall rules using netsh
            cmd = "netsh advfirewall firewall show rule name=all"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse the output to extract rules
                lines = result.stdout.split('\n')
                current_rule = {}
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Rule Name:'):
                        if current_rule:
                            rules.append(current_rule)
                        current_rule = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('Enabled:'):
                        current_rule['enabled'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Direction:'):
                        current_rule['direction'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Profiles:'):
                        current_rule['profiles'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Action:'):
                        current_rule['action'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Protocol:'):
                        current_rule['protocol'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Local Port:'):
                        current_rule['local_port'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Remote Port:'):
                        current_rule['remote_port'] = line.split(':', 1)[1].strip()
                
                # Add the last rule
                if current_rule:
                    rules.append(current_rule)
                    
        except Exception:
            # Return empty list if unable to get rules
            pass
        
        return rules
    
    def remove_firewall_rule(self, rule_name: str) -> HardeningResult:
        """Remove a specific firewall rule."""
        result = HardeningResult(
            parameter_id=f"remove_rule_{rule_name}",
            previous_value=rule_name,
            applied_value=None,
            success=False
        )
        
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            proc_result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if proc_result.returncode == 0:
                result.success = True
            else:
                result.error_message = f"Failed to remove firewall rule: {proc_result.stderr}"
                
        except Exception as e:
            result.error_message = str(e)
        
        return result