"""Windows Registry Manager for security policy configuration."""

import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from ...core.models import (
    HardeningError, HardeningResult, Parameter, ParameterBackup, SystemError
)

# Windows-specific imports
if sys.platform == "win32":
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None


class WindowsRegistryManager:
    """Manages Windows Registry operations for security hardening."""
    
    def __init__(self):
        """Initialize Windows Registry Manager."""
        if not self._is_windows():
            raise SystemError("Windows Registry Manager can only be used on Windows systems")
        
        if winreg is None:
            raise SystemError("Windows Registry module not available")
        
        # Registry key mappings for security policies
        self.security_policy_keys = {
            # Account Policies - Password Policy
            "password_min_length": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "MinimumPasswordLength",
                "type": winreg.REG_DWORD
            },
            "password_complexity": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "PasswordComplexity",
                "type": winreg.REG_DWORD
            },
            "password_history_count": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "PasswordHistoryLength",
                "type": winreg.REG_DWORD
            },
            "password_max_age": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "MaximumPasswordAge",
                "type": winreg.REG_DWORD
            },
            "password_min_age": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "MinimumPasswordAge",
                "type": winreg.REG_DWORD
            },
            "reversible_encryption_disabled": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "ClearTextPassword",
                "type": winreg.REG_DWORD
            },
            
            # Account Policies - Account Lockout Policy
            "account_lockout_threshold": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "LockoutBadCount",
                "type": winreg.REG_DWORD
            },
            "account_lockout_duration": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "value": "LockoutDuration",
                "type": winreg.REG_DWORD
            },
            "admin_account_lockout": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa",
                "value": "LimitBlankPasswordUse",
                "type": winreg.REG_DWORD
            },
            
            # Security Options - Accounts
            "guest_account_disabled": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa",
                "value": "NoDefaultAdminOwner",
                "type": winreg.REG_DWORD
            },
            "anonymous_sid_translation_disabled": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa",
                "value": "TurnOffAnonymousBlock",
                "type": winreg.REG_DWORD
            },
            "everyone_permissions_disabled": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa",
                "value": "EveryoneIncludesAnonymous",
                "type": winreg.REG_DWORD
            },
            
            # Security Options - Interactive Logon
            "interactive_logon_ctrl_alt_del": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "DisableCAD",
                "type": winreg.REG_DWORD
            },
            "interactive_logon_last_user": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "DontDisplayLastUserName",
                "type": winreg.REG_DWORD
            },
            "interactive_logon_machine_lockout": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "MaxDevicePasswordFailedAttempts",
                "type": winreg.REG_DWORD
            },
            "interactive_logon_inactivity_limit": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "InactivityTimeoutSecs",
                "type": winreg.REG_DWORD
            },
            
            # Security Options - Network Security
            "lan_manager_hash_disabled": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa",
                "value": "NoLMHash",
                "type": winreg.REG_DWORD
            },
            "ntlm_minimum_security": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                "value": "NTLMMinClientSec",
                "type": winreg.REG_DWORD
            },
            "ldap_client_signing": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SYSTEM\CurrentControlSet\Services\LDAP",
                "value": "LDAPClientIntegrity",
                "type": winreg.REG_DWORD
            },
            
            # User Account Control (UAC)
            "uac_admin_approval_mode": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "FilterAdministratorToken",
                "type": winreg.REG_DWORD
            },
            "uac_elevation_prompt_admin": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "ConsentPromptBehaviorAdmin",
                "type": winreg.REG_DWORD
            },
            "uac_elevation_prompt_user": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "ConsentPromptBehaviorUser",
                "type": winreg.REG_DWORD
            },
            "uac_detect_installations": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "EnableInstallerDetection",
                "type": winreg.REG_DWORD
            },
            "uac_run_all_admins": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "EnableLUA",
                "type": winreg.REG_DWORD
            },
            "uac_secure_desktop": {
                "key": winreg.HKEY_LOCAL_MACHINE,
                "subkey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value": "PromptOnSecureDesktop",
                "type": winreg.REG_DWORD
            }
        }
    
    def read_registry_value(self, parameter_id: str) -> Tuple[bool, Any]:
        """Read registry value for specified parameter."""
        if parameter_id not in self.security_policy_keys:
            return False, None
        
        reg_info = self.security_policy_keys[parameter_id]
        
        try:
            with winreg.OpenKey(reg_info["key"], reg_info["subkey"], 0, winreg.KEY_READ) as key:
                value, reg_type = winreg.QueryValueEx(key, reg_info["value"])
                return True, value
                
        except (OSError, FileNotFoundError):
            # Registry key or value doesn't exist
            return False, None
    
    def write_registry_value(self, parameter_id: str, value: Any) -> bool:
        """Write registry value for specified parameter."""
        if parameter_id not in self.security_policy_keys:
            return False
        
        reg_info = self.security_policy_keys[parameter_id]
        
        try:
            # Create or open the registry key
            with winreg.CreateKey(reg_info["key"], reg_info["subkey"]) as key:
                # Set the value
                winreg.SetValueEx(key, reg_info["value"], 0, reg_info["type"], value)
                return True
                
        except (OSError, PermissionError) as e:
            raise SystemError(f"Failed to write registry value for {parameter_id}: {str(e)}")
    
    def backup_registry_value(self, parameter_id: str) -> Optional[ParameterBackup]:
        """Create backup of registry value."""
        success, current_value = self.read_registry_value(parameter_id)
        
        if not success:
            current_value = None
        
        reg_info = self.security_policy_keys.get(parameter_id, {})
        
        backup = ParameterBackup(
            parameter_id=parameter_id,
            original_value=current_value,
            restore_method="registry",
            restore_data={
                "key": reg_info.get("key"),
                "subkey": reg_info.get("subkey"),
                "value": reg_info.get("value"),
                "type": reg_info.get("type")
            }
        )
        
        return backup
    
    def restore_registry_value(self, backup: ParameterBackup) -> bool:
        """Restore registry value from backup."""
        if backup.restore_method != "registry":
            return False
        
        try:
            if backup.original_value is None:
                # Value didn't exist, try to delete it
                return self._delete_registry_value(backup)
            else:
                # Restore original value
                return self.write_registry_value(backup.parameter_id, backup.original_value)
                
        except Exception:
            return False
    
    def apply_account_policies(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply account policy parameters."""
        results = []
        
        for param in parameters:
            if param.category != "authentication":
                continue
            
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.read_registry_value(param.id)
                result.previous_value = current_value if success else None
                
                # Apply new value
                if self.write_registry_value(param.id, param.target_value):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to write registry value for {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def apply_security_options(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply security options parameters."""
        results = []
        
        for param in parameters:
            if param.category not in ["access_control", "network"]:
                continue
            
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.read_registry_value(param.id)
                result.previous_value = current_value if success else None
                
                # Convert boolean values to registry format
                target_value = param.target_value
                if isinstance(target_value, bool):
                    target_value = 1 if target_value else 0
                
                # Apply new value
                if self.write_registry_value(param.id, target_value):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to write registry value for {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def apply_uac_settings(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply User Account Control settings."""
        results = []
        
        uac_params = [p for p in parameters if p.id.startswith("uac_")]
        
        for param in uac_params:
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Get current value
                success, current_value = self.read_registry_value(param.id)
                result.previous_value = current_value if success else None
                
                # Convert boolean values to registry format
                target_value = param.target_value
                if isinstance(target_value, bool):
                    target_value = 1 if target_value else 0
                
                # Apply new value
                if self.write_registry_value(param.id, target_value):
                    result.success = True
                    result.backup_created = True
                    # UAC changes typically require reboot
                    result.requires_reboot = True
                else:
                    result.error_message = f"Failed to write registry value for {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_current_values(self, parameter_ids: List[str]) -> Dict[str, Any]:
        """Get current registry values for specified parameters."""
        current_values = {}
        
        for param_id in parameter_ids:
            success, value = self.read_registry_value(param_id)
            current_values[param_id] = value if success else None
        
        return current_values
    
    def validate_registry_access(self) -> bool:
        """Validate that we have necessary registry access permissions."""
        try:
            # Try to open a common registry key for reading
            test_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, test_key, 0, winreg.KEY_READ):
                pass
            
            # Try to create a test key to check write permissions
            test_subkey = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, test_subkey, 0, winreg.KEY_WRITE):
                pass
            
            return True
            
        except (OSError, PermissionError):
            return False
    
    def _delete_registry_value(self, backup: ParameterBackup) -> bool:
        """Delete registry value (used during restore if original didn't exist)."""
        try:
            restore_data = backup.restore_data
            key = restore_data.get("key")
            subkey = restore_data.get("subkey")
            value_name = restore_data.get("value")
            
            if not all([key, subkey, value_name]):
                return False
            
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as reg_key:
                winreg.DeleteValue(reg_key, value_name)
                return True
                
        except (OSError, FileNotFoundError):
            # Value already doesn't exist, which is what we want
            return True
        except Exception:
            return False
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported parameter IDs."""
        return list(self.security_policy_keys.keys())
    
    def is_parameter_supported(self, parameter_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return parameter_id in self.security_policy_keys