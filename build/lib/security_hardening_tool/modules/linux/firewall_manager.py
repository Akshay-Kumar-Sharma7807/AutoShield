"""Linux firewall manager for UFW configuration hardening."""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import HardeningResult, Parameter, ParameterBackup


class LinuxFirewallManager:
    """Manager for Linux UFW (Uncomplicated Firewall) hardening."""
    
    def __init__(self):
        """Initialize firewall manager."""
        self.ufw_config_dir = Path("/etc/ufw")
        self.ufw_config = self.ufw_config_dir / "ufw.conf"
        self.before_rules = self.ufw_config_dir / "before.rules"
        self.after_rules = self.ufw_config_dir / "after.rules"
        
        # Supported firewall parameters from Annexure-B
        self.supported_parameters = {
            # UFW basic configuration
            "ufw_enabled": {"type": "status", "default": "active"},
            "ufw_default_incoming": {"type": "policy", "direction": "incoming", "default": "deny"},
            "ufw_default_outgoing": {"type": "policy", "direction": "outgoing", "default": "allow"},
            "ufw_default_forward": {"type": "policy", "direction": "forward", "default": "deny"},
            "ufw_default_routed": {"type": "policy", "direction": "routed", "default": "deny"},
            
            # Logging configuration
            "ufw_logging": {"type": "config", "setting": "LOGLEVEL", "default": "low"},
            
            # IPv6 support
            "ufw_ipv6": {"type": "config", "setting": "IPV6", "default": "yes"},
            
            # Service-specific rules (common secure services)
            "ufw_allow_ssh": {"type": "rule", "rule": "allow 22/tcp", "default": "enabled"},
            "ufw_allow_http": {"type": "rule", "rule": "allow 80/tcp", "default": "disabled"},
            "ufw_allow_https": {"type": "rule", "rule": "allow 443/tcp", "default": "disabled"},
            "ufw_allow_dns": {"type": "rule", "rule": "allow 53", "default": "disabled"},
            "ufw_allow_ntp": {"type": "rule", "rule": "allow 123/udp", "default": "disabled"},
            
            # Security rules
            "ufw_deny_telnet": {"type": "rule", "rule": "deny 23/tcp", "default": "enabled"},
            "ufw_deny_ftp": {"type": "rule", "rule": "deny 21/tcp", "default": "enabled"},
            "ufw_deny_tftp": {"type": "rule", "rule": "deny 69/udp", "default": "enabled"},
            "ufw_deny_finger": {"type": "rule", "rule": "deny 79/tcp", "default": "enabled"},
            "ufw_deny_pop3": {"type": "rule", "rule": "deny 110/tcp", "default": "enabled"},
            "ufw_deny_imap": {"type": "rule", "rule": "deny 143/tcp", "default": "enabled"},
            "ufw_deny_snmp": {"type": "rule", "rule": "deny 161/udp", "default": "enabled"},
            "ufw_deny_ldap": {"type": "rule", "rule": "deny 389/tcp", "default": "enabled"},
            "ufw_deny_smb": {"type": "rule", "rule": "deny 445/tcp", "default": "enabled"},
            "ufw_deny_rpc": {"type": "rule", "rule": "deny 111", "default": "enabled"},
            "ufw_deny_nfs": {"type": "rule", "rule": "deny 2049/tcp", "default": "enabled"},
            
            # Rate limiting for SSH
            "ufw_limit_ssh": {"type": "rule", "rule": "limit 22/tcp", "default": "enabled"},
        }
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported firewall parameters."""
        return list(self.supported_parameters.keys())
    
    def is_parameter_supported(self, param_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return param_id in self.supported_parameters
    
    def get_firewall_setting(self, param_id: str) -> Optional[str]:
        """Get current value of firewall setting."""
        if not self.is_parameter_supported(param_id):
            return None
        
        param_info = self.supported_parameters[param_id]
        param_type = param_info["type"]
        
        try:
            if param_type == "status":
                return self._get_ufw_status()
            elif param_type == "policy":
                return self._get_ufw_policy(param_info["direction"])
            elif param_type == "config":
                return self._get_ufw_config_setting(param_info["setting"])
            elif param_type == "rule":
                return self._check_ufw_rule_exists(param_info["rule"])
            
            return None
            
        except Exception:
            return None
    
    def set_firewall_setting(self, param_id: str, value: str) -> bool:
        """Set firewall setting value."""
        if not self.is_parameter_supported(param_id):
            return False
        
        param_info = self.supported_parameters[param_id]
        param_type = param_info["type"]
        
        try:
            if param_type == "status":
                return self._set_ufw_status(value)
            elif param_type == "policy":
                return self._set_ufw_policy(param_info["direction"], value)
            elif param_type == "config":
                return self._set_ufw_config_setting(param_info["setting"], value)
            elif param_type == "rule":
                if value.lower() == "enabled":
                    return self._add_ufw_rule(param_info["rule"])
                else:
                    return self._remove_ufw_rule(param_info["rule"])
            
            return False
            
        except Exception:
            return False
    
    def apply_firewall_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply firewall hardening for specified parameters."""
        results = []
        
        for param in parameters:
            if not self.is_parameter_supported(param.id):
                continue
            
            result = HardeningResult(
                parameter_id=param.id,
                success=False,
                timestamp=None
            )
            
            try:
                # Get current value
                current_value = self.get_firewall_setting(param.id)
                result.previous_value = current_value
                
                # Apply new value
                target_value = str(param.target_value)
                success = self.set_firewall_setting(param.id, target_value)
                
                if success:
                    result.success = True
                    result.applied_value = target_value
                    result.requires_reboot = False
                else:
                    result.error_message = f"Failed to set {param.id} to {target_value}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def backup_firewall_configuration(self, param_id: str) -> Optional[ParameterBackup]:
        """Create backup of firewall configuration."""
        try:
            current_value = self.get_firewall_setting(param_id)
            if current_value is None:
                return None
            
            param_info = self.supported_parameters[param_id]
            
            return ParameterBackup(
                parameter_id=param_id,
                original_value=current_value,
                restore_method="firewall",
                restore_data={
                    "param_id": param_id,
                    "value": current_value,
                    "type": param_info["type"],
                    "rule": param_info.get("rule"),
                    "direction": param_info.get("direction"),
                    "setting": param_info.get("setting")
                }
            )
            
        except Exception:
            return None
    
    def restore_firewall_configuration(self, backup: ParameterBackup) -> bool:
        """Restore firewall configuration from backup."""
        try:
            param_id = backup.restore_data["param_id"]
            value = backup.restore_data["value"]
            
            return self.set_firewall_setting(param_id, value)
            
        except Exception:
            return False
    
    def _get_ufw_status(self) -> str:
        """Get UFW status."""
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                if "Status: active" in result.stdout:
                    return "active"
                elif "Status: inactive" in result.stdout:
                    return "inactive"
            
            return "unknown"
            
        except Exception:
            return "unknown"
    
    def _set_ufw_status(self, status: str) -> bool:
        """Set UFW status (enable/disable)."""
        try:
            if status.lower() == "active":
                result = subprocess.run(
                    ["ufw", "--force", "enable"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            elif status.lower() == "inactive":
                result = subprocess.run(
                    ["ufw", "--force", "disable"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                return False
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _get_ufw_policy(self, direction: str) -> str:
        """Get UFW default policy for direction."""
        try:
            result = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if f"Default: deny ({direction})" in line.lower():
                        return "deny"
                    elif f"Default: allow ({direction})" in line.lower():
                        return "allow"
                    elif f"Default: reject ({direction})" in line.lower():
                        return "reject"
            
            return "unknown"
            
        except Exception:
            return "unknown"
    
    def _set_ufw_policy(self, direction: str, policy: str) -> bool:
        """Set UFW default policy for direction."""
        try:
            result = subprocess.run(
                ["ufw", "--force", "default", policy, direction],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _get_ufw_config_setting(self, setting: str) -> Optional[str]:
        """Get UFW configuration setting."""
        if not self.ufw_config.exists():
            return None
        
        try:
            with open(self.ufw_config, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{setting}="):
                        return line.split('=', 1)[1].strip('"\'')
            return None
        except Exception:
            return None
    
    def _set_ufw_config_setting(self, setting: str, value: str) -> bool:
        """Set UFW configuration setting."""
        try:
            # Ensure directory exists
            self.ufw_config_dir.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            lines = []
            if self.ufw_config.exists():
                with open(self.ufw_config, 'r') as f:
                    lines = f.readlines()
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                if line.strip().startswith(f"{setting}="):
                    lines[i] = f"{setting}={value}\n"
                    setting_found = True
                    break
            
            if not setting_found:
                lines.append(f"{setting}={value}\n")
            
            # Write updated config
            with open(self.ufw_config, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def _check_ufw_rule_exists(self, rule: str) -> str:
        """Check if UFW rule exists."""
        try:
            result = subprocess.run(
                ["ufw", "status", "numbered"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse rule to check for existence
                rule_parts = rule.split()
                action = rule_parts[0]  # allow, deny, limit
                
                if len(rule_parts) >= 2:
                    port_proto = rule_parts[1]  # e.g., "22/tcp", "80/tcp"
                    
                    # Check if rule exists in output
                    for line in result.stdout.split('\n'):
                        if action.upper() in line and port_proto in line:
                            return "enabled"
            
            return "disabled"
            
        except Exception:
            return "disabled"
    
    def _add_ufw_rule(self, rule: str) -> bool:
        """Add UFW rule."""
        try:
            # Check if rule already exists
            if self._check_ufw_rule_exists(rule) == "enabled":
                return True
            
            # Add the rule
            cmd = ["ufw"] + rule.split()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _remove_ufw_rule(self, rule: str) -> bool:
        """Remove UFW rule."""
        try:
            # Parse rule to find and delete
            rule_parts = rule.split()
            if len(rule_parts) >= 2:
                action = rule_parts[0]
                port_proto = rule_parts[1]
                
                # Delete the rule
                cmd = ["ufw", "--force", "delete", action, port_proto]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                return result.returncode == 0
            
            return False
            
        except Exception:
            return False
    
    def validate_firewall_parameter(self, param_id: str, value: str) -> Tuple[bool, str]:
        """Validate firewall parameter and value."""
        if not self.is_parameter_supported(param_id):
            return False, f"Parameter {param_id} is not supported"
        
        param_info = self.supported_parameters[param_id]
        param_type = param_info["type"]
        
        try:
            if param_type == "status":
                if value.lower() not in ["active", "inactive"]:
                    return False, "Status must be 'active' or 'inactive'"
            
            elif param_type == "policy":
                if value.lower() not in ["allow", "deny", "reject"]:
                    return False, "Policy must be 'allow', 'deny', or 'reject'"
            
            elif param_type == "config":
                setting = param_info["setting"]
                if setting == "LOGLEVEL":
                    if value.lower() not in ["off", "low", "medium", "high", "full"]:
                        return False, "Log level must be off, low, medium, high, or full"
                elif setting == "IPV6":
                    if value.lower() not in ["yes", "no"]:
                        return False, "IPv6 setting must be 'yes' or 'no'"
            
            elif param_type == "rule":
                if value.lower() not in ["enabled", "disabled"]:
                    return False, "Rule value must be 'enabled' or 'disabled'"
            
            return True, "Valid"
            
        except Exception:
            return False, f"Invalid value format: {value}"
    
    def get_current_config(self) -> Dict[str, str]:
        """Get current firewall configuration."""
        config = {}
        
        for param_id in self.supported_parameters:
            value = self.get_firewall_setting(param_id)
            if value is not None:
                config[param_id] = value
        
        return config
    
    def check_compliance(self, hardening_level: str = "basic") -> Dict[str, Dict]:
        """Check compliance of current firewall configuration."""
        compliance = {}
        
        for param_id, param_info in self.supported_parameters.items():
            current_value = self.get_firewall_setting(param_id)
            expected_value = param_info["default"]
            
            compliance[param_id] = {
                "current": current_value,
                "expected": expected_value,
                "compliant": current_value == expected_value,
                "type": param_info["type"]
            }
        
        return compliance
    
    def reset_firewall(self) -> bool:
        """Reset UFW to default state."""
        try:
            result = subprocess.run(
                ["ufw", "--force", "reset"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def get_firewall_status(self) -> Dict[str, any]:
        """Get comprehensive firewall status."""
        status = {
            "enabled": False,
            "default_incoming": "unknown",
            "default_outgoing": "unknown",
            "default_forward": "unknown",
            "rules_count": 0,
            "logging": "unknown"
        }
        
        try:
            # Get basic status
            result = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse status
                if "Status: active" in output:
                    status["enabled"] = True
                
                # Parse default policies
                for line in output.split('\n'):
                    if "Default: " in line:
                        if "(incoming)" in line:
                            status["default_incoming"] = line.split()[1]
                        elif "(outgoing)" in line:
                            status["default_outgoing"] = line.split()[1]
                        elif "(forward)" in line:
                            status["default_forward"] = line.split()[1]
                    elif "Logging: " in line:
                        status["logging"] = line.split()[1]
                
                # Count rules
                numbered_result = subprocess.run(
                    ["ufw", "status", "numbered"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if numbered_result.returncode == 0:
                    lines = [line for line in numbered_result.stdout.split('\n') if line.strip() and '[' in line]
                    status["rules_count"] = len(lines)
        
        except Exception:
            pass
        
        return status