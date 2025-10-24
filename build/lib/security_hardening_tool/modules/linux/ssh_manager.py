"""Linux SSH manager for SSH daemon hardening."""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import HardeningResult, Parameter, ParameterBackup


class LinuxSSHManager:
    """Manager for Linux SSH daemon hardening."""
    
    def __init__(self):
        """Initialize SSH manager."""
        self.sshd_config = Path("/etc/ssh/sshd_config")
        self.ssh_config_dir = Path("/etc/ssh")
        
        # Supported SSH parameters from Annexure-B (20+ settings)
        self.supported_parameters = {
            # Protocol and encryption settings
            "ssh_protocol": {"default": "2", "type": "string"},
            "ssh_port": {"default": "22", "type": "int"},
            "ssh_address_family": {"default": "inet", "type": "string"},
            
            # Authentication settings
            "ssh_permit_root_login": {"default": "no", "type": "string"},
            "ssh_password_authentication": {"default": "no", "type": "string"},
            "ssh_pubkey_authentication": {"default": "yes", "type": "string"},
            "ssh_permit_empty_passwords": {"default": "no", "type": "string"},
            "ssh_challenge_response_authentication": {"default": "no", "type": "string"},
            "ssh_kerberos_authentication": {"default": "no", "type": "string"},
            "ssh_gssapi_authentication": {"default": "no", "type": "string"},
            "ssh_hostbased_authentication": {"default": "no", "type": "string"},
            
            # Connection and session settings
            "ssh_max_auth_tries": {"default": "3", "type": "int"},
            "ssh_max_sessions": {"default": "4", "type": "int"},
            "ssh_max_startups": {"default": "10:30:100", "type": "string"},
            "ssh_login_grace_time": {"default": "60", "type": "int"},
            "ssh_client_alive_interval": {"default": "300", "type": "int"},
            "ssh_client_alive_count_max": {"default": "2", "type": "int"},
            
            # Security settings
            "ssh_permit_user_environment": {"default": "no", "type": "string"},
            "ssh_allow_agent_forwarding": {"default": "no", "type": "string"},
            "ssh_allow_tcp_forwarding": {"default": "no", "type": "string"},
            "ssh_gateway_ports": {"default": "no", "type": "string"},
            "ssh_x11_forwarding": {"default": "no", "type": "string"},
            "ssh_permit_tunnel": {"default": "no", "type": "string"},
            
            # Logging and banner
            "ssh_log_level": {"default": "INFO", "type": "string"},
            "ssh_syslog_facility": {"default": "AUTHPRIV", "type": "string"},
            "ssh_banner": {"default": "/etc/issue.net", "type": "string"},
            
            # Cipher and MAC settings
            "ssh_ciphers": {"default": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr", "type": "string"},
            "ssh_macs": {"default": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512", "type": "string"},
            "ssh_kex_algorithms": {"default": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512", "type": "string"},
            
            # Additional security settings
            "ssh_ignore_rhosts": {"default": "yes", "type": "string"},
            "ssh_ignore_user_known_hosts": {"default": "yes", "type": "string"},
            "ssh_strict_modes": {"default": "yes", "type": "string"},
            "ssh_use_privilege_separation": {"default": "sandbox", "type": "string"},
            "ssh_compression": {"default": "no", "type": "string"},
        }
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported SSH parameters."""
        return list(self.supported_parameters.keys())
    
    def is_parameter_supported(self, param_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return param_id in self.supported_parameters
    
    def get_ssh_setting(self, param_id: str) -> Optional[str]:
        """Get current value of SSH setting."""
        if not self.is_parameter_supported(param_id):
            return None
        
        if not self.sshd_config.exists():
            return None
        
        # Convert parameter ID to SSH config directive
        directive = self._param_to_directive(param_id)
        
        try:
            with open(self.sshd_config, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # Match directive (case-insensitive)
                    if line.lower().startswith(directive.lower()):
                        parts = line.split(None, 1)
                        if len(parts) >= 2:
                            return parts[1]
            
            return None
            
        except Exception:
            return None
    
    def set_ssh_setting(self, param_id: str, value: str) -> bool:
        """Set SSH setting value."""
        if not self.is_parameter_supported(param_id):
            return False
        
        directive = self._param_to_directive(param_id)
        
        try:
            # Create backup
            backup_path = self.sshd_config.with_suffix('.bak')
            shutil.copy2(self.sshd_config, backup_path)
            
            # Read existing config
            lines = []
            if self.sshd_config.exists():
                with open(self.sshd_config, 'r') as f:
                    lines = f.readlines()
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.lower().startswith(directive.lower()) and not stripped.startswith('#'):
                    lines[i] = f"{directive} {value}\n"
                    setting_found = True
                    break
            
            if not setting_found:
                lines.append(f"{directive} {value}\n")
            
            # Write updated config
            with open(self.sshd_config, 'w') as f:
                f.writelines(lines)
            
            # Validate configuration
            if not self._validate_sshd_config():
                # Restore backup if validation fails
                shutil.copy2(backup_path, self.sshd_config)
                return False
            
            return True
            
        except Exception:
            return False
    
    def apply_ssh_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply SSH hardening for specified parameters."""
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
                current_value = self.get_ssh_setting(param.id)
                result.previous_value = current_value
                
                # Apply new value
                target_value = str(param.target_value)
                success = self.set_ssh_setting(param.id, target_value)
                
                if success:
                    result.success = True
                    result.applied_value = target_value
                    result.requires_reboot = False  # SSH reload is sufficient
                else:
                    result.error_message = f"Failed to set {param.id} to {target_value}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def backup_ssh_configuration(self, param_id: str) -> Optional[ParameterBackup]:
        """Create backup of SSH configuration."""
        try:
            current_value = self.get_ssh_setting(param_id)
            if current_value is None:
                return None
            
            return ParameterBackup(
                parameter_id=param_id,
                original_value=current_value,
                restore_method="ssh",
                restore_data={
                    "param_id": param_id,
                    "value": current_value,
                    "directive": self._param_to_directive(param_id)
                }
            )
            
        except Exception:
            return None
    
    def restore_ssh_configuration(self, backup: ParameterBackup) -> bool:
        """Restore SSH configuration from backup."""
        try:
            param_id = backup.restore_data["param_id"]
            value = backup.restore_data["value"]
            
            return self.set_ssh_setting(param_id, value)
            
        except Exception:
            return False
    
    def _param_to_directive(self, param_id: str) -> str:
        """Convert parameter ID to SSH config directive."""
        # Remove ssh_ prefix and convert to proper case
        directive = param_id.replace("ssh_", "")
        
        # Handle special cases
        directive_map = {
            "permit_root_login": "PermitRootLogin",
            "password_authentication": "PasswordAuthentication",
            "pubkey_authentication": "PubkeyAuthentication",
            "permit_empty_passwords": "PermitEmptyPasswords",
            "challenge_response_authentication": "ChallengeResponseAuthentication",
            "kerberos_authentication": "KerberosAuthentication",
            "gssapi_authentication": "GSSAPIAuthentication",
            "hostbased_authentication": "HostbasedAuthentication",
            "max_auth_tries": "MaxAuthTries",
            "max_sessions": "MaxSessions",
            "max_startups": "MaxStartups",
            "login_grace_time": "LoginGraceTime",
            "client_alive_interval": "ClientAliveInterval",
            "client_alive_count_max": "ClientAliveCountMax",
            "permit_user_environment": "PermitUserEnvironment",
            "allow_agent_forwarding": "AllowAgentForwarding",
            "allow_tcp_forwarding": "AllowTcpForwarding",
            "gateway_ports": "GatewayPorts",
            "x11_forwarding": "X11Forwarding",
            "permit_tunnel": "PermitTunnel",
            "log_level": "LogLevel",
            "syslog_facility": "SyslogFacility",
            "banner": "Banner",
            "ciphers": "Ciphers",
            "macs": "MACs",
            "kex_algorithms": "KexAlgorithms",
            "ignore_rhosts": "IgnoreRhosts",
            "ignore_user_known_hosts": "IgnoreUserKnownHosts",
            "strict_modes": "StrictModes",
            "use_privilege_separation": "UsePrivilegeSeparation",
            "compression": "Compression",
            "protocol": "Protocol",
            "port": "Port",
            "address_family": "AddressFamily"
        }
        
        return directive_map.get(directive, directive.title())
    
    def _validate_sshd_config(self) -> bool:
        """Validate SSH daemon configuration."""
        try:
            result = subprocess.run(
                ["sshd", "-t", "-f", str(self.sshd_config)],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def validate_ssh_parameter(self, param_id: str, value: str) -> Tuple[bool, str]:
        """Validate SSH parameter and value."""
        if not self.is_parameter_supported(param_id):
            return False, f"Parameter {param_id} is not supported"
        
        param_info = self.supported_parameters[param_id]
        param_type = param_info["type"]
        
        try:
            # Type validation
            if param_type == "int":
                int_val = int(value)
                if int_val < 0:
                    return False, f"Value {value} cannot be negative"
                
                # Specific validations
                if param_id == "ssh_port" and (int_val < 1 or int_val > 65535):
                    return False, "Port must be between 1 and 65535"
                elif param_id == "ssh_max_auth_tries" and int_val < 1:
                    return False, "MaxAuthTries must be at least 1"
                elif param_id == "ssh_login_grace_time" and int_val < 1:
                    return False, "LoginGraceTime must be at least 1"
            
            elif param_type == "string":
                # Boolean-like string validation
                if param_id.endswith(("_authentication", "_forwarding", "_login")) or param_id in ["ssh_permit_empty_passwords", "ssh_permit_user_environment", "ssh_gateway_ports", "ssh_permit_tunnel", "ssh_ignore_rhosts", "ssh_ignore_user_known_hosts", "ssh_strict_modes", "ssh_compression"]:
                    if value.lower() not in ["yes", "no"]:
                        return False, f"Value must be 'yes' or 'no', got '{value}'"
                
                # Protocol validation
                if param_id == "ssh_protocol" and value not in ["1", "2", "1,2"]:
                    return False, "Protocol must be '1', '2', or '1,2'"
                
                # Log level validation
                if param_id == "ssh_log_level" and value.upper() not in ["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"]:
                    return False, "Invalid log level"
                
                # Address family validation
                if param_id == "ssh_address_family" and value.lower() not in ["any", "inet", "inet6"]:
                    return False, "AddressFamily must be 'any', 'inet', or 'inet6'"
            
            return True, "Valid"
            
        except ValueError:
            return False, f"Invalid value format: {value}"
    
    def get_current_config(self) -> Dict[str, str]:
        """Get current SSH configuration."""
        config = {}
        
        for param_id in self.supported_parameters:
            value = self.get_ssh_setting(param_id)
            if value is not None:
                config[param_id] = value
        
        return config
    
    def check_compliance(self, hardening_level: str = "basic") -> Dict[str, Dict]:
        """Check compliance of current SSH configuration."""
        compliance = {}
        
        for param_id, param_info in self.supported_parameters.items():
            current_value = self.get_ssh_setting(param_id)
            expected_value = param_info["default"]
            
            compliance[param_id] = {
                "current": current_value,
                "expected": expected_value,
                "compliant": current_value == expected_value,
                "type": param_info["type"]
            }
        
        return compliance
    
    def reload_ssh_service(self) -> bool:
        """Reload SSH service to apply configuration changes."""
        try:
            # Try systemctl first
            result = subprocess.run(
                ["systemctl", "reload", "sshd"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True
            
            # Fallback to service command
            result = subprocess.run(
                ["service", "ssh", "reload"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def test_ssh_connection(self, host: str = "localhost", port: int = 22) -> bool:
        """Test SSH connection to verify service is working."""
        try:
            result = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
                 f"{host}", "-p", str(port), "exit"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Connection should fail with authentication error, not connection error
            return "Permission denied" in result.stderr or result.returncode == 255
            
        except Exception:
            return False