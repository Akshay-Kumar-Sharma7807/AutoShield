"""Linux PAM manager for authentication policy hardening."""

import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import HardeningResult, Parameter, ParameterBackup


class LinuxPAMManager:
    """Manager for Linux PAM (Pluggable Authentication Modules) hardening."""
    
    def __init__(self):
        """Initialize PAM manager."""
        self.pam_dir = Path("/etc/pam.d")
        self.security_dir = Path("/etc/security")
        self.login_defs = Path("/etc/login.defs")
        
        # PAM configuration files to manage
        self.pam_files = {
            "common-auth": self.pam_dir / "common-auth",
            "common-account": self.pam_dir / "common-account", 
            "common-password": self.pam_dir / "common-password",
            "common-session": self.pam_dir / "common-session",
            "login": self.pam_dir / "login",
            "sshd": self.pam_dir / "sshd",
            "sudo": self.pam_dir / "sudo"
        }
        
        # Security configuration files
        self.security_files = {
            "pwquality.conf": self.security_dir / "pwquality.conf",
            "faillock.conf": self.security_dir / "faillock.conf",
            "limits.conf": self.security_dir / "limits.conf"
        }
        
        # Supported PAM parameters from Annexure-B
        self.supported_parameters = {
            # Password quality parameters
            "pam_password_minlen": {"file": "pwquality.conf", "setting": "minlen", "default": "12"},
            "pam_password_minclass": {"file": "pwquality.conf", "setting": "minclass", "default": "3"},
            "pam_password_maxrepeat": {"file": "pwquality.conf", "setting": "maxrepeat", "default": "2"},
            "pam_password_dcredit": {"file": "pwquality.conf", "setting": "dcredit", "default": "-1"},
            "pam_password_ucredit": {"file": "pwquality.conf", "setting": "ucredit", "default": "-1"},
            "pam_password_lcredit": {"file": "pwquality.conf", "setting": "lcredit", "default": "-1"},
            "pam_password_ocredit": {"file": "pwquality.conf", "setting": "ocredit", "default": "-1"},
            
            # Account lockout parameters
            "pam_faillock_deny": {"file": "faillock.conf", "setting": "deny", "default": "5"},
            "pam_faillock_unlock_time": {"file": "faillock.conf", "setting": "unlock_time", "default": "900"},
            "pam_faillock_fail_interval": {"file": "faillock.conf", "setting": "fail_interval", "default": "900"},
            
            # Login parameters
            "login_max_tries": {"file": "login.defs", "setting": "LOGIN_RETRIES", "default": "3"},
            "login_timeout": {"file": "login.defs", "setting": "LOGIN_TIMEOUT", "default": "60"},
            "pass_max_days": {"file": "login.defs", "setting": "PASS_MAX_DAYS", "default": "90"},
            "pass_min_days": {"file": "login.defs", "setting": "PASS_MIN_DAYS", "default": "1"},
            "pass_warn_age": {"file": "login.defs", "setting": "PASS_WARN_AGE", "default": "7"},
            
            # Session limits
            "pam_limits_maxlogins": {"file": "limits.conf", "setting": "* hard maxlogins", "default": "10"},
            "pam_limits_core": {"file": "limits.conf", "setting": "* hard core", "default": "0"},
        }
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported PAM parameters."""
        return list(self.supported_parameters.keys())
    
    def is_parameter_supported(self, param_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return param_id in self.supported_parameters
    
    def get_pam_setting(self, param_id: str) -> Optional[str]:
        """Get current value of PAM setting."""
        if not self.is_parameter_supported(param_id):
            return None
        
        param_info = self.supported_parameters[param_id]
        config_file = param_info["file"]
        setting = param_info["setting"]
        
        try:
            if config_file == "pwquality.conf":
                return self._read_pwquality_setting(setting)
            elif config_file == "faillock.conf":
                return self._read_faillock_setting(setting)
            elif config_file == "login.defs":
                return self._read_login_defs_setting(setting)
            elif config_file == "limits.conf":
                return self._read_limits_setting(setting)
            
            return None
            
        except Exception:
            return None
    
    def set_pam_setting(self, param_id: str, value: str) -> bool:
        """Set PAM setting value."""
        if not self.is_parameter_supported(param_id):
            return False
        
        param_info = self.supported_parameters[param_id]
        config_file = param_info["file"]
        setting = param_info["setting"]
        
        try:
            if config_file == "pwquality.conf":
                return self._write_pwquality_setting(setting, value)
            elif config_file == "faillock.conf":
                return self._write_faillock_setting(setting, value)
            elif config_file == "login.defs":
                return self._write_login_defs_setting(setting, value)
            elif config_file == "limits.conf":
                return self._write_limits_setting(setting, value)
            
            return False
            
        except Exception:
            return False
    
    def apply_pam_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply PAM hardening for specified parameters."""
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
                current_value = self.get_pam_setting(param.id)
                result.previous_value = current_value
                
                # Apply new value
                target_value = str(param.target_value)
                success = self.set_pam_setting(param.id, target_value)
                
                if success:
                    result.success = True
                    result.applied_value = target_value
                else:
                    result.error_message = f"Failed to set {param.id} to {target_value}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def backup_pam_configuration(self, param_id: str) -> Optional[ParameterBackup]:
        """Create backup of PAM configuration."""
        try:
            current_value = self.get_pam_setting(param_id)
            if current_value is None:
                return None
            
            param_info = self.supported_parameters[param_id]
            
            return ParameterBackup(
                parameter_id=param_id,
                original_value=current_value,
                restore_method="pam",
                restore_data={
                    "param_id": param_id,
                    "value": current_value,
                    "file": param_info["file"],
                    "setting": param_info["setting"]
                }
            )
            
        except Exception:
            return None
    
    def restore_pam_configuration(self, backup: ParameterBackup) -> bool:
        """Restore PAM configuration from backup."""
        try:
            param_id = backup.restore_data["param_id"]
            value = backup.restore_data["value"]
            
            return self.set_pam_setting(param_id, value)
            
        except Exception:
            return False
    
    def _read_pwquality_setting(self, setting: str) -> Optional[str]:
        """Read setting from pwquality.conf."""
        config_file = self.security_files["pwquality.conf"]
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{setting} =") or line.startswith(f"{setting}="):
                        return line.split('=', 1)[1].strip()
            return None
        except Exception:
            return None
    
    def _write_pwquality_setting(self, setting: str, value: str) -> bool:
        """Write setting to pwquality.conf."""
        config_file = self.security_files["pwquality.conf"]
        
        try:
            # Ensure directory exists
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            lines = []
            if config_file.exists():
                with open(config_file, 'r') as f:
                    lines = f.readlines()
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                if line.strip().startswith(f"{setting} =") or line.strip().startswith(f"{setting}="):
                    lines[i] = f"{setting} = {value}\n"
                    setting_found = True
                    break
            
            if not setting_found:
                lines.append(f"{setting} = {value}\n")
            
            # Write updated config
            with open(config_file, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def _read_faillock_setting(self, setting: str) -> Optional[str]:
        """Read setting from faillock.conf."""
        config_file = self.security_files["faillock.conf"]
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{setting} =") or line.startswith(f"{setting}="):
                        return line.split('=', 1)[1].strip()
            return None
        except Exception:
            return None
    
    def _write_faillock_setting(self, setting: str, value: str) -> bool:
        """Write setting to faillock.conf."""
        config_file = self.security_files["faillock.conf"]
        
        try:
            # Ensure directory exists
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            lines = []
            if config_file.exists():
                with open(config_file, 'r') as f:
                    lines = f.readlines()
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                if line.strip().startswith(f"{setting} =") or line.strip().startswith(f"{setting}="):
                    lines[i] = f"{setting} = {value}\n"
                    setting_found = True
                    break
            
            if not setting_found:
                lines.append(f"{setting} = {value}\n")
            
            # Write updated config
            with open(config_file, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def _read_login_defs_setting(self, setting: str) -> Optional[str]:
        """Read setting from login.defs."""
        if not self.login_defs.exists():
            return None
        
        try:
            with open(self.login_defs, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(setting) and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            return None
        except Exception:
            return None
    
    def _write_login_defs_setting(self, setting: str, value: str) -> bool:
        """Write setting to login.defs."""
        try:
            # Read existing config
            lines = []
            if self.login_defs.exists():
                with open(self.login_defs, 'r') as f:
                    lines = f.readlines()
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(setting) and not stripped.startswith('#'):
                    lines[i] = f"{setting}\t{value}\n"
                    setting_found = True
                    break
            
            if not setting_found:
                lines.append(f"{setting}\t{value}\n")
            
            # Write updated config
            with open(self.login_defs, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def _read_limits_setting(self, setting: str) -> Optional[str]:
        """Read setting from limits.conf."""
        config_file = self.security_files["limits.conf"]
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(setting.split()[0]) and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[3]
            return None
        except Exception:
            return None
    
    def _write_limits_setting(self, setting: str, value: str) -> bool:
        """Write setting to limits.conf."""
        config_file = self.security_files["limits.conf"]
        
        try:
            # Ensure directory exists
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            lines = []
            if config_file.exists():
                with open(config_file, 'r') as f:
                    lines = f.readlines()
            
            # Parse setting (e.g., "* hard maxlogins")
            setting_parts = setting.split()
            if len(setting_parts) < 3:
                return False
            
            domain, type_limit, item = setting_parts[0], setting_parts[1], setting_parts[2]
            
            # Update or add setting
            setting_found = False
            for i, line in enumerate(lines):
                stripped = line.strip()
                if not stripped.startswith('#') and stripped:
                    parts = stripped.split()
                    if len(parts) >= 4 and parts[0] == domain and parts[1] == type_limit and parts[2] == item:
                        lines[i] = f"{domain}\t{type_limit}\t{item}\t{value}\n"
                        setting_found = True
                        break
            
            if not setting_found:
                lines.append(f"{domain}\t{type_limit}\t{item}\t{value}\n")
            
            # Write updated config
            with open(config_file, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def validate_pam_parameter(self, param_id: str, value: str) -> Tuple[bool, str]:
        """Validate PAM parameter and value."""
        if not self.is_parameter_supported(param_id):
            return False, f"Parameter {param_id} is not supported"
        
        try:
            # Basic validation based on parameter type
            if param_id.startswith("pam_password_"):
                if not value.isdigit():
                    return False, "Password policy values must be numeric"
                
                int_val = int(value)
                if param_id == "pam_password_minlen" and int_val < 8:
                    return False, "Minimum password length should be at least 8"
                
            elif param_id.startswith("pam_faillock_"):
                if not value.isdigit():
                    return False, "Faillock values must be numeric"
                
                int_val = int(value)
                if int_val < 0:
                    return False, "Faillock values cannot be negative"
                
            elif param_id.startswith("login_") or param_id.startswith("pass_"):
                if not value.isdigit():
                    return False, "Login/password values must be numeric"
                
                int_val = int(value)
                if int_val < 0:
                    return False, "Login/password values cannot be negative"
            
            return True, "Valid"
            
        except ValueError:
            return False, f"Invalid value format: {value}"
    
    def get_current_config(self) -> Dict[str, str]:
        """Get current PAM configuration."""
        config = {}
        
        for param_id in self.supported_parameters:
            value = self.get_pam_setting(param_id)
            if value is not None:
                config[param_id] = value
        
        return config
    
    def check_compliance(self, hardening_level: str = "basic") -> Dict[str, Dict]:
        """Check compliance of current PAM configuration."""
        compliance = {}
        
        for param_id, param_info in self.supported_parameters.items():
            current_value = self.get_pam_setting(param_id)
            expected_value = param_info["default"]
            
            compliance[param_id] = {
                "current": current_value,
                "expected": expected_value,
                "compliant": current_value == expected_value,
                "file": param_info["file"]
            }
        
        return compliance