"""Linux auditd manager for system auditing hardening."""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import HardeningResult, Parameter, ParameterBackup


class LinuxAuditdManager:
    """Manager for Linux auditd system auditing hardening."""
    
    def __init__(self):
        """Initialize auditd manager."""
        self.audit_dir = Path("/etc/audit")
        self.auditd_conf = self.audit_dir / "auditd.conf"
        self.audit_rules = self.audit_dir / "rules.d" / "audit.rules"
        self.hardening_rules = self.audit_dir / "rules.d" / "99-security-hardening.rules"
        
        # Supported auditd parameters from Annexure-B
        self.supported_parameters = {
            # Auditd daemon configuration
            "audit_log_file": {"file": "auditd.conf", "setting": "log_file", "default": "/var/log/audit/audit.log"},
            "audit_log_format": {"file": "auditd.conf", "setting": "log_format", "default": "RAW"},
            "audit_log_group": {"file": "auditd.conf", "setting": "log_group", "default": "root"},
            "audit_priority_boost": {"file": "auditd.conf", "setting": "priority_boost", "default": "4"},
            "audit_flush": {"file": "auditd.conf", "setting": "flush", "default": "INCREMENTAL_ASYNC"},
            "audit_freq": {"file": "auditd.conf", "setting": "freq", "default": "50"},
            "audit_max_log_file": {"file": "auditd.conf", "setting": "max_log_file", "default": "100"},
            "audit_num_logs": {"file": "auditd.conf", "setting": "num_logs", "default": "10"},
            "audit_max_log_file_action": {"file": "auditd.conf", "setting": "max_log_file_action", "default": "rotate"},
            "audit_space_left": {"file": "auditd.conf", "setting": "space_left", "default": "75"},
            "audit_space_left_action": {"file": "auditd.conf", "setting": "space_left_action", "default": "email"},
            "audit_admin_space_left": {"file": "auditd.conf", "setting": "admin_space_left", "default": "50"},
            "audit_admin_space_left_action": {"file": "auditd.conf", "setting": "admin_space_left_action", "default": "halt"},
            "audit_disk_full_action": {"file": "auditd.conf", "setting": "disk_full_action", "default": "halt"},
            "audit_disk_error_action": {"file": "auditd.conf", "setting": "disk_error_action", "default": "halt"},
            
            # Audit rules for system monitoring
            "audit_time_change": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change", "description": "Time change events"},
            "audit_user_emulation": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S personality -k user-emulation", "description": "User emulation"},
            "audit_system_locale": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale", "description": "System locale changes"},
            "audit_mac_policy": {"file": "rules", "rule": "-w /etc/selinux/ -p wa -k MAC-policy", "description": "MAC policy changes"},
            "audit_login_logout": {"file": "rules", "rule": "-w /var/log/lastlog -p wa -k logins", "description": "Login/logout events"},
            "audit_session_initiation": {"file": "rules", "rule": "-w /var/run/utmp -p wa -k session", "description": "Session initiation"},
            "audit_discretionary_access_control": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod", "description": "Discretionary access control permission modification"},
            "audit_unsuccessful_unauthorized_file_access": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access", "description": "Unsuccessful unauthorized file access attempts"},
            "audit_privileged_commands": {"file": "rules", "rule": "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged", "description": "Use of privileged commands"},
            "audit_successful_file_system_mounts": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts", "description": "Successful file system mounts"},
            "audit_file_deletion": {"file": "rules", "rule": "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete", "description": "File deletion events by users"},
            "audit_sudoers": {"file": "rules", "rule": "-w /etc/sudoers -p wa -k scope", "description": "Changes to sudoers file"},
            "audit_sudo_log": {"file": "rules", "rule": "-w /var/log/sudo.log -p wa -k actions", "description": "Sudo log file changes"},
            "audit_kernel_modules": {"file": "rules", "rule": "-w /sbin/insmod -p x -k modules", "description": "Kernel module loading"},
            "audit_system_admin_actions": {"file": "rules", "rule": "-w /var/log/auth.log -p wa -k admin-actions", "description": "System administrator actions"},
        }
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported auditd parameters."""
        return list(self.supported_parameters.keys())
    
    def is_parameter_supported(self, param_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return param_id in self.supported_parameters
    
    def get_auditd_setting(self, param_id: str) -> Optional[str]:
        """Get current value of auditd setting."""
        if not self.is_parameter_supported(param_id):
            return None
        
        param_info = self.supported_parameters[param_id]
        
        try:
            if param_info["file"] == "auditd.conf":
                return self._read_auditd_conf_setting(param_info["setting"])
            elif param_info["file"] == "rules":
                return self._check_audit_rule_exists(param_info["rule"])
            
            return None
            
        except Exception:
            return None
    
    def set_auditd_setting(self, param_id: str, value: str) -> bool:
        """Set auditd setting value."""
        if not self.is_parameter_supported(param_id):
            return False
        
        param_info = self.supported_parameters[param_id]
        
        try:
            if param_info["file"] == "auditd.conf":
                return self._write_auditd_conf_setting(param_info["setting"], value)
            elif param_info["file"] == "rules":
                # For rules, value should be "enabled" or "disabled"
                if value.lower() == "enabled":
                    return self._add_audit_rule(param_info["rule"], param_info.get("description", ""))
                else:
                    return self._remove_audit_rule(param_info["rule"])
            
            return False
            
        except Exception:
            return False
    
    def apply_auditd_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply auditd hardening for specified parameters."""
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
                current_value = self.get_auditd_setting(param.id)
                result.previous_value = current_value
                
                # Apply new value
                target_value = str(param.target_value)
                success = self.set_auditd_setting(param.id, target_value)
                
                if success:
                    result.success = True
                    result.applied_value = target_value
                    result.requires_reboot = False  # auditd reload is sufficient
                else:
                    result.error_message = f"Failed to set {param.id} to {target_value}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def backup_auditd_configuration(self, param_id: str) -> Optional[ParameterBackup]:
        """Create backup of auditd configuration."""
        try:
            current_value = self.get_auditd_setting(param_id)
            if current_value is None:
                return None
            
            param_info = self.supported_parameters[param_id]
            
            return ParameterBackup(
                parameter_id=param_id,
                original_value=current_value,
                restore_method="auditd",
                restore_data={
                    "param_id": param_id,
                    "value": current_value,
                    "file": param_info["file"],
                    "setting": param_info.get("setting"),
                    "rule": param_info.get("rule")
                }
            )
            
        except Exception:
            return None
    
    def restore_auditd_configuration(self, backup: ParameterBackup) -> bool:
        """Restore auditd configuration from backup."""
        try:
            param_id = backup.restore_data["param_id"]
            value = backup.restore_data["value"]
            
            return self.set_auditd_setting(param_id, value)
            
        except Exception:
            return False
    
    def _read_auditd_conf_setting(self, setting: str) -> Optional[str]:
        """Read setting from auditd.conf."""
        if not self.auditd_conf.exists():
            return None
        
        try:
            with open(self.auditd_conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{setting} =") or line.startswith(f"{setting}="):
                        return line.split('=', 1)[1].strip()
            return None
        except Exception:
            return None
    
    def _write_auditd_conf_setting(self, setting: str, value: str) -> bool:
        """Write setting to auditd.conf."""
        try:
            # Ensure directory exists
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            lines = []
            if self.auditd_conf.exists():
                with open(self.auditd_conf, 'r') as f:
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
            with open(self.auditd_conf, 'w') as f:
                f.writelines(lines)
            
            return True
            
        except Exception:
            return False
    
    def _check_audit_rule_exists(self, rule: str) -> str:
        """Check if audit rule exists."""
        try:
            # Check in hardening rules file
            if self.hardening_rules.exists():
                with open(self.hardening_rules, 'r') as f:
                    content = f.read()
                    if rule in content:
                        return "enabled"
            
            # Check in main audit rules
            if self.audit_rules.exists():
                with open(self.audit_rules, 'r') as f:
                    content = f.read()
                    if rule in content:
                        return "enabled"
            
            return "disabled"
            
        except Exception:
            return "disabled"
    
    def _add_audit_rule(self, rule: str, description: str = "") -> bool:
        """Add audit rule to configuration."""
        try:
            # Ensure directory exists
            self.hardening_rules.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if rule already exists
            if self._check_audit_rule_exists(rule) == "enabled":
                return True
            
            # Add rule to hardening rules file
            with open(self.hardening_rules, 'a') as f:
                if description:
                    f.write(f"# {description}\n")
                f.write(f"{rule}\n\n")
            
            return True
            
        except Exception:
            return False
    
    def _remove_audit_rule(self, rule: str) -> bool:
        """Remove audit rule from configuration."""
        try:
            # Remove from hardening rules file
            if self.hardening_rules.exists():
                with open(self.hardening_rules, 'r') as f:
                    lines = f.readlines()
                
                # Filter out the rule and its comment
                new_lines = []
                skip_next = False
                for line in lines:
                    if skip_next and line.strip() == "":
                        skip_next = False
                        continue
                    
                    if rule in line:
                        skip_next = True
                        continue
                    
                    if skip_next and line.strip().startswith("#"):
                        continue
                    
                    skip_next = False
                    new_lines.append(line)
                
                with open(self.hardening_rules, 'w') as f:
                    f.writelines(new_lines)
            
            return True
            
        except Exception:
            return False
    
    def validate_auditd_parameter(self, param_id: str, value: str) -> Tuple[bool, str]:
        """Validate auditd parameter and value."""
        if not self.is_parameter_supported(param_id):
            return False, f"Parameter {param_id} is not supported"
        
        param_info = self.supported_parameters[param_id]
        
        try:
            if param_info["file"] == "auditd.conf":
                # Validate auditd.conf settings
                setting = param_info["setting"]
                
                if setting in ["max_log_file", "num_logs", "space_left", "admin_space_left", "freq", "priority_boost"]:
                    if not value.isdigit():
                        return False, f"{setting} must be a number"
                    
                    int_val = int(value)
                    if int_val < 0:
                        return False, f"{setting} cannot be negative"
                
                elif setting in ["max_log_file_action", "space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action"]:
                    valid_actions = ["ignore", "syslog", "email", "exec", "suspend", "single", "halt", "rotate"]
                    if value.lower() not in valid_actions:
                        return False, f"Invalid action: {value}. Must be one of: {', '.join(valid_actions)}"
                
                elif setting == "log_format":
                    if value.upper() not in ["RAW", "NOLOG"]:
                        return False, "log_format must be RAW or NOLOG"
                
                elif setting == "flush":
                    valid_flush = ["none", "incremental", "incremental_async", "data", "sync"]
                    if value.lower() not in valid_flush:
                        return False, f"Invalid flush mode: {value}"
            
            elif param_info["file"] == "rules":
                # For audit rules, value should be "enabled" or "disabled"
                if value.lower() not in ["enabled", "disabled"]:
                    return False, "Audit rule value must be 'enabled' or 'disabled'"
            
            return True, "Valid"
            
        except ValueError:
            return False, f"Invalid value format: {value}"
    
    def get_current_config(self) -> Dict[str, str]:
        """Get current auditd configuration."""
        config = {}
        
        for param_id in self.supported_parameters:
            value = self.get_auditd_setting(param_id)
            if value is not None:
                config[param_id] = value
        
        return config
    
    def check_compliance(self, hardening_level: str = "basic") -> Dict[str, Dict]:
        """Check compliance of current auditd configuration."""
        compliance = {}
        
        for param_id, param_info in self.supported_parameters.items():
            current_value = self.get_auditd_setting(param_id)
            expected_value = param_info["default"]
            
            compliance[param_id] = {
                "current": current_value,
                "expected": expected_value,
                "compliant": current_value == expected_value,
                "file": param_info["file"]
            }
        
        return compliance
    
    def reload_auditd_service(self) -> bool:
        """Reload auditd service to apply configuration changes."""
        try:
            # Reload audit rules
            result = subprocess.run(
                ["augenrules", "--load"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                # Fallback to service restart
                result = subprocess.run(
                    ["systemctl", "restart", "auditd"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def check_auditd_status(self) -> Dict[str, any]:
        """Check auditd service status."""
        status = {
            "service_running": False,
            "rules_loaded": 0,
            "log_file_exists": False,
            "disk_space_ok": True
        }
        
        try:
            # Check service status
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True,
                text=True,
                timeout=10
            )
            status["service_running"] = result.returncode == 0
            
            # Check loaded rules
            result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                status["rules_loaded"] = len([line for line in result.stdout.split('\n') if line.strip()])
            
            # Check log file
            log_file = self._read_auditd_conf_setting("log_file") or "/var/log/audit/audit.log"
            status["log_file_exists"] = Path(log_file).exists()
            
        except Exception:
            pass
        
        return status