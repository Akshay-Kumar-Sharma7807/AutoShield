"""Linux sysctl manager for kernel parameter hardening."""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import HardeningResult, Parameter, ParameterBackup


class LinuxSysctlManager:
    """Manager for Linux sysctl kernel parameter hardening."""
    
    def __init__(self):
        """Initialize sysctl manager."""
        self.sysctl_config_dir = Path("/etc/sysctl.d")
        self.proc_sys_dir = Path("/proc/sys")
        self.hardening_config_file = self.sysctl_config_dir / "99-security-hardening.conf"
        
        # Supported sysctl parameters from Annexure-B
        self.supported_parameters = {
            # Network security parameters
            "net.ipv4.ip_forward": {"default": "0", "category": "network"},
            "net.ipv4.conf.all.send_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.default.send_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.all.accept_source_route": {"default": "0", "category": "network"},
            "net.ipv4.conf.default.accept_source_route": {"default": "0", "category": "network"},
            "net.ipv4.conf.all.accept_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.default.accept_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.all.secure_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.default.secure_redirects": {"default": "0", "category": "network"},
            "net.ipv4.conf.all.log_martians": {"default": "1", "category": "network"},
            "net.ipv4.conf.default.log_martians": {"default": "1", "category": "network"},
            "net.ipv4.icmp_echo_ignore_broadcasts": {"default": "1", "category": "network"},
            "net.ipv4.icmp_ignore_bogus_error_responses": {"default": "1", "category": "network"},
            "net.ipv4.conf.all.rp_filter": {"default": "1", "category": "network"},
            "net.ipv4.conf.default.rp_filter": {"default": "1", "category": "network"},
            "net.ipv4.tcp_syncookies": {"default": "1", "category": "network"},
            
            # IPv6 parameters
            "net.ipv6.conf.all.accept_ra": {"default": "0", "category": "network"},
            "net.ipv6.conf.default.accept_ra": {"default": "0", "category": "network"},
            "net.ipv6.conf.all.accept_redirects": {"default": "0", "category": "network"},
            "net.ipv6.conf.default.accept_redirects": {"default": "0", "category": "network"},
            
            # Kernel security parameters
            "kernel.randomize_va_space": {"default": "2", "category": "kernel"},
            "kernel.exec-shield": {"default": "1", "category": "kernel"},
            "kernel.dmesg_restrict": {"default": "1", "category": "kernel"},
            "kernel.kptr_restrict": {"default": "2", "category": "kernel"},
            "kernel.yama.ptrace_scope": {"default": "1", "category": "kernel"},
            "kernel.perf_event_paranoid": {"default": "3", "category": "kernel"},
            
            # File system parameters
            "fs.suid_dumpable": {"default": "0", "category": "filesystem"},
            "fs.protected_hardlinks": {"default": "1", "category": "filesystem"},
            "fs.protected_symlinks": {"default": "1", "category": "filesystem"},
            
            # Virtual memory parameters
            "vm.mmap_min_addr": {"default": "65536", "category": "memory"},
        }
    
    def get_supported_parameters(self) -> List[str]:
        """Get list of supported sysctl parameters."""
        return list(self.supported_parameters.keys())
    
    def is_parameter_supported(self, param_id: str) -> bool:
        """Check if parameter is supported by this manager."""
        return param_id in self.supported_parameters
    
    def get_sysctl_value(self, param_id: str) -> Optional[str]:
        """Get current value of sysctl parameter."""
        try:
            # Try reading from /proc/sys first (current runtime value)
            proc_path = self.proc_sys_dir / param_id.replace(".", "/")
            if proc_path.exists():
                return proc_path.read_text().strip()
            
            # Fallback to sysctl command
            result = subprocess.run(
                ["sysctl", "-n", param_id],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            return None
            
        except Exception:
            return None
    
    def set_sysctl_value(self, param_id: str, value: str, persistent: bool = True) -> bool:
        """Set sysctl parameter value."""
        try:
            # Set runtime value
            result = subprocess.run(
                ["sysctl", "-w", f"{param_id}={value}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return False
            
            # Make persistent if requested
            if persistent:
                self._add_to_config_file(param_id, value)
            
            return True
            
        except Exception:
            return False
    
    def apply_sysctl_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply sysctl hardening for specified parameters."""
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
                current_value = self.get_sysctl_value(param.id)
                result.previous_value = current_value
                
                # Apply new value
                target_value = str(param.target_value)
                success = self.set_sysctl_value(param.id, target_value, persistent=True)
                
                if success:
                    result.success = True
                    result.applied_value = target_value
                else:
                    result.error_message = f"Failed to set {param.id} to {target_value}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def backup_sysctl_value(self, param_id: str) -> Optional[ParameterBackup]:
        """Create backup of sysctl parameter."""
        try:
            current_value = self.get_sysctl_value(param_id)
            if current_value is None:
                return None
            
            return ParameterBackup(
                parameter_id=param_id,
                original_value=current_value,
                restore_method="sysctl",
                restore_data={"param_id": param_id, "value": current_value}
            )
            
        except Exception:
            return None
    
    def restore_sysctl_value(self, backup: ParameterBackup) -> bool:
        """Restore sysctl parameter from backup."""
        try:
            param_id = backup.restore_data["param_id"]
            value = backup.restore_data["value"]
            
            return self.set_sysctl_value(param_id, value, persistent=True)
            
        except Exception:
            return False
    
    def _add_to_config_file(self, param_id: str, value: str) -> None:
        """Add parameter to persistent configuration file."""
        try:
            # Ensure config directory exists
            self.sysctl_config_dir.mkdir(parents=True, exist_ok=True)
            
            # Read existing config
            existing_config = {}
            if self.hardening_config_file.exists():
                with open(self.hardening_config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '=' in line:
                                key, val = line.split('=', 1)
                                existing_config[key.strip()] = val.strip()
            
            # Update config
            existing_config[param_id] = value
            
            # Write updated config
            with open(self.hardening_config_file, 'w') as f:
                f.write("# Security hardening sysctl parameters\n")
                f.write("# Generated by security hardening tool\n\n")
                
                # Group by category
                categories = {}
                for param, val in existing_config.items():
                    if param in self.supported_parameters:
                        category = self.supported_parameters[param]["category"]
                        if category not in categories:
                            categories[category] = []
                        categories[category].append((param, val))
                
                # Write by category
                for category, params in categories.items():
                    f.write(f"# {category.title()} parameters\n")
                    for param, val in sorted(params):
                        f.write(f"{param} = {val}\n")
                    f.write("\n")
            
        except Exception as e:
            raise Exception(f"Failed to update sysctl config file: {e}")
    
    def validate_sysctl_parameter(self, param_id: str, value: str) -> Tuple[bool, str]:
        """Validate sysctl parameter and value."""
        if not self.is_parameter_supported(param_id):
            return False, f"Parameter {param_id} is not supported"
        
        # Check if parameter exists in /proc/sys
        proc_path = self.proc_sys_dir / param_id.replace(".", "/")
        if not proc_path.exists():
            return False, f"Parameter {param_id} does not exist on this system"
        
        # Basic value validation
        try:
            # Most sysctl values are integers
            if value.isdigit():
                int_val = int(value)
                if int_val < 0:
                    return False, f"Value {value} cannot be negative"
            
            # Check for reasonable ranges for specific parameters
            if param_id == "vm.mmap_min_addr":
                if int(value) < 4096:
                    return False, "vm.mmap_min_addr should be at least 4096"
            
            elif param_id == "kernel.randomize_va_space":
                if int(value) not in [0, 1, 2]:
                    return False, "kernel.randomize_va_space must be 0, 1, or 2"
            
            elif param_id in ["kernel.perf_event_paranoid"]:
                if int(value) not in [0, 1, 2, 3]:
                    return False, f"{param_id} must be 0, 1, 2, or 3"
            
            return True, "Valid"
            
        except ValueError:
            return False, f"Invalid value format: {value}"
    
    def get_current_config(self) -> Dict[str, str]:
        """Get current sysctl configuration."""
        config = {}
        
        for param_id in self.supported_parameters:
            value = self.get_sysctl_value(param_id)
            if value is not None:
                config[param_id] = value
        
        return config
    
    def check_compliance(self, hardening_level: str = "basic") -> Dict[str, Dict]:
        """Check compliance of current sysctl configuration."""
        compliance = {}
        
        for param_id, param_info in self.supported_parameters.items():
            current_value = self.get_sysctl_value(param_id)
            expected_value = param_info["default"]
            
            compliance[param_id] = {
                "current": current_value,
                "expected": expected_value,
                "compliant": current_value == expected_value,
                "category": param_info["category"]
            }
        
        return compliance