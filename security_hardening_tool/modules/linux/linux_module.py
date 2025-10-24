"""Main Linux hardening module that integrates all Linux-specific managers."""

import os
import sys
import subprocess
from typing import List, Optional

from ...core.interfaces import HardeningModule
from ...core.models import (
    AssessmentResult, BackupData, HardeningResult, OSInfo, Parameter,
    Platform, RestoreResult, SystemError, ValidationResult
)
from .sysctl_manager import LinuxSysctlManager
from .pam_manager import LinuxPAMManager
from .ssh_manager import LinuxSSHManager
from .auditd_manager import LinuxAuditdManager
from .firewall_manager import LinuxFirewallManager


class LinuxHardeningModule(HardeningModule):
    """Main Linux hardening module that coordinates all Linux-specific managers."""
    
    def __init__(self):
        """Initialize Linux hardening module."""
        if not self._is_linux():
            raise SystemError("Linux hardening module can only be used on Linux systems")
        
        # Initialize all managers
        self.sysctl_manager = LinuxSysctlManager()
        self.pam_manager = LinuxPAMManager()
        self.ssh_manager = LinuxSSHManager()
        self.auditd_manager = LinuxAuditdManager()
        self.firewall_manager = LinuxFirewallManager()
        
        # Validate access permissions and dependencies
        self._validate_permissions()
        self._check_dependencies()
    
    def get_supported_parameters(self) -> List[Parameter]:
        """Get list of parameters supported by this module."""
        parameters = []
        
        # Add sysctl-based parameters
        sysctl_params = self.sysctl_manager.get_supported_parameters()
        for param_id in sysctl_params:
            param = self._create_parameter_from_sysctl(param_id)
            if param:
                parameters.append(param)
        
        # Add PAM-based parameters
        pam_params = self.pam_manager.get_supported_parameters()
        for param_id in pam_params:
            param = self._create_parameter_from_pam(param_id)
            if param:
                parameters.append(param)
        
        # Add SSH-based parameters
        ssh_params = self.ssh_manager.get_supported_parameters()
        for param_id in ssh_params:
            param = self._create_parameter_from_ssh(param_id)
            if param:
                parameters.append(param)
        
        # Add auditd-based parameters
        auditd_params = self.auditd_manager.get_supported_parameters()
        for param_id in auditd_params:
            param = self._create_parameter_from_auditd(param_id)
            if param:
                parameters.append(param)
        
        # Add firewall-based parameters
        firewall_params = self.firewall_manager.get_supported_parameters()
        for param_id in firewall_params:
            param = self._create_parameter_from_firewall(param_id)
            if param:
                parameters.append(param)
        
        return parameters
    
    def assess_current_state(self, parameters: List[Parameter]) -> List[AssessmentResult]:
        """Assess current state of specified parameters."""
        results = []
        
        for param in parameters:
            result = AssessmentResult(
                parameter_id=param.id,
                current_value=None,
                expected_value=param.target_value,
                compliant=False,
                severity=param.severity,
                risk_description=f"Parameter {param.id} assessment"
            )
            
            try:
                # Determine which manager handles this parameter
                current_value = self._get_current_value(param)
                result.current_value = current_value
                
                # Check compliance
                result.compliant = self._is_compliant(current_value, param.target_value)
                
                if not result.compliant:
                    result.risk_description = f"Parameter {param.id} is not compliant. Current: {current_value}, Expected: {param.target_value}"
                    result.remediation_steps = [f"Set {param.id} to {param.target_value}"]
                
            except Exception as e:
                result.risk_description = f"Failed to assess {param.id}: {str(e)}"
                result.remediation_steps = [f"Check system permissions and parameter configuration"]
            
            results.append(result)
        
        return results
    
    def apply_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply hardening configurations for specified parameters."""
        results = []
        
        # Group parameters by type for efficient processing
        sysctl_params = [p for p in parameters if self._is_sysctl_parameter(p)]
        pam_params = [p for p in parameters if self._is_pam_parameter(p)]
        ssh_params = [p for p in parameters if self._is_ssh_parameter(p)]
        auditd_params = [p for p in parameters if self._is_auditd_parameter(p)]
        firewall_params = [p for p in parameters if self._is_firewall_parameter(p)]
        
        # Apply sysctl-based hardening
        if sysctl_params:
            sysctl_results = self.sysctl_manager.apply_sysctl_hardening(sysctl_params)
            results.extend(sysctl_results)
        
        # Apply PAM-based hardening
        if pam_params:
            pam_results = self.pam_manager.apply_pam_hardening(pam_params)
            results.extend(pam_results)
        
        # Apply SSH-based hardening
        if ssh_params:
            ssh_results = self.ssh_manager.apply_ssh_hardening(ssh_params)
            results.extend(ssh_results)
        
        # Apply auditd-based hardening
        if auditd_params:
            auditd_results = self.auditd_manager.apply_auditd_hardening(auditd_params)
            results.extend(auditd_results)
        
        # Apply firewall-based hardening
        if firewall_params:
            firewall_results = self.firewall_manager.apply_firewall_hardening(firewall_params)
            results.extend(firewall_results)
        
        return results
    
    def validate_configuration(self, parameters: List[Parameter]) -> List[ValidationResult]:
        """Validate parameter configurations before applying."""
        results = []
        
        for param in parameters:
            result = ValidationResult(
                parameter_id=param.id,
                valid=True
            )
            
            try:
                # Validate parameter based on type
                if self._is_sysctl_parameter(param):
                    if not self.sysctl_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Sysctl parameter {param.id} is not supported")
                
                elif self._is_pam_parameter(param):
                    if not self.pam_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"PAM parameter {param.id} is not supported")
                
                elif self._is_ssh_parameter(param):
                    if not self.ssh_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"SSH parameter {param.id} is not supported")
                
                elif self._is_auditd_parameter(param):
                    if not self.auditd_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Auditd parameter {param.id} is not supported")
                
                elif self._is_firewall_parameter(param):
                    if not self.firewall_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Firewall parameter {param.id} is not supported")
                
                else:
                    result.valid = False
                    result.errors.append(f"Unknown parameter type for {param.id}")
                
                # Validate target value
                if param.target_value is None:
                    result.warnings.append(f"Parameter {param.id} has no target value")
                
            except Exception as e:
                result.valid = False
                result.errors.append(f"Validation error for {param.id}: {str(e)}")
            
            results.append(result)
        
        return results
    
    def create_backup(self, parameters: List[Parameter]) -> BackupData:
        """Create backup of current parameter values."""
        from datetime import datetime
        import uuid
        import hashlib
        
        backup_id = str(uuid.uuid4())
        parameter_backups = []
        
        for param in parameters:
            try:
                backup = self._create_parameter_backup(param)
                if backup:
                    parameter_backups.append(backup)
            except Exception:
                # Continue with other parameters if one fails
                pass
        
        # Calculate checksum
        backup_data_str = f"{backup_id}{datetime.now().isoformat()}{len(parameter_backups)}"
        checksum = hashlib.sha256(backup_data_str.encode()).hexdigest()
        
        return BackupData(
            backup_id=backup_id,
            timestamp=datetime.now(),
            os_info=self.get_platform_info(),
            parameters=parameter_backups,
            checksum=checksum,
            description="Linux security hardening backup"
        )
    
    def restore_backup(self, backup: BackupData) -> List[RestoreResult]:
        """Restore parameters from backup data."""
        results = []
        
        for param_backup in backup.parameters:
            result = RestoreResult(
                parameter_id=param_backup.parameter_id,
                success=False
            )
            
            try:
                # Restore based on backup method
                if param_backup.restore_method == "sysctl":
                    result.success = self.sysctl_manager.restore_sysctl_value(param_backup)
                elif param_backup.restore_method == "pam":
                    result.success = self.pam_manager.restore_pam_configuration(param_backup)
                elif param_backup.restore_method == "ssh":
                    result.success = self.ssh_manager.restore_ssh_configuration(param_backup)
                elif param_backup.restore_method == "auditd":
                    result.success = self.auditd_manager.restore_auditd_configuration(param_backup)
                elif param_backup.restore_method == "firewall":
                    result.success = self.firewall_manager.restore_firewall_configuration(param_backup)
                else:
                    result.error_message = f"Unknown restore method: {param_backup.restore_method}"
                
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_platform_info(self) -> OSInfo:
        """Get platform-specific information."""
        from ...core.os_detector import OSDetector
        
        detector = OSDetector()
        return detector.get_system_info().os_info
    
    def _validate_permissions(self) -> None:
        """Validate that we have necessary permissions for all operations."""
        errors = []
        
        # Check if running as root or with sudo
        if os.geteuid() != 0:
            # Check if sudo is available
            try:
                result = subprocess.run(['sudo', '-n', 'true'], 
                                      capture_output=True, timeout=5)
                if result.returncode != 0:
                    errors.append("Root privileges required. Run with sudo or as root.")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                errors.append("Root privileges required and sudo not available.")
        
        # Check file system access
        critical_paths = ['/etc/sysctl.d/', '/etc/pam.d/', '/etc/ssh/', '/etc/audit/']
        for path in critical_paths:
            if os.path.exists(path) and not os.access(path, os.W_OK):
                errors.append(f"Write access required to {path}")
        
        if errors:
            raise SystemError(f"Permission validation failed: {'; '.join(errors)}")
    
    def _check_dependencies(self) -> None:
        """Check for required system dependencies."""
        warnings = []
        
        # Check for required commands
        required_commands = ['sysctl', 'systemctl', 'ufw']
        for cmd in required_commands:
            try:
                subprocess.run(['which', cmd], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                warnings.append(f"Command '{cmd}' not found. Some functionality may be limited.")
        
        # Check for auditd
        try:
            subprocess.run(['systemctl', 'status', 'auditd'], 
                          capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            warnings.append("Auditd service not available. Audit hardening will be skipped.")
        
        # Log warnings but don't fail
        if warnings:
            print(f"Dependency warnings: {'; '.join(warnings)}")
    
    def _get_current_value(self, param: Parameter) -> any:
        """Get current value for a parameter."""
        if self._is_sysctl_parameter(param):
            return self.sysctl_manager.get_sysctl_value(param.id)
        
        elif self._is_pam_parameter(param):
            return self.pam_manager.get_pam_setting(param.id)
        
        elif self._is_ssh_parameter(param):
            return self.ssh_manager.get_ssh_setting(param.id)
        
        elif self._is_auditd_parameter(param):
            return self.auditd_manager.get_auditd_setting(param.id)
        
        elif self._is_firewall_parameter(param):
            return self.firewall_manager.get_firewall_setting(param.id)
        
        return None
    
    def _is_compliant(self, current_value: any, target_value: any) -> bool:
        """Check if current value is compliant with target value."""
        if current_value is None:
            return False
        
        # Handle different value types
        if isinstance(target_value, bool) and isinstance(current_value, str):
            return current_value.lower() in ['1', 'yes', 'true', 'on'] if target_value else current_value.lower() in ['0', 'no', 'false', 'off']
        
        if isinstance(target_value, str) and isinstance(current_value, str):
            return current_value.strip() == target_value.strip()
        
        if isinstance(target_value, int) and isinstance(current_value, str):
            try:
                return int(current_value) == target_value
            except ValueError:
                return False
        
        return current_value == target_value
    
    def _is_sysctl_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by sysctl manager."""
        return param.category in ["kernel", "network"] or param.id.startswith(("net.", "kernel.", "vm.", "fs."))
    
    def _is_pam_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by PAM manager."""
        return param.category == "authentication" or param.id.startswith("pam_")
    
    def _is_ssh_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by SSH manager."""
        return param.category == "ssh" or param.id.startswith("ssh_")
    
    def _is_auditd_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by auditd manager."""
        return param.category == "auditing" or param.id.startswith("audit_")
    
    def _is_firewall_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by firewall manager."""
        return param.category == "firewall" or param.id.startswith("ufw_")
    
    def _create_parameter_backup(self, param: Parameter) -> Optional[any]:
        """Create backup for a specific parameter."""
        if self._is_sysctl_parameter(param):
            return self.sysctl_manager.backup_sysctl_value(param.id)
        elif self._is_pam_parameter(param):
            return self.pam_manager.backup_pam_configuration(param.id)
        elif self._is_ssh_parameter(param):
            return self.ssh_manager.backup_ssh_configuration(param.id)
        elif self._is_auditd_parameter(param):
            return self.auditd_manager.backup_auditd_configuration(param.id)
        elif self._is_firewall_parameter(param):
            return self.firewall_manager.backup_firewall_configuration(param.id)
        
        return None
    
    def _create_parameter_from_sysctl(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from sysctl parameter ID."""
        category = "kernel"
        if param_id.startswith("net."):
            category = "network"
        elif param_id.startswith("vm."):
            category = "memory"
        elif param_id.startswith("fs."):
            category = "filesystem"
        
        return Parameter(
            id=param_id,
            name=param_id.replace(".", " ").replace("_", " ").title(),
            category=category,
            description=f"Kernel parameter: {param_id}",
            platform_specific=True
        )
    
    def _create_parameter_from_pam(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from PAM parameter ID."""
        return Parameter(
            id=param_id,
            name=param_id.replace("_", " ").title(),
            category="authentication",
            description=f"PAM configuration: {param_id}",
            platform_specific=True
        )
    
    def _create_parameter_from_ssh(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from SSH parameter ID."""
        return Parameter(
            id=param_id,
            name=param_id.replace("_", " ").title(),
            category="ssh",
            description=f"SSH configuration: {param_id}",
            platform_specific=True,
            requires_reboot=False
        )
    
    def _create_parameter_from_auditd(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from auditd parameter ID."""
        return Parameter(
            id=param_id,
            name=param_id.replace("_", " ").title(),
            category="auditing",
            description=f"Audit configuration: {param_id}",
            platform_specific=True
        )
    
    def _create_parameter_from_firewall(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from firewall parameter ID."""
        return Parameter(
            id=param_id,
            name=param_id.replace("_", " ").title(),
            category="firewall",
            description=f"Firewall configuration: {param_id}",
            platform_specific=True
        )
    
    def _is_linux(self) -> bool:
        """Check if running on Linux."""
        return sys.platform.startswith("linux")