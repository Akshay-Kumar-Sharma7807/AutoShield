"""Main Windows hardening module that integrates all Windows-specific managers."""

import sys
from typing import List, Optional

from ...core.interfaces import HardeningModule
from ...core.models import (
    AssessmentResult, BackupData, HardeningResult, OSInfo, Parameter,
    Platform, RestoreResult, SystemError, ValidationResult
)
from .audit_manager import WindowsAuditManager
from .firewall_manager import WindowsFirewallManager
from .registry_manager import WindowsRegistryManager
from .service_manager import WindowsServiceManager


class WindowsHardeningModule(HardeningModule):
    """Main Windows hardening module that coordinates all Windows-specific managers."""
    
    def __init__(self):
        """Initialize Windows hardening module."""
        if not self._is_windows():
            raise SystemError("Windows hardening module can only be used on Windows systems")
        
        # Initialize all managers
        self.registry_manager = WindowsRegistryManager()
        self.service_manager = WindowsServiceManager()
        self.firewall_manager = WindowsFirewallManager()
        self.audit_manager = WindowsAuditManager()
        
        # Validate access permissions
        self._validate_permissions()
    
    def get_supported_parameters(self) -> List[Parameter]:
        """Get list of parameters supported by this module."""
        parameters = []
        
        # Add registry-based parameters
        registry_params = self.registry_manager.get_supported_parameters()
        for param_id in registry_params:
            # Create parameter objects based on registry settings
            param = self._create_parameter_from_registry(param_id)
            if param:
                parameters.append(param)
        
        # Add service-based parameters
        service_params = self.service_manager.get_supported_services()
        for service_name in service_params:
            param = self._create_parameter_from_service(service_name)
            if param:
                parameters.append(param)
        
        # Add firewall-based parameters
        firewall_params = self.firewall_manager.get_supported_settings()
        for setting_id in firewall_params:
            param = self._create_parameter_from_firewall(setting_id)
            if param:
                parameters.append(param)
        
        # Add audit policy parameters
        audit_params = self.audit_manager.get_supported_policies()
        for policy_id in audit_params:
            param = self._create_parameter_from_audit(policy_id)
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
        registry_params = [p for p in parameters if self._is_registry_parameter(p)]
        service_params = [p for p in parameters if self._is_service_parameter(p)]
        firewall_params = [p for p in parameters if self._is_firewall_parameter(p)]
        audit_params = [p for p in parameters if self._is_audit_parameter(p)]
        
        # Apply registry-based hardening
        if registry_params:
            registry_results = self._apply_registry_hardening(registry_params)
            results.extend(registry_results)
        
        # Apply service-based hardening
        if service_params:
            service_results = self.service_manager.apply_service_hardening(service_params)
            results.extend(service_results)
        
        # Apply firewall-based hardening
        if firewall_params:
            firewall_results = self.firewall_manager.apply_firewall_hardening(firewall_params)
            results.extend(firewall_results)
        
        # Apply audit policy hardening
        if audit_params:
            audit_results = self.audit_manager.apply_audit_hardening(audit_params)
            results.extend(audit_results)
        
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
                if self._is_registry_parameter(param):
                    if not self.registry_manager.is_parameter_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Registry parameter {param.id} is not supported")
                
                elif self._is_service_parameter(param):
                    if not self.service_manager.is_service_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Service parameter {param.id} is not supported")
                
                elif self._is_firewall_parameter(param):
                    if not self.firewall_manager.is_setting_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Firewall parameter {param.id} is not supported")
                
                elif self._is_audit_parameter(param):
                    if not self.audit_manager.is_policy_supported(param.id):
                        result.valid = False
                        result.errors.append(f"Audit parameter {param.id} is not supported")
                
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
            description="Windows security hardening backup"
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
                if param_backup.restore_method == "registry":
                    result.success = self.registry_manager.restore_registry_value(param_backup)
                elif param_backup.restore_method == "service":
                    result.success = self.service_manager.restore_service_configuration(param_backup)
                elif param_backup.restore_method == "firewall":
                    result.success = self.firewall_manager.restore_firewall_setting(param_backup)
                elif param_backup.restore_method == "audit_policy":
                    result.success = self.audit_manager.restore_audit_policy(param_backup)
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
        
        # Check registry access
        if not self.registry_manager.validate_registry_access():
            errors.append("Insufficient registry access permissions")
        
        # Check service access
        if not self.service_manager.validate_service_access():
            errors.append("Insufficient service management permissions")
        
        # Check audit policy access
        if not self.audit_manager.validate_audit_access():
            errors.append("Insufficient audit policy management permissions")
        
        if errors:
            raise SystemError(f"Permission validation failed: {'; '.join(errors)}")
    
    def _get_current_value(self, param: Parameter) -> any:
        """Get current value for a parameter."""
        if self._is_registry_parameter(param):
            success, value = self.registry_manager.read_registry_value(param.id)
            return value if success else None
        
        elif self._is_service_parameter(param):
            status = self.service_manager.get_service_status(param.id)
            return status
        
        elif self._is_firewall_parameter(param):
            success, value = self.firewall_manager.get_firewall_setting(param.id)
            return value if success else None
        
        elif self._is_audit_parameter(param):
            success, value = self.audit_manager.get_audit_policy(param.id)
            return value if success else None
        
        return None
    
    def _is_compliant(self, current_value: any, target_value: any) -> bool:
        """Check if current value is compliant with target value."""
        if current_value is None:
            return False
        
        # Handle different value types
        if isinstance(target_value, bool) and isinstance(current_value, int):
            return bool(current_value) == target_value
        
        if isinstance(target_value, str) and isinstance(current_value, str):
            return current_value.lower() == target_value.lower()
        
        return current_value == target_value
    
    def _is_registry_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by registry manager."""
        return self.registry_manager.is_parameter_supported(param.id)
    
    def _is_service_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by service manager."""
        return param.category == "services" or self.service_manager.is_service_supported(param.id)
    
    def _is_firewall_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by firewall manager."""
        return "firewall" in param.id or self.firewall_manager.is_setting_supported(param.id)
    
    def _is_audit_parameter(self, param: Parameter) -> bool:
        """Check if parameter is handled by audit manager."""
        return param.category == "auditing" or self.audit_manager.is_policy_supported(param.id)
    
    def _apply_registry_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply registry-based hardening."""
        results = []
        
        # Group by category for efficient processing
        auth_params = [p for p in parameters if p.category == "authentication"]
        access_params = [p for p in parameters if p.category == "access_control"]
        network_params = [p for p in parameters if p.category == "network" and "firewall" not in p.id]
        
        if auth_params:
            results.extend(self.registry_manager.apply_account_policies(auth_params))
        
        if access_params:
            results.extend(self.registry_manager.apply_security_options(access_params))
        
        if network_params:
            results.extend(self.registry_manager.apply_security_options(network_params))
        
        # Handle UAC settings
        uac_params = [p for p in parameters if p.id.startswith("uac_")]
        if uac_params:
            results.extend(self.registry_manager.apply_uac_settings(uac_params))
        
        return results
    
    def _create_parameter_backup(self, param: Parameter) -> Optional[any]:
        """Create backup for a specific parameter."""
        if self._is_registry_parameter(param):
            return self.registry_manager.backup_registry_value(param.id)
        elif self._is_service_parameter(param):
            return self.service_manager.backup_service_configuration(param.id)
        elif self._is_firewall_parameter(param):
            return self.firewall_manager.backup_firewall_setting(param.id)
        elif self._is_audit_parameter(param):
            return self.audit_manager.backup_audit_policy(param.id)
        
        return None
    
    def _create_parameter_from_registry(self, param_id: str) -> Optional[Parameter]:
        """Create Parameter object from registry parameter ID."""
        # This would typically load from configuration files
        # For now, return a basic parameter
        return Parameter(
            id=param_id,
            name=param_id.replace("_", " ").title(),
            category="authentication",
            description=f"Registry-based parameter: {param_id}",
            platform_specific=True
        )
    
    def _create_parameter_from_service(self, service_name: str) -> Optional[Parameter]:
        """Create Parameter object from service name."""
        return Parameter(
            id=service_name,
            name=f"Service: {service_name}",
            category="services",
            description=f"Windows service: {service_name}",
            target_value=False,  # Most security services should be disabled
            platform_specific=True,
            requires_reboot=True
        )
    
    def _create_parameter_from_firewall(self, setting_id: str) -> Optional[Parameter]:
        """Create Parameter object from firewall setting ID."""
        return Parameter(
            id=setting_id,
            name=setting_id.replace("_", " ").title(),
            category="network",
            description=f"Firewall setting: {setting_id}",
            platform_specific=True
        )
    
    def _create_parameter_from_audit(self, policy_id: str) -> Optional[Parameter]:
        """Create Parameter object from audit policy ID."""
        return Parameter(
            id=policy_id,
            name=policy_id.replace("_", " ").title(),
            category="auditing",
            description=f"Audit policy: {policy_id}",
            target_value=True,  # Most audit policies should be enabled
            platform_specific=True
        )
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"