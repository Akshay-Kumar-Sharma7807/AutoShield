"""Windows Audit Policy Manager for advanced audit configuration."""

import sys
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ...core.models import (
    HardeningError, HardeningResult, Parameter, ParameterBackup, SystemError
)

# Windows-specific imports
if sys.platform == "win32":
    try:
        import subprocess
    except ImportError:
        subprocess = None
else:
    subprocess = None


class WindowsAuditManager:
    """Manages Windows Advanced Audit Policy for security hardening."""
    
    def __init__(self):
        """Initialize Windows Audit Manager."""
        if not self._is_windows():
            raise SystemError("Windows Audit Manager can only be used on Windows systems")
        
        if subprocess is None:
            raise SystemError("Subprocess module not available")
        
        # Advanced Audit Policy settings according to Annexure-A (15 total settings)
        self.audit_policies = {
            # Account Logon
            "audit_credential_validation": {
                "category": "Account Logon",
                "subcategory": "Credential Validation",
                "target_value": "Success and Failure",
                "description": "Audit credential validation events",
                "auditpol_command": "auditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable"
            },
            
            # Account Management
            "audit_application_group_management": {
                "category": "Account Management",
                "subcategory": "Application Group Management",
                "target_value": "Success and Failure",
                "description": "Audit application group management",
                "auditpol_command": "auditpol /set /subcategory:\"Application Group Management\" /success:enable /failure:enable"
            },
            "audit_security_group_management": {
                "category": "Account Management",
                "subcategory": "Security Group Management",
                "target_value": "Success",
                "description": "Audit security group management",
                "auditpol_command": "auditpol /set /subcategory:\"Security Group Management\" /success:enable /failure:disable"
            },
            "audit_user_account_management": {
                "category": "Account Management",
                "subcategory": "User Account Management",
                "target_value": "Success and Failure",
                "description": "Audit user account management",
                "auditpol_command": "auditpol /set /subcategory:\"User Account Management\" /success:enable /failure:enable"
            },
            
            # Detailed Tracking
            "audit_pnp_activity": {
                "category": "Detailed Tracking",
                "subcategory": "PNP Activity",
                "target_value": "Success",
                "description": "Audit Plug and Play activity",
                "auditpol_command": "auditpol /set /subcategory:\"PNP Activity\" /success:enable /failure:disable"
            },
            "audit_process_creation": {
                "category": "Detailed Tracking",
                "subcategory": "Process Creation",
                "target_value": "Success",
                "description": "Audit process creation",
                "auditpol_command": "auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:disable"
            },
            
            # Logon/Logoff
            "audit_account_lockout": {
                "category": "Logon/Logoff",
                "subcategory": "Account Lockout",
                "target_value": "Failure",
                "description": "Audit account lockout events",
                "auditpol_command": "auditpol /set /subcategory:\"Account Lockout\" /success:disable /failure:enable"
            },
            "audit_logon": {
                "category": "Logon/Logoff",
                "subcategory": "Logon",
                "target_value": "Success and Failure",
                "description": "Audit logon events",
                "auditpol_command": "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable"
            },
            "audit_other_logon_logoff_events": {
                "category": "Logon/Logoff",
                "subcategory": "Other Logon/Logoff Events",
                "target_value": "Success and Failure",
                "description": "Audit other logon/logoff events",
                "auditpol_command": "auditpol /set /subcategory:\"Other Logon/Logoff Events\" /success:enable /failure:enable"
            },
            
            # Object Access
            "audit_file_share": {
                "category": "Object Access",
                "subcategory": "File Share",
                "target_value": "Success and Failure",
                "description": "Audit file share access",
                "auditpol_command": "auditpol /set /subcategory:\"File Share\" /success:enable /failure:enable"
            },
            "audit_removable_storage": {
                "category": "Object Access",
                "subcategory": "Removable Storage",
                "target_value": "Success and Failure",
                "description": "Audit removable storage access",
                "auditpol_command": "auditpol /set /subcategory:\"Removable Storage\" /success:enable /failure:enable"
            },
            
            # Policy Change
            "audit_audit_policy_change": {
                "category": "Policy Change",
                "subcategory": "Audit Policy Change",
                "target_value": "Success",
                "description": "Audit changes to audit policy",
                "auditpol_command": "auditpol /set /subcategory:\"Audit Policy Change\" /success:enable /failure:disable"
            },
            "audit_other_policy_change_events": {
                "category": "Policy Change",
                "subcategory": "Other Policy Change Events",
                "target_value": "Failure",
                "description": "Audit other policy change events",
                "auditpol_command": "auditpol /set /subcategory:\"Other Policy Change Events\" /success:disable /failure:enable"
            },
            
            # Privilege Use
            "audit_sensitive_privilege_use": {
                "category": "Privilege Use",
                "subcategory": "Sensitive Privilege Use",
                "target_value": "Success and Failure",
                "description": "Audit sensitive privilege use",
                "auditpol_command": "auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable /failure:enable"
            },
            
            # System
            "audit_system_integrity": {
                "category": "System",
                "subcategory": "System Integrity",
                "target_value": "Success and Failure",
                "description": "Audit system integrity events",
                "auditpol_command": "auditpol /set /subcategory:\"System Integrity\" /success:enable /failure:enable"
            }
        }
    
    def get_audit_policy(self, policy_id: str) -> Tuple[bool, str]:
        """Get current audit policy setting."""
        if policy_id not in self.audit_policies:
            return False, ""
        
        policy_info = self.audit_policies[policy_id]
        subcategory = policy_info["subcategory"]
        
        try:
            # Use auditpol to get current setting
            cmd = f'auditpol /get /subcategory:"{subcategory}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the output to extract current setting
                current_setting = self._parse_auditpol_output(result.stdout, subcategory)
                return True, current_setting
            
        except subprocess.TimeoutExpired:
            pass
        
        return False, ""
    
    def set_audit_policy(self, policy_id: str, setting: str) -> bool:
        """Set audit policy setting."""
        if policy_id not in self.audit_policies:
            return False
        
        policy_info = self.audit_policies[policy_id]
        
        try:
            # Use the predefined auditpol command or construct one
            if setting == policy_info["target_value"]:
                cmd = policy_info["auditpol_command"]
            else:
                # Construct custom command based on setting
                cmd = self._construct_auditpol_command(policy_info, setting)
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
    
    def backup_audit_policy(self, policy_id: str) -> Optional[ParameterBackup]:
        """Create backup of audit policy setting."""
        success, current_setting = self.get_audit_policy(policy_id)
        
        if not success:
            current_setting = "No Auditing"
        
        policy_info = self.audit_policies.get(policy_id, {})
        
        backup = ParameterBackup(
            parameter_id=policy_id,
            original_value=current_setting,
            restore_method="audit_policy",
            restore_data={
                "policy_info": policy_info,
                "subcategory": policy_info.get("subcategory"),
                "category": policy_info.get("category")
            }
        )
        
        return backup
    
    def restore_audit_policy(self, backup: ParameterBackup) -> bool:
        """Restore audit policy from backup."""
        if backup.restore_method != "audit_policy":
            return False
        
        try:
            original_setting = backup.original_value
            if original_setting:
                return self.set_audit_policy(backup.parameter_id, original_setting)
            else:
                # Disable auditing if no original setting
                return self._disable_audit_policy(backup)
                
        except Exception:
            return False
    
    def apply_audit_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply audit policy hardening configurations."""
        results = []
        
        # Filter audit-related parameters
        audit_params = [p for p in parameters if p.category == "auditing"]
        
        for param in audit_params:
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Get current setting
                success, current_setting = self.get_audit_policy(param.id)
                result.previous_value = current_setting if success else None
                
                # Apply new setting
                target_setting = self._convert_target_value(param.target_value)
                if self.set_audit_policy(param.id, target_setting):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to set audit policy {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_all_audit_policies_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all audit policies."""
        status = {}
        
        for policy_id, policy_info in self.audit_policies.items():
            success, current_setting = self.get_audit_policy(policy_id)
            
            status[policy_id] = {
                "info": policy_info,
                "current_setting": current_setting if success else "Unknown",
                "target_setting": policy_info["target_value"],
                "compliant": self._is_policy_compliant(current_setting, policy_info["target_value"]) if success else False
            }
        
        return status
    
    def enable_comprehensive_auditing(self) -> List[HardeningResult]:
        """Enable comprehensive auditing for all security-relevant categories."""
        results = []
        
        for policy_id, policy_info in self.audit_policies.items():
            result = HardeningResult(
                parameter_id=policy_id,
                previous_value=None,
                applied_value=policy_info["target_value"],
                success=False
            )
            
            try:
                # Get current setting
                success, current_setting = self.get_audit_policy(policy_id)
                result.previous_value = current_setting if success else None
                
                # Apply target setting
                if self.set_audit_policy(policy_id, policy_info["target_value"]):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to enable auditing for {policy_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def export_audit_configuration(self, output_file: str) -> bool:
        """Export current audit configuration to file."""
        try:
            cmd = f'auditpol /backup /file:"{output_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
    
    def import_audit_configuration(self, config_file: str) -> bool:
        """Import audit configuration from file."""
        try:
            cmd = f'auditpol /restore /file:"{config_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
    
    def configure_audit_log_settings(self) -> List[HardeningResult]:
        """Configure audit log settings including size, retention, and security."""
        results = []
        
        # Configure Security Event Log settings
        log_settings = {
            "maximum_log_size": {
                "registry_path": r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "value_name": "MaxSize",
                "target_value": 196608000,  # 192 MB in bytes
                "description": "Set Security Event Log maximum size to 192 MB"
            },
            "log_retention_method": {
                "registry_path": r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "value_name": "Retention",
                "target_value": 0,  # 0 = Overwrite events as needed
                "description": "Configure log retention method"
            },
            "restrict_guest_access": {
                "registry_path": r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "value_name": "RestrictGuestAccess",
                "target_value": 1,  # 1 = Restrict guest access
                "description": "Restrict guest access to Security Event Log"
            }
        }
        
        for setting_id, setting_info in log_settings.items():
            result = HardeningResult(
                parameter_id=f"audit_log_{setting_id}",
                previous_value=None,
                applied_value=setting_info["target_value"],
                success=False
            )
            
            try:
                # Get current registry value
                current_value = self._get_registry_value(
                    setting_info["registry_path"], 
                    setting_info["value_name"]
                )
                result.previous_value = current_value
                
                # Set new registry value
                if self._set_registry_value(
                    setting_info["registry_path"],
                    setting_info["value_name"],
                    setting_info["target_value"]
                ):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to configure {setting_info['description']}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def validate_audit_policy_configuration(self) -> Dict[str, Any]:
        """Validate current audit policy configuration against security requirements."""
        validation_results = {
            "overall_compliance": True,
            "compliant_policies": [],
            "non_compliant_policies": [],
            "missing_policies": [],
            "validation_errors": [],
            "compliance_percentage": 0.0
        }
        
        try:
            total_policies = len(self.audit_policies)
            compliant_count = 0
            
            for policy_id, policy_info in self.audit_policies.items():
                try:
                    success, current_setting = self.get_audit_policy(policy_id)
                    
                    if not success:
                        validation_results["missing_policies"].append({
                            "policy_id": policy_id,
                            "description": policy_info["description"],
                            "expected_setting": policy_info["target_value"]
                        })
                        continue
                    
                    is_compliant = self._is_policy_compliant(current_setting, policy_info["target_value"])
                    
                    policy_result = {
                        "policy_id": policy_id,
                        "description": policy_info["description"],
                        "current_setting": current_setting,
                        "expected_setting": policy_info["target_value"],
                        "compliant": is_compliant
                    }
                    
                    if is_compliant:
                        validation_results["compliant_policies"].append(policy_result)
                        compliant_count += 1
                    else:
                        validation_results["non_compliant_policies"].append(policy_result)
                        
                except Exception as e:
                    validation_results["validation_errors"].append({
                        "policy_id": policy_id,
                        "error": str(e)
                    })
            
            # Calculate compliance percentage
            if total_policies > 0:
                validation_results["compliance_percentage"] = (compliant_count / total_policies) * 100
            
            # Overall compliance is true only if all policies are compliant
            validation_results["overall_compliance"] = (
                compliant_count == total_policies and 
                len(validation_results["validation_errors"]) == 0
            )
            
        except Exception as e:
            validation_results["validation_errors"].append({
                "general_error": str(e)
            })
            validation_results["overall_compliance"] = False
        
        return validation_results
    
    def get_audit_policy_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations for improving audit policy configuration."""
        recommendations = []
        
        try:
            validation_results = self.validate_audit_policy_configuration()
            
            # Recommendations for non-compliant policies
            for policy in validation_results["non_compliant_policies"]:
                recommendations.append({
                    "type": "policy_configuration",
                    "priority": "high",
                    "policy_id": policy["policy_id"],
                    "description": f"Configure {policy['description']}",
                    "current_setting": policy["current_setting"],
                    "recommended_setting": policy["expected_setting"],
                    "remediation_command": self.audit_policies[policy["policy_id"]]["auditpol_command"]
                })
            
            # Recommendations for missing policies
            for policy in validation_results["missing_policies"]:
                recommendations.append({
                    "type": "policy_missing",
                    "priority": "critical",
                    "policy_id": policy["policy_id"],
                    "description": f"Enable {policy['description']}",
                    "recommended_setting": policy["expected_setting"],
                    "remediation_command": self.audit_policies[policy["policy_id"]]["auditpol_command"]
                })
            
            # General recommendations
            if validation_results["compliance_percentage"] < 100:
                recommendations.append({
                    "type": "general",
                    "priority": "medium",
                    "description": "Consider enabling comprehensive audit logging",
                    "details": f"Current compliance: {validation_results['compliance_percentage']:.1f}%"
                })
            
            # Log configuration recommendations
            recommendations.extend(self._get_log_configuration_recommendations())
            
        except Exception as e:
            recommendations.append({
                "type": "error",
                "priority": "high",
                "description": f"Error generating recommendations: {str(e)}"
            })
        
        return recommendations
    
    def _get_log_configuration_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations for audit log configuration."""
        recommendations = []
        
        try:
            # Check Security Event Log size
            current_size = self._get_registry_value(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "MaxSize"
            )
            
            if current_size and current_size < 196608000:  # Less than 192 MB
                recommendations.append({
                    "type": "log_configuration",
                    "priority": "medium",
                    "description": "Increase Security Event Log maximum size",
                    "current_value": f"{current_size // 1024 // 1024} MB",
                    "recommended_value": "192 MB",
                    "rationale": "Larger log size prevents important security events from being overwritten"
                })
            
            # Check guest access restriction
            guest_access = self._get_registry_value(
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "RestrictGuestAccess"
            )
            
            if guest_access != 1:
                recommendations.append({
                    "type": "log_security",
                    "priority": "high",
                    "description": "Restrict guest access to Security Event Log",
                    "current_value": "Unrestricted" if guest_access == 0 else "Unknown",
                    "recommended_value": "Restricted",
                    "rationale": "Prevents unauthorized access to sensitive audit information"
                })
                
        except Exception as e:
            recommendations.append({
                "type": "error",
                "priority": "medium",
                "description": f"Error checking log configuration: {str(e)}"
            })
        
        return recommendations
    
    def _get_registry_value(self, registry_path: str, value_name: str) -> Any:
        """Get registry value using reg query command."""
        try:
            # Convert HKEY_LOCAL_MACHINE to HKLM for reg command
            reg_path = registry_path.replace("HKEY_LOCAL_MACHINE", "HKLM")
            
            cmd = f'reg query "{reg_path}" /v "{value_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the output to extract the value
                lines = result.stdout.split('\n')
                for line in lines:
                    if value_name in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            # Return the value (last part)
                            value_str = parts[-1]
                            # Try to convert to integer if it looks like a number
                            if value_str.startswith('0x'):
                                return int(value_str, 16)
                            elif value_str.isdigit():
                                return int(value_str)
                            else:
                                return value_str
            
            return None
            
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None
    
    def _set_registry_value(self, registry_path: str, value_name: str, value: Any) -> bool:
        """Set registry value using reg add command."""
        try:
            # Convert HKEY_LOCAL_MACHINE to HKLM for reg command
            reg_path = registry_path.replace("HKEY_LOCAL_MACHINE", "HKLM")
            
            # Determine value type
            if isinstance(value, int):
                value_type = "REG_DWORD"
                value_str = str(value)
            else:
                value_type = "REG_SZ"
                value_str = str(value)
            
            cmd = f'reg add "{reg_path}" /v "{value_name}" /t {value_type} /d "{value_str}" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def _parse_auditpol_output(self, output: str, subcategory: str) -> str:
        """Parse auditpol command output to extract current setting."""
        lines = output.split('\n')
        
        for line in lines:
            if subcategory in line:
                # Extract the setting from the line
                parts = line.split()
                if len(parts) >= 3:
                    # Look for Success/Failure indicators
                    success = "Success" in line
                    failure = "Failure" in line
                    
                    if success and failure:
                        return "Success and Failure"
                    elif success:
                        return "Success"
                    elif failure:
                        return "Failure"
                    else:
                        return "No Auditing"
        
        return "No Auditing"
    
    def _construct_auditpol_command(self, policy_info: Dict[str, Any], setting: str) -> str:
        """Construct auditpol command based on policy info and setting."""
        subcategory = policy_info["subcategory"]
        
        if setting == "Success and Failure":
            return f'auditpol /set /subcategory:"{subcategory}" /success:enable /failure:enable'
        elif setting == "Success":
            return f'auditpol /set /subcategory:"{subcategory}" /success:enable /failure:disable'
        elif setting == "Failure":
            return f'auditpol /set /subcategory:"{subcategory}" /success:disable /failure:enable'
        else:
            return f'auditpol /set /subcategory:"{subcategory}" /success:disable /failure:disable'
    
    def _convert_target_value(self, target_value: Any) -> str:
        """Convert parameter target value to audit policy setting."""
        if isinstance(target_value, bool):
            return "Success and Failure" if target_value else "No Auditing"
        elif isinstance(target_value, str):
            return target_value
        else:
            return "Success and Failure"
    
    def _disable_audit_policy(self, backup: ParameterBackup) -> bool:
        """Disable audit policy (used during restore)."""
        try:
            restore_data = backup.restore_data
            subcategory = restore_data.get("subcategory")
            
            if subcategory:
                cmd = f'auditpol /set /subcategory:"{subcategory}" /success:disable /failure:disable'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                return result.returncode == 0
                
        except subprocess.TimeoutExpired:
            pass
        
        return False
    
    def _is_policy_compliant(self, current_setting: str, target_setting: str) -> bool:
        """Check if current audit policy is compliant with target."""
        if not current_setting or not target_setting:
            return False
        
        # Normalize settings for comparison
        current_normalized = self._normalize_audit_setting(current_setting)
        target_normalized = self._normalize_audit_setting(target_setting)
        
        return current_normalized == target_normalized
    
    def _normalize_audit_setting(self, setting: str) -> str:
        """Normalize audit setting for comparison."""
        if not setting:
            return "no auditing"
        
        setting_lower = setting.lower()
        
        if "success" in setting_lower and "failure" in setting_lower:
            return "success and failure"
        elif "success" in setting_lower:
            return "success"
        elif "failure" in setting_lower:
            return "failure"
        else:
            return "no auditing"
    
    def validate_audit_access(self) -> bool:
        """Validate that we have necessary permissions to manage audit policies."""
        try:
            # Try to get current audit policy for a common subcategory
            cmd = 'auditpol /get /subcategory:"Logon"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"
    
    def get_supported_policies(self) -> List[str]:
        """Get list of supported audit policy IDs."""
        return list(self.audit_policies.keys())
    
    def is_policy_supported(self, policy_id: str) -> bool:
        """Check if audit policy is supported by this manager."""
        return policy_id in self.audit_policies
    
    def get_audit_categories(self) -> Dict[str, List[str]]:
        """Get audit policies organized by category."""
        categories = {}
        
        for policy_id, policy_info in self.audit_policies.items():
            category = policy_info["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(policy_id)
        
        return categories
    
    def get_category_compliance_status(self) -> Dict[str, Dict[str, Any]]:
        """Get compliance status for each audit category."""
        categories = self.get_audit_categories()
        category_status = {}
        
        for category, policy_ids in categories.items():
            total_policies = len(policy_ids)
            compliant_policies = 0
            category_policies = []
            
            for policy_id in policy_ids:
                success, current_setting = self.get_audit_policy(policy_id)
                policy_info = self.audit_policies[policy_id]
                
                is_compliant = False
                if success:
                    is_compliant = self._is_policy_compliant(current_setting, policy_info["target_value"])
                    if is_compliant:
                        compliant_policies += 1
                
                category_policies.append({
                    "policy_id": policy_id,
                    "description": policy_info["description"],
                    "current_setting": current_setting if success else "Unknown",
                    "target_setting": policy_info["target_value"],
                    "compliant": is_compliant
                })
            
            compliance_percentage = (compliant_policies / total_policies * 100) if total_policies > 0 else 0
            
            category_status[category] = {
                "total_policies": total_policies,
                "compliant_policies": compliant_policies,
                "compliance_percentage": compliance_percentage,
                "overall_compliant": compliant_policies == total_policies,
                "policies": category_policies
            }
        
        return category_status
    
    def apply_category_hardening(self, category: str) -> List[HardeningResult]:
        """Apply hardening for all policies in a specific category."""
        results = []
        categories = self.get_audit_categories()
        
        if category not in categories:
            result = HardeningResult(
                parameter_id=f"category_{category}",
                previous_value=None,
                applied_value=None,
                success=False,
                error_message=f"Unknown audit category: {category}"
            )
            results.append(result)
            return results
        
        policy_ids = categories[category]
        
        for policy_id in policy_ids:
            policy_info = self.audit_policies[policy_id]
            result = HardeningResult(
                parameter_id=policy_id,
                previous_value=None,
                applied_value=policy_info["target_value"],
                success=False
            )
            
            try:
                # Get current setting
                success, current_setting = self.get_audit_policy(policy_id)
                result.previous_value = current_setting if success else None
                
                # Apply target setting
                if self.set_audit_policy(policy_id, policy_info["target_value"]):
                    result.success = True
                    result.backup_created = True
                else:
                    result.error_message = f"Failed to configure audit policy {policy_id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_comprehensive_audit_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all audit configurations."""
        try:
            # Get policy validation results
            validation_results = self.validate_audit_policy_configuration()
            
            # Get category compliance
            category_status = self.get_category_compliance_status()
            
            # Get recommendations
            recommendations = self.get_audit_policy_recommendations()
            
            # Calculate overall security score
            security_score = self._calculate_security_score(validation_results, category_status)
            
            return {
                "timestamp": subprocess.run("date /t", shell=True, capture_output=True, text=True).stdout.strip(),
                "overall_compliance": validation_results["overall_compliance"],
                "compliance_percentage": validation_results["compliance_percentage"],
                "security_score": security_score,
                "total_policies": len(self.audit_policies),
                "compliant_policies": len(validation_results["compliant_policies"]),
                "non_compliant_policies": len(validation_results["non_compliant_policies"]),
                "missing_policies": len(validation_results["missing_policies"]),
                "category_breakdown": category_status,
                "policy_details": validation_results,
                "recommendations": recommendations,
                "audit_access_validated": self.validate_audit_access()
            }
            
        except Exception as e:
            return {
                "error": f"Failed to get comprehensive audit status: {str(e)}",
                "timestamp": subprocess.run("date /t", shell=True, capture_output=True, text=True).stdout.strip(),
                "audit_access_validated": False
            }
    
    def _calculate_security_score(self, validation_results: Dict[str, Any], category_status: Dict[str, Dict[str, Any]]) -> float:
        """Calculate overall security score based on audit configuration."""
        try:
            base_score = validation_results["compliance_percentage"]
            
            # Penalty for missing critical categories
            critical_categories = ["Account Logon", "Account Management", "System"]
            penalty = 0
            
            for category in critical_categories:
                if category in category_status:
                    if category_status[category]["compliance_percentage"] < 100:
                        penalty += 10  # 10 point penalty for non-compliant critical category
            
            # Bonus for full compliance
            bonus = 0
            if validation_results["overall_compliance"]:
                bonus = 5  # 5 point bonus for full compliance
            
            final_score = max(0, min(100, base_score - penalty + bonus))
            return round(final_score, 1)
            
        except Exception:
            return 0.0